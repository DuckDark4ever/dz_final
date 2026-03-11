"""
Коллектор для проверки индикаторов (IP, домены, хэши) через VirusTotal API.
Реализует кэширование, retry логику и защиту от rate limiting.
"""
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import quote, urljoin
from collections import OrderedDict

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    wait_fixed,
    retry_if_exception_type,
    before_sleep_log
)

from collectors.base import BaseCollector
from models.event import ThreatIntelEvent, RawEvent
from config import Config
from utils.logger import logger


class VirusTotalAPIError(Exception):
    """Базовое исключение для ошибок VirusTotal API."""
    pass


class VirusTotalRateLimitError(VirusTotalAPIError):
    """Специфическая ошибка для превышения лимита запросов."""
    pass


class VirusTotalAuthError(VirusTotalAPIError):
    """Ошибка аутентификации (неверный или отсутствующий API ключ)."""
    pass


@dataclass
class VTCache:
    """
    Кэш в памяти для результатов VirusTotal с ограничением размера (LRU).
    Используем OrderedDict для эффективной реализации LRU.
    """
    maxsize: int = 1000  # Максимальное количество записей в кэше
    cache: OrderedDict = field(default_factory=OrderedDict)
    hits: int = 0
    misses: int = 0
    
    def _make_key(self, indicator: str, indicator_type: str) -> str:
        """
        Создает составной ключ для кэша.
        
        Args:
            indicator: Строка индикатора
            indicator_type: Тип индикатора
        
        Returns:
            Составной ключ вида "type:indicator"
        """
        return f"{indicator_type}:{indicator}"
    
    def get(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelEvent]:
        """
        Получить значение из кэша с подсчетом статистики.
        Реализует LRU - при обращении элемент перемещается в конец.
        
        Args:
            indicator: Строка индикатора
            indicator_type: Тип индикатора
        
        Returns:
            Значение из кэша или None
        """
        key = self._make_key(indicator, indicator_type)
        
        if key in self.cache:
            # LRU: перемещаем в конец (самый свежий)
            self.cache.move_to_end(key)
            self.hits += 1
            return self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, indicator: str, indicator_type: str, value: ThreatIntelEvent) -> None:
        """
        Сохранить значение в кэш с учетом максимального размера.
        
        Args:
            indicator: Строка индикатора
            indicator_type: Тип индикатора
            value: Значение для сохранения
        """
        key = self._make_key(indicator, indicator_type)
        
        # Добавляем или обновляем элемент
        self.cache[key] = value
        self.cache.move_to_end(key)
        
        # Проверяем превышение размера
        if len(self.cache) > self.maxsize:
            # Удаляем самый старый элемент (первый в OrderedDict)
            removed_key, removed_value = self.cache.popitem(last=False)
            logger.debug(f"Кэш переполнен, удален элемент: {removed_key}")
    
    def stats(self) -> Dict[str, Any]:
        """
        Вернуть статистику использования кэша.
        
        Returns:
            Словарь со статистикой
        """
        total = self.hits + self.misses
        return {
            'size': len(self.cache),
            'maxsize': self.maxsize,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': round(self.hits / total * 100, 2) if total > 0 else 0
        }


class VirusTotalCollector(BaseCollector):
    """
    Коллектор для VirusTotal API v3.
    
    Особенности:
    - Кэширование результатов в памяти (LRU, ограниченный размер)
    - Retry с экспоненциальной задержкой для rate limiting
    - Защита от rate limiting Public API (4 запроса/минуту)
    - URL-кодирование индикаторов
    - Проверка наличия API ключа перед запросом
    - Нормализация ответов в ThreatIntelEvent
    """
    
    # ВАЖНО: Никаких пробелов в URL!
    BASE_URL = "https://www.virustotal.com/api/v3/"
    
    # Типы индикаторов и соответствующие эндпоинты
    INDICATOR_ENDPOINTS = {
        'ip': 'ip_addresses/{indicator}',
        'domain': 'domains/{indicator}',
        'url': 'urls/{indicator}',
        'file': 'files/{indicator}'  # Для хэшей
    }
    
    # Public API лимит: 4 запроса в минуту
    # Используем 16 секунд для запаса (60/4 = 15, берем 16)
    REQUEST_DELAY = 16
    
    def __init__(self, max_cache_size: int = 1000):
        """
        Инициализация коллектора VirusTotal.
        
        Args:
            max_cache_size: Максимальный размер кэша в памяти
        """
        super().__init__("virustotal")
        self.api_key = Config.get_virustotal_api_key()
        self.session = self._create_session()
        self.cache = VTCache(maxsize=max_cache_size)
        
        # Проверяем наличие API ключа при инициализации
        self._check_api_key()
        
        self.logger.info("VirusTotal коллектор инициализирован")
        self.logger.info(f"API ключ: {'установлен' if self.api_key else 'ОТСУТСТВУЕТ'}")
        self.logger.info(f"Максимальный размер кэша: {max_cache_size}")
    
    def _check_api_key(self) -> None:
        """
        Проверяет наличие API ключа.
        
        Raises:
            VirusTotalAuthError: Если ключ отсутствует
        """
        if not self.api_key:
            error_msg = "API ключ VirusTotal не найден. Укажите VIRUSTOTAL_API_KEY в .env файле"
            self.logger.error(error_msg)
            raise VirusTotalAuthError(error_msg)
    
    def _create_session(self) -> requests.Session:
        """
        Создает настроенную сессию requests с заголовками аутентификации.
        
        Returns:
            Сессия с заголовком авторизации
        """
        session = requests.Session()
        session.headers.update({
            'x-apikey': self.api_key,
            'Accept': 'application/json',
            'User-Agent': 'ThreatDetector/1.0'
        })
        return session
    
    def _determine_indicator_type(self, indicator: str) -> str:
        """
        Определяет тип индикатора по его формату.
        
        Args:
            indicator: Строка индикатора (IP, домен, URL, хэш)
        
        Returns:
            Тип индикатора для API эндпоинта
        
        Raises:
            ValueError: Если тип не удалось определить
        """
        # Нормализуем индикатор (убираем протокол для URL)
        clean_indicator = indicator.lower().strip()
        if clean_indicator.startswith(('http://', 'https://')):
            return 'url'
        
        # Проверка на IP-адрес (IPv4)
        ip_parts = clean_indicator.split('.')
        if len(ip_parts) == 4 and all(part.isdigit() for part in ip_parts):
            if all(0 <= int(part) <= 255 for part in ip_parts):
                return 'ip'
        
        # Проверка на домен (содержит точки, но не начинается с http)
        if '.' in clean_indicator and not clean_indicator[0].isdigit():
            # Простая проверка: нет пробелов и спецсимволов
            if all(c.isalnum() or c in '.-_' for c in clean_indicator):
                return 'domain'
        
        # Хэши (MD5, SHA1, SHA256) обычно 32-64 символа, hex
        if len(clean_indicator) in (32, 40, 64) and all(
            c in '0123456789abcdef' for c in clean_indicator
        ):
            return 'file'
        
        # Если ничего не подошло, пробуем как домен (для обратной совместимости)
        self.logger.debug(f"Не удалось определить тип индикатора: {indicator}, используем 'domain'")
        return 'domain'
    
    @retry(
        stop=stop_after_attempt(5),  # Максимум 5 попыток
        wait=wait_exponential(multiplier=1, min=4, max=60),  # Экспоненциальная задержка
        retry=retry_if_exception_type((
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            VirusTotalRateLimitError
        )),
        before_sleep=before_sleep_log(logger, 20),  # Логируем перед повторной попыткой
        reraise=True
    )
    def _make_request(self, endpoint: str) -> Dict[str, Any]:
        """
        Выполняет HTTP запрос к VirusTotal API с retry логикой.
        
        Args:
            endpoint: Эндпоинт API (относительный путь)
        
        Returns:
            JSON ответ от API
        
        Raises:
            VirusTotalRateLimitError: При превышении лимита запросов
            VirusTotalAuthError: При ошибке аутентификации
            VirusTotalAPIError: При других ошибках API
        """
        # Убираем возможные пробелы из BASE_URL (защита от опечаток)
        base_url = self.BASE_URL.strip()
        url = urljoin(base_url, endpoint)
        
        self.logger.debug(f"Запрос к API: {url}")
        
        try:
            response = self.session.get(url, timeout=30)
            
            # Обработка специфических HTTP статусов
            if response.status_code == 429:
                self.logger.warning("Превышен лимит запросов к VirusTotal API")
                raise VirusTotalRateLimitError("Rate limit exceeded")
            
            if response.status_code == 401:
                self.logger.error("Ошибка аутентификации VirusTotal API")
                raise VirusTotalAuthError("Invalid API key")
            
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.Timeout:
            self.logger.error("Таймаут при запросе к VirusTotal API")
            raise
        except requests.exceptions.ConnectionError:
            self.logger.error("Ошибка соединения с VirusTotal API")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP ошибка: {e}")
            raise VirusTotalAPIError(f"HTTP {response.status_code}: {response.text[:200]}")
    
    def _normalize_response(self, indicator: str, indicator_type: str, 
                           raw_data: Dict[str, Any]) -> ThreatIntelEvent:
        """
        Нормализует ответ API в структурированный ThreatIntelEvent.
        
        Args:
            indicator: Проверяемый индикатор
            indicator_type: Тип индикатора
            raw_data: Сырой JSON ответ от API
        
        Returns:
            Нормализованное событие
        """
        # Извлекаем статистику анализа
        attributes = raw_data.get('data', {}).get('attributes', {})
        if not attributes:
            attributes = raw_data.get('attributes', {})
        
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        event = ThreatIntelEvent(
            source='virustotal',
            raw_data=raw_data,
            indicator=indicator,
            indicator_type=indicator_type,
            malicious_count=last_analysis_stats.get('malicious', 0),
            suspicious_count=last_analysis_stats.get('suspicious', 0),
            harmless_count=last_analysis_stats.get('harmless', 0),
            undetected_count=last_analysis_stats.get('undetected', 0)
        )
        
        # Логируем результат
        if event.malicious_count > 0:
            self.logger.warning(
                f"Найден вредоносный индикатор: {indicator} "
                f"(malicious: {event.malicious_count})"
            )
        else:
            self.logger.debug(f"Индикатор чист: {indicator}")
        
        return event
    
    def check_indicator(self, indicator: str) -> Optional[ThreatIntelEvent]:
        """
        Проверяет один индикатор через VirusTotal API с использованием кэша.
        
        Args:
            indicator: Индикатор для проверки (IP, домен, хэш)
        
        Returns:
            ThreatIntelEvent или None при ошибке
        """
        self.logger.debug(f"Проверка индикатора: {indicator}")
        
        # Определяем тип индикатора
        try:
            indicator_type = self._determine_indicator_type(indicator)
        except ValueError as e:
            self.logger.error(f"Не удалось определить тип индикатора {indicator}: {e}")
            return None
        
        # Проверяем кэш с составным ключом
        cached = self.cache.get(indicator, indicator_type)
        if cached:
            self.logger.debug(f"Найдено в кэше: {indicator} (тип: {indicator_type})")
            return cached
        
        # Формируем эндпоинт с URL-кодированием
        endpoint_template = self.INDICATOR_ENDPOINTS.get(indicator_type)
        if not endpoint_template:
            self.logger.error(f"Неподдерживаемый тип индикатора: {indicator_type}")
            return None
        
        # URL-кодируем индикатор для безопасности
        encoded_indicator = quote(indicator, safe='')
        endpoint = endpoint_template.format(indicator=encoded_indicator)
        
        # Выполняем запрос
        try:
            raw_data = self._make_request(endpoint)
            
            # Нормализуем ответ
            event = self._normalize_response(indicator, indicator_type, raw_data)
            
            # Сохраняем в кэш
            self.cache.set(indicator, indicator_type, event)
            
            # Защита от rate limiting (Public API: 4 запроса/минуту)
            # Пауза ТОЛЬКО после успешного запроса к API
            self.logger.debug(f"Пауза {self.REQUEST_DELAY}с для соблюдения rate limits")
            time.sleep(self.REQUEST_DELAY)
            
            return event
            
        except VirusTotalRateLimitError:
            # Если rate limit, ждем дольше и пробуем еще раз (tenacity сделает retry)
            self.logger.warning(f"Rate limit для {indicator}, повтор с экспоненциальной задержкой")
            raise
        except VirusTotalAuthError:
            # Ошибка аутентификации - не retry
            self.logger.error("Ошибка аутентификации, прекращаем проверку")
            return None
        except Exception as e:
            self.logger.error(f"Неожиданная ошибка при проверке {indicator}: {e}")
            return None
    
    def collect(self, indicators: List[str]) -> List[RawEvent]:
        """
        Проверяет список индикаторов через VirusTotal API.
        
        Args:
            indicators: Список индикаторов для проверки
        
        Returns:
            Список событий ThreatIntelEvent
        """
        self.logger.info(f"Начало проверки {len(indicators)} индикаторов")
        
        events = []
        successful = 0
        failed = 0
        
        for i, indicator in enumerate(indicators, 1):
            self.logger.info(f"Прогресс: {i}/{len(indicators)} - проверка {indicator}")
            
            event = self.check_indicator(indicator)
            if event:
                events.append(event)
                successful += 1
            else:
                failed += 1
        
        # Итоговая статистика
        cache_stats = self.cache.stats()
        self.logger.info(
            f"Проверка индикаторов завершена:\n"
            f"  Всего: {len(indicators)}\n"
            f"  Успешно: {successful}\n"
            f"  Ошибок: {failed}\n"
            f"  Кэш: {cache_stats}"
        )
        
        return events


# Функция-фабрика для создания коллектора
def create_collector(max_cache_size: int = 1000) -> VirusTotalCollector:
    """
    Создает и возвращает экземпляр коллектора VirusTotal.
    
    Args:
        max_cache_size: Максимальный размер кэша
    
    Returns:
        Настроенный коллектор
    
    Raises:
        VirusTotalAuthError: Если API ключ отсутствует
    """
    return VirusTotalCollector(max_cache_size=max_cache_size)


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Тестирование коллектора:
    python -m collectors.virustotal 8.8.8.8 google.com https://example.com
    """
    import sys
    
    # Настраиваем подробное логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)  # DEBUG
    
    if len(sys.argv) < 2:
        print("Использование: python -m collectors.virustotal <indicator1> [indicator2 ...]")
        sys.exit(1)
    
    indicators = sys.argv[1:]
    
    try:
        # Создаем коллектор с маленьким кэшем для тестирования LRU
        collector = VirusTotalCollector(max_cache_size=5)
        events = collector.collect(indicators)
        
        print(f"\nРезультаты проверки:")
        print(f"  Проверено индикаторов: {len(indicators)}")
        print(f"  Получено результатов: {len(events)}")
        print(f"  Статистика кэша: {collector.cache.stats()}")
        
        # Показываем результаты
        if events:
            print("\nДетали по индикаторам:")
            for event in events:
                print(f"\n--- {event.indicator} ({event.indicator_type}) ---")
                print(f"  Malicious: {event.malicious_count}")
                print(f"  Suspicious: {event.suspicious_count}")
                print(f"  Harmless: {event.harmless_count}")
                print(f"  Undetected: {event.undetected_count}")
        
    except VirusTotalAuthError as e:
        print(f"\nОшибка аутентификации: {e}")
        print("Убедитесь, что VIRUSTOTAL_API_KEY установлен в .env файле")
        sys.exit(1)
    except Exception as e:
        print(f"\nНеожиданная ошибка: {e}")
        sys.exit(1)
