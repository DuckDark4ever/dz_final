"""
Коллектор для проверки индикаторов (IP, домены, хэши) через VirusTotal API.
Реализует кэширование, retry логику и защиту от rate limiting.
"""
import time
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urljoin

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
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
    Простой кэш в памяти для результатов VirusTotal.
    Используем dataclass для автоматического создания методов.
    """
    cache: Dict[str, ThreatIntelEvent] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0
    
    def get(self, key: str) -> Optional[ThreatIntelEvent]:
        """Получить значение из кэша с подсчетом статистики."""
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        return None
    
    def set(self, key: str, value: ThreatIntelEvent) -> None:
        """Сохранить значение в кэш."""
        self.cache[key] = value
    
    def stats(self) -> Dict[str, int]:
        """Вернуть статистику использования кэша."""
        return {
            'size': len(self.cache),
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': round(self.hits / (self.hits + self.misses) * 100, 2) 
                        if (self.hits + self.misses) > 0 else 0
        }


class VirusTotalCollector(BaseCollector):
    """
    Коллектор для VirusTotal API v3.
    
    Особенности:
    - Кэширование результатов в памяти
    - Retry с экспоненциальной задержкой для rate limiting
    - Проверка наличия API ключа перед запросом
    - Нормализация ответов в ThreatIntelEvent
    - Статистика использования кэша
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3/"
    
    # Типы индикаторов и соответствующие эндпоинты
    INDICATOR_ENDPOINTS = {
        'ip': 'ip_addresses/{indicator}',
        'domain': 'domains/{indicator}',
        'url': 'urls/{indicator}',
        'file': 'files/{indicator}'  # Для хэшей
    }
    
    def __init__(self):
        """Инициализация коллектора VirusTotal."""
        super().__init__("virustotal")
        self.api_key = Config.get_virustotal_api_key()
        self.session = self._create_session()
        self.cache = VTCache()
        
        # Проверяем наличие API ключа при инициализации
        self._check_api_key()
        
        self.logger.info("VirusTotal коллектор инициализирован")
        self.logger.info(f"API ключ: {'установлен' if self.api_key else 'ОТСУТСТВУЕТ'}")
    
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
            'Accept': 'application/json'
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
        # Простая эвристика для определения типа
        if '.' in indicator and not indicator.replace('.', '').isdigit():
            # Содержит точки и не состоит только из цифр -> вероятно домен
            if ' ' not in indicator and '/' not in indicator:
                return 'domain'
        
        if indicator.count('.') == 3 and all(
            part.isdigit() and 0 <= int(part) <= 255 
            for part in indicator.split('.') 
            if part.isdigit()
        ):
            return 'ip'
        
        if indicator.startswith(('http://', 'https://')):
            return 'url'
        
        # Хэши (MD5, SHA1, SHA256) обычно 32-64 символа, hex
        if len(indicator) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in indicator):
            return 'file'
        
        # По умолчанию считаем доменом
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
            VirusTotalAPIError: При других ошибках API
        """
        url = urljoin(self.BASE_URL, endpoint)
        
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
        # Извлекаем статистику анализа, если доступна
        attributes = raw_data.get('data', {}).get('attributes', {})
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        # Для IP и доменов может быть другая структура
        if not last_analysis_stats and 'attributes' in raw_data:
            last_analysis_stats = raw_data['attributes'].get('last_analysis_stats', {})
        
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
        
        # Проверяем кэш
        cached = self.cache.get(indicator)
        if cached:
            self.logger.debug(f"Найдено в кэше: {indicator}")
            return cached
        
        # Определяем тип индикатора
        try:
            indicator_type = self._determine_indicator_type(indicator)
        except ValueError as e:
            self.logger.error(f"Не удалось определить тип индикатора {indicator}: {e}")
            return None
        
        # Формируем эндпоинт
        endpoint_template = self.INDICATOR_ENDPOINTS.get(indicator_type)
        if not endpoint_template:
            self.logger.error(f"Неподдерживаемый тип индикатора: {indicator_type}")
            return None
        
        endpoint = endpoint_template.format(indicator=indicator)
        
        # Выполняем запрос
        try:
            raw_data = self._make_request(endpoint)
            
            # Нормализуем ответ
            event = self._normalize_response(indicator, indicator_type, raw_data)
            
            # Сохраняем в кэш
            self.cache.set(indicator, event)
            
            # Защита от rate limiting (Public API: 4 запроса/минуту)
            # Добавляем паузу между запросами
            time.sleep(15)  # 60 секунд / 4 запроса = 15 секунд
            
            return event
            
        except VirusTotalRateLimitError:
            # Если rate limit, ждем дольше и пробуем еще раз (tenacity сделает retry)
            self.logger.warning(f"Rate limit для {indicator}, повтор через 60с")
            time.sleep(60)
            # Пробрасываем исключение для retry
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
        
        for indicator in indicators:
            event = self.check_indicator(indicator)
            if event:
                events.append(event)
                successful += 1
            else:
                failed += 1
        
        # Итоговая статистика
        self.logger.info(
            f"Проверка индикаторов завершена:\n"
            f"  Всего: {len(indicators)}\n"
            f"  Успешно: {successful}\n"
            f"  Ошибок: {failed}\n"
            f"  Кэш: {self.cache.stats()}"
        )
        
        return events


# Функция-фабрика для создания коллектора
def create_collector() -> VirusTotalCollector:
    """
    Создает и возвращает экземпляр коллектора VirusTotal.
    
    Returns:
        Настроенный коллектор
    
    Raises:
        VirusTotalAuthError: Если API ключ отсутствует
    """
    return VirusTotalCollector()


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Тестирование коллектора:
    python -m collectors.virustotal 8.8.8.8 google.com
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
        collector = VirusTotalCollector()
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
