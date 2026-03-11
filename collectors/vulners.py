"""
Коллектор для поиска уязвимостей через Vulners API.
Реализует поиск по названию и версии ПО с фильтрацией по CVSS.
"""
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import quote
from collections import OrderedDict
from functools import lru_cache

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from collectors.base import BaseCollector
from models.event import VulnerabilityEvent, RawEvent
from config import Config
from utils.logger import logger


class VulnersAPIError(Exception):
    """Базовое исключение для ошибок Vulners API."""
    pass


class VulnersRateLimitError(VulnersAPIError):
    """Превышение лимита запросов к API."""
    pass


class VulnersCache:
    """
    Кэш для результатов Vulners с ограничением размера (LRU).
    Использует OrderedDict для эффективного вытеснения.
    """
    
    def __init__(self, maxsize: int = 500):
        """
        Инициализация кэша.
        
        Args:
            maxsize: Максимальное количество записей
        """
        self.cache = OrderedDict()
        self.maxsize = maxsize
        self.hits = 0
        self.misses = 0
    
    def _make_key(self, software: str, version: str) -> str:
        """Создает ключ для кэша."""
        return f"{software.lower().strip()}:{version.lower().strip()}"
    
    def get(self, software: str, version: str) -> Optional[List[VulnerabilityEvent]]:
        """
        Получает значение из кэша.
        
        Args:
            software: Название ПО
            version: Версия
        
        Returns:
            Список уязвимостей или None
        """
        key = self._make_key(software, version)
        
        if key in self.cache:
            # LRU: перемещаем в конец (самый свежий)
            self.cache.move_to_end(key)
            self.hits += 1
            return self.cache[key]
        
        self.misses += 1
        return None
    
    def set(self, software: str, version: str, value: List[VulnerabilityEvent]) -> None:
        """
        Сохраняет значение в кэш.
        
        Args:
            software: Название ПО
            version: Версия
            value: Список уязвимостей
        """
        key = self._make_key(software, version)
        
        # Добавляем или обновляем элемент
        self.cache[key] = value
        self.cache.move_to_end(key)
        
        # Проверяем превышение размера
        if len(self.cache) > self.maxsize:
            # Удаляем самый старый элемент (первый в OrderedDict)
            removed_key, removed_value = self.cache.popitem(last=False)
            logger.debug(f"Кэш Vulners переполнен, удален элемент: {removed_key}")
    
    def stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику использования кэша.
        
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


class VulnersCollector(BaseCollector):
    """
    Коллектор для Vulners API (поиск уязвимостей).
    
    Особенности:
    - Поиск по software:nginx AND version:1.18.0
    - Фильтрация по CVSS (порог из конфига)
    - Кэширование результатов с ограничением размера (LRU)
    - Устойчивый парсинг CVSS (защита от "N/A", null)
    - Retry логика с экспоненциальной задержкой
    """
    
    BASE_URL = "https://vulners.com/api/v3/"
    
    # Эндпоинты API
    SEARCH_ENDPOINT = "search/lucene/"
    
    # Публичный API: ~5 запросов/сек
    REQUEST_DELAY = 0.2  # 200ms между запросами
    
    def __init__(self, use_api_key: bool = True, max_cache_size: int = 500):
        """
        Инициализация Vulners коллектора.
        
        Args:
            use_api_key: Использовать API ключ (если есть) или публичный доступ
            max_cache_size: Максимальный размер кэша
        """
        super().__init__("vulners")
        
        self.api_key = Config.get_vulners_api_key() if use_api_key else None
        self.session = self._create_session()
        
        # Кэш с ограничением размера
        self.cache = VulnersCache(maxsize=max_cache_size)
        
        self.logger.info(
            f"Vulners коллектор инициализирован:\n"
            f"  Режим: {'API ключ' if self.api_key else 'публичный (ограниченный)'}\n"
            f"  Порог CVSS: {Config.get_cvss_threshold()}\n"
            f"  Размер кэша: {max_cache_size}"
        )
    
    def _create_session(self) -> requests.Session:
        """
        Создает настроенную сессию requests.
        
        Returns:
            Сессия с заголовками
        """
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'ThreatDetector/1.0',
            'Content-Type': 'application/json'
        })
        
        if self.api_key:
            session.headers.update({'X-API-Key': self.api_key})
        
        return session
    
    def _build_query(self, software: str, version: str) -> str:
        """
        Строит поисковый запрос для Vulners.
        
        Args:
            software: Название ПО (например, nginx)
            version: Версия (например, 1.18.0)
        
        Returns:
            Строка запроса в формате Lucene
        """
        # Экранируем специальные символы
        safe_software = quote(software)
        safe_version = quote(version)
        
        return f"software:{safe_software} AND version:{safe_version}"
    
    def _parse_software_spec(self, spec: str) -> Optional[Tuple[str, str]]:
        """
        Парсит строку 'software version' с обработкой краевых случаев.
        
        Поддерживает:
        - "nginx 1.18.0" -> ("nginx", "1.18.0")
        - "Apache HTTP Server 2.4.49" -> ("Apache HTTP Server", "2.4.49")
        - "Microsoft Windows 10" -> ("Microsoft Windows", "10")
        
        Args:
            spec: Строка вида "software version"
        
        Returns:
            Кортеж (software, version) или None при ошибке парсинга
        """
        spec = spec.strip()
        
        # Ищем последнее вхождение пробела как разделитель
        last_space = spec.rfind(' ')
        
        if last_space == -1:
            self.logger.warning(f"Не удалось распарсить спецификацию ПО (нет пробела): {spec}")
            return None
        
        software = spec[:last_space].strip()
        version = spec[last_space + 1:].strip()
        
        # Валидация
        if not software:
            self.logger.warning(f"Название ПО пустое в спецификации: {spec}")
            return None
        
        if not version:
            self.logger.warning(f"Версия ПО пустая в спецификации: {spec}")
            return None
        
        # Проверка, что версия не содержит пробелов (если содержит - возможно, парсинг неверный)
        if ' ' in version:
            self.logger.warning(f"Версия содержит пробелы, возможно ошибка парсинга: {spec}")
            # Всё равно возвращаем, но с предупреждением
        
        return software, version
    
    def _parse_cvss(self, cvss_data: Any) -> float:
        """
        Устойчивый парсинг CVSS балла из различных форматов.
        
        Vulners может возвращать:
        - float: 9.8
        - dict: {"score": 9.8, "vector": "AV:N/..."}
        - string: "9.8"
        - string: "N/A"
        - null
        - отсутствие поля
        
        Args:
            cvss_data: Данные CVSS из API
        
        Returns:
            Числовое значение CVSS (0.0 если не удалось распарсить)
        """
        if cvss_data is None:
            return 0.0
        
        # Если это словарь с ключом score
        if isinstance(cvss_data, dict):
            score = cvss_data.get('score')
            if score is not None:
                return self._parse_cvss(score)  # Рекурсивно парсим score
        
        # Если это строка
        if isinstance(cvss_data, str):
            cvss_str = cvss_data.strip().lower()
            if cvss_str in ('', 'n/a', 'none', 'null', 'undefined'):
                return 0.0
            
            try:
                return float(cvss_str)
            except (ValueError, TypeError):
                self.logger.debug(f"Не удалось распарсить строку CVSS: {cvss_data}")
                return 0.0
        
        # Если это число
        try:
            return float(cvss_data)
        except (ValueError, TypeError):
            self.logger.debug(f"Не удалось распарсить CVSS: {cvss_data} (тип: {type(cvss_data)})")
            return 0.0
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            VulnersRateLimitError
        )),
        before_sleep=before_sleep_log(logger, 20),
        reraise=True
    )
    def _search_vulnerabilities(self, query: str) -> Dict[str, Any]:
        """
        Выполняет поиск уязвимостей через Vulners API.
        
        Args:
            query: Поисковый запрос в формате Lucene
        
        Returns:
            JSON ответ от API
        
        Raises:
            VulnersRateLimitError: При превышении лимита
            VulnersAPIError: При других ошибках
        """
        url = f"{self.BASE_URL}{self.SEARCH_ENDPOINT}"
        
        payload = {
            'query': query,
            'size': 100,  # Максимальное количество результатов
            'fields': ['id', 'title', 'cvss', 'description', 'affectedSoftware']
        }
        
        self.logger.debug(f"Поиск уязвимостей: {query}")
        
        try:
            response = self.session.post(url, json=payload, timeout=30)
            
            # Обработка rate limiting
            if response.status_code == 429:
                self.logger.warning("Rate limit достигнут")
                raise VulnersRateLimitError("Too many requests")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.Timeout:
            self.logger.error("Таймаут при запросе к Vulners API")
            raise
        except requests.exceptions.ConnectionError:
            self.logger.error("Ошибка соединения с Vulners API")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP ошибка: {e}")
            raise VulnersAPIError(f"HTTP {response.status_code}: {response.text[:200]}")
    
    def _normalize_vulnerability(self, raw_vuln: Dict[str, Any]) -> Optional[VulnerabilityEvent]:
        """
        Нормализует сырой ответ API в структурированное событие.
        
        Args:
            raw_vuln: Сырые данные об уязвимости
        
        Returns:
            VulnerabilityEvent или None, если нет обязательных полей
        """
        source_data = raw_vuln.get('_source', {})
        
        # Извлекаем ID (обязательное поле)
        vuln_id = source_data.get('id') or raw_vuln.get('id')
        if not vuln_id:
            self.logger.debug("Пропущена уязвимость без ID")
            return None
        
        # Устойчивый парсинг CVSS
        cvss_raw = source_data.get('cvss')
        cvss_score = self._parse_cvss(cvss_raw)
        
        # Фильтруем по порогу CVSS
        if cvss_score < Config.get_cvss_threshold():
            self.logger.debug(
                f"Уязвимость {vuln_id} ниже порога: {cvss_score} < {Config.get_cvss_threshold()}"
            )
            return None
        
        # Извлекаем affected software
        affected = source_data.get('affectedSoftware', [])
        if isinstance(affected, list):
            affected_str = ', '.join(str(a) for a in affected if a)
        else:
            affected_str = str(affected) if affected else 'unknown'
        
        return VulnerabilityEvent(
            source='vulners',
            raw_data=raw_vuln,
            vuln_id=vuln_id,
            title=source_data.get('title', 'No title'),
            cvss_score=cvss_score,
            description=source_data.get('description', 'No description'),
            affected_software=affected_str
        )
    
    def search(self, software: str, version: str) -> List[VulnerabilityEvent]:
        """
        Ищет уязвимости для конкретного ПО и версии.
        
        Args:
            software: Название ПО
            version: Версия
        
        Returns:
            Список найденных уязвимостей (с CVSS >= порога)
        """
        # Проверка кэша
        cached = self.cache.get(software, version)
        if cached is not None:
            self.logger.debug(f"Найдено в кэше: {software} {version}")
            return cached
        
        self.logger.info(f"Поиск уязвимостей для {software} {version}")
        
        query = self._build_query(software, version)
        
        try:
            response = self._search_vulnerabilities(query)
            
            vulnerabilities = []
            
            # Парсим результаты
            search_data = response.get('data', {}).get('search', [])
            
            for item in search_data:
                vuln = self._normalize_vulnerability(item)
                if vuln:
                    vulnerabilities.append(vuln)
                    self.logger.debug(
                        f"Найдена уязвимость: {vuln.vuln_id} "
                        f"(CVSS: {vuln.cvss_score})"
                    )
            
            # Сохраняем в кэш
            self.cache.set(software, version, vulnerabilities)
            
            # Защита от rate limiting
            time.sleep(self.REQUEST_DELAY)
            
            self.logger.info(f"Найдено уязвимостей: {len(vulnerabilities)}")
            return vulnerabilities
            
        except VulnersRateLimitError:
            self.logger.error("Rate limit превышен, попробуйте позже")
            return []
        except Exception as e:
            self.logger.error(f"Ошибка при поиске уязвимостей: {e}")
            return []
    
    def collect(self, software_list: List[str]) -> List[RawEvent]:
        """
        Основной метод сбора данных (интерфейс BaseCollector).
        
        Args:
            software_list: Список строк вида "nginx 1.18.0", 
                          "Apache HTTP Server 2.4.49"
        
        Returns:
            Список найденных уязвимостей
        """
        self.logger.info(f"Начало сбора данных для {len(software_list)} позиций")
        
        all_vulnerabilities = []
        failed = 0
        
        for item in software_list:
            # Парсим "nginx 1.18.0" на софт и версию
            parsed = self._parse_software_spec(item)
            
            if parsed is None:
                self.logger.warning(f"Некорректный формат: {item}, пропускаем")
                failed += 1
                continue
            
            software, version = parsed
            vulnerabilities = self.search(software, version)
            all_vulnerabilities.extend(vulnerabilities)
        
        # Статистика кэша
        cache_stats = self.cache.stats()
        
        self.logger.info(
            f"Сбор данных завершен:\n"
            f"  Всего позиций: {len(software_list)}\n"
            f"  Ошибок парсинга: {failed}\n"
            f"  Найдено уязвимостей: {len(all_vulnerabilities)}\n"
            f"  Кэш: {cache_stats}"
        )
        
        return all_vulnerabilities
    
    def clear_cache(self) -> None:
        """Очищает кэш."""
        self.cache = VulnersCache(maxsize=self.cache.maxsize)
        self.logger.info("Кэш очищен")


# Функция-фабрика
def create_collector(use_api_key: bool = True, max_cache_size: int = 500) -> VulnersCollector:
    """
    Создает экземпляр Vulners коллектора.
    
    Args:
        use_api_key: Использовать API ключ
        max_cache_size: Максимальный размер кэша
    
    Returns:
        Настроенный коллектор
    """
    return VulnersCollector(use_api_key=use_api_key, max_cache_size=max_cache_size)


# Блок тестирования
if __name__ == "__main__":
    import sys
    
    from utils.logger import setup_logger
    setup_logger(console_level=10)
    
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ VULNERS КОЛЛЕКТОРА")
    print("=" * 60)
    
    # Тест 1: Парсинг спецификаций
    print("\n1. ТЕСТ ПАРСИНГА СПЕЦИФИКАЦИЙ")
    collector = VulnersCollector()
    
    test_specs = [
        "nginx 1.18.0",
        "Apache HTTP Server 2.4.49",
        "Microsoft Windows 10",
        "php 7.4",
        "   padded   version   1.0   ",  # С пробелами
        "noversion",  # Ошибка
        "onlyspace ",  # Ошибка
        "  "  # Пусто
    ]
    
    for spec in test_specs:
        result = collector._parse_software_spec(spec)
        print(f"  '{spec}' -> {result}")
    
    # Тест 2: Парсинг CVSS
    print("\n2. ТЕСТ ПАРСИНГА CVSS")
    
    test_cvss = [
        (9.8, "float"),
        ({"score": 9.8, "vector": "AV:N/AC:L"}, "dict with score"),
        ("9.8", "string number"),
        ("N/A", "string N/A"),
        ("", "empty string"),
        (None, "null"),
        ("invalid", "invalid string"),
        ([], "empty list")
    ]
    
    for cvss, desc in test_cvss:
        parsed = collector._parse_cvss(cvss)
        print(f"  {desc:20} -> {parsed}")
    
    # Тест 3: Реальный поиск (если передан аргумент)
    if len(sys.argv) >= 3:
        print("\n3. РЕАЛЬНЫЙ ПОИСК")
        software = sys.argv[1]
        version = sys.argv[2]
        
        print(f"Поиск уязвимостей для {software} {version}...")
        results = collector.search(software, version)
        
        print(f"\nРезультаты для {software} {version}:")
        print(f"Найдено уязвимостей: {len(results)}")
        
        for i, vuln in enumerate(results[:5], 1):  # Показываем первые 5
            print(f"\n--- {i}. {vuln.vuln_id} ---")
            print(f"CVSS: {vuln.cvss_score}")
            print(f"Title: {vuln.title[:100]}...")
        
        if len(results) > 5:
            print(f"\n... и еще {len(results) - 5} уязвимостей")
        
        print(f"\nСтатистика кэша: {collector.cache.stats()}")
