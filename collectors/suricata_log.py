"""
Коллектор для парсинга логов Suricata в формате EVE JSON (JSON Lines).
Читает файл построчно, фильтрует события (alert, dns) и нормализует их в объекты SuricataEvent.
"""
import json
from pathlib import Path
from typing import List, Generator, Dict, Any, Optional
import sys

# Для защиты от чрезмерно больших файлов
import os

from collectors.base import BaseCollector
from models.event import SuricataEvent, RawEvent
from config import Config
from utils.logger import logger


class SuricataLogCollector(BaseCollector):
    """
    Коллектор для анализа EVE JSON логов Suricata.
    
    Особенности:
    - Построчное чтение (поддержка JSON Lines)
    - Защита от слишком больших файлов (OOM prevention)
    - Фильтрация только релевантных типов событий (alert, dns)
    - Нормализация полей в структурированную модель SuricataEvent
    - Устойчивость к битой кодировке (errors='ignore')
    """
    
    # Типы событий Suricata, которые нас интересуют
    INTERESTING_EVENT_TYPES = {'alert', 'dns'}
    
    def __init__(self, file_path: str):
        """
        Инициализация коллектора с путем к файлу лога.
        
        Args:
            file_path: Путь к файлу eve.json
        """
        super().__init__(f"suricata:{Path(file_path).name}")
        self.file_path = Path(file_path)
        self.logger.info(f"Инициализирован коллектор для файла: {self.file_path}")
        
        # Проверяем существование файла при инициализации
        if not self.file_path.exists():
            self.logger.error(f"Файл не существует: {self.file_path}")
            raise FileNotFoundError(f"Лог файл не найден: {self.file_path}")
        
        # Проверяем размер файла
        self._check_file_size()
    
    def _check_file_size(self) -> None:
        """
        Проверяет размер файла на превышение лимита.
        Защита от случайной загрузки многогигабайтных файлов.
        
        Raises:
            ValueError: Если файл превышает максимальный разрешенный размер
        """
        max_size_mb = Config.get_max_file_size_mb()
        file_size_mb = self.file_path.stat().st_size / (1024 * 1024)
        
        if file_size_mb > max_size_mb:
            error_msg = (f"Файл слишком большой: {file_size_mb:.1f} МБ "
                        f"(макс. {max_size_mb} МБ)")
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        self.logger.debug(f"Размер файла: {file_size_mb:.1f} МБ")
    
    def _line_generator(self) -> Generator[str, None, None]:
        """
        Генератор для безопасного построчного чтения файла.
        Использует генератор для экономии памяти.
        
        Yields:
            Строка из файла (непустая)
        """
        line_count = 0
        try:
            with open(
                self.file_path, 
                'r', 
                encoding='utf-8', 
                errors='ignore'  # Критично для сетевых логов с битыми символами
            ) as f:
                for line in f:
                    line = line.strip()
                    if line:  # Пропускаем пустые строки
                        line_count += 1
                        yield line
        except IOError as e:
            self.logger.error(f"Ошибка чтения файла: {e}")
            raise
        
        self.logger.debug(f"Прочитано строк в файле: {line_count}")
    
    def _parse_line(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """
        Парсит одну строку JSON с защитой от ошибок.
        
        Args:
            line: Строка для парсинга
            line_num: Номер строки (для логирования)
        
        Returns:
            Распарсенный словарь или None в случае ошибки
        """
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            self.logger.warning(
                f"Ошибка парсинга JSON в строке {line_num}: {e}. "
                f"Строка: {line[:100]}..."  # Логируем только начало строки
            )
            return None
    
    def _normalize_event(self, raw_data: Dict[str, Any]) -> Optional[SuricataEvent]:
        """
        Нормализует сырой JSON событие в структурированный SuricataEvent.
        
        Args:
            raw_data: Сырой JSON объект события
        
        Returns:
            SuricataEvent или None, если событие не содержит обязательных полей
        """
        # Проверяем наличие обязательного поля event_type
        event_type = raw_data.get('event_type')
        if not event_type:
            self.logger.debug("Пропущено событие без event_type")
            return None
        
        # Создаем базовое событие
        event = SuricataEvent(
            source='suricata',
            raw_data=raw_data,
            event_type=event_type
        )
        
        # Извлекаем сетевые адреса (могут быть в разных местах)
        src_ip = raw_data.get('src_ip')
        dest_ip = raw_data.get('dest_ip')
        
        if src_ip:
            event.src_ip = src_ip
        if dest_ip:
            event.dest_ip = dest_ip
        
        # Специфические поля для alert событий
        if event_type == 'alert' and 'alert' in raw_data:
            alert_data = raw_data['alert']
            event.alert_severity = alert_data.get('severity')
            event.alert_signature = alert_data.get('signature')
        
        # Специфические поля для DNS событий
        if event_type == 'dns' and 'dns' in raw_data:
            dns_data = raw_data['dns']
            event.dns_query = dns_data.get('rrname')
            event.dns_type = dns_data.get('type')
        
        return event
    
    def collect(self) -> List[RawEvent]:
        """
        Основной метод сбора данных из лога Suricata.
        
        Returns:
            Список нормализованных событий (только alert и dns)
        """
        self.logger.info(f"Начало сбора данных из: {self.file_path}")
        
        events = []
        processed = 0
        filtered = 0
        errors = 0
        
        # Построчно обрабатываем файл
        for line_num, line in enumerate(self._line_generator(), 1):
            processed += 1
            
            # Парсим JSON
            raw_data = self._parse_line(line, line_num)
            if raw_data is None:
                errors += 1
                continue
            
            # Проверяем тип события
            event_type = raw_data.get('event_type')
            if event_type not in self.INTERESTING_EVENT_TYPES:
                self.logger.debug(f"Пропущено событие типа: {event_type}")
                filtered += 1
                continue
            
            # Нормализуем событие
            event = self._normalize_event(raw_data)
            if event:
                events.append(event)
                self.logger.debug(
                    f"Добавлено событие: {event.event_type} | "
                    f"{event.src_ip or '-'} -> {event.dest_ip or '-'}"
                )
        
        # Итоговая статистика
        self.logger.info(
            f"Сбор данных завершен. Статистика:\n"
            f"  Всего обработано строк: {processed}\n"
            f"  Отфильтровано (неинтересные типы): {filtered}\n"
            f"  Ошибок парсинга: {errors}\n"
            f"  Получено событий: {len(events)}"
        )
        
        # Детальная разбивка по типам
        if events and self.logger.isEnabledFor(10):  # DEBUG level
            type_stats = {}
            for e in events:
                type_stats[e.event_type] = type_stats.get(e.event_type, 0) + 1
            self.logger.debug(f"Распределение по типам: {type_stats}")
        
        return events


# Функция-фабрика для удобного создания коллектора
def create_collector(file_path: str) -> SuricataLogCollector:
    """
    Создает и возвращает экземпляр коллектора Suricata.
    
    Args:
        file_path: Путь к файлу лога
    
    Returns:
        Настроенный коллектор
    
    Raises:
        FileNotFoundError: Если файл не существует
        ValueError: Если файл слишком большой
    """
    return SuricataLogCollector(file_path)


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Позволяет протестировать коллектор напрямую:
    python -m collectors.suricata_log /path/to/eve.json
    """
    import sys
    
    # Настраиваем более подробный вывод для тестов
    from utils.logger import setup_logger
    setup_logger(console_level=10)  # DEBUG
    
    if len(sys.argv) < 2:
        print("Использование: python -m collectors.suricata_log <path_to_eve.json>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        collector = SuricataLogCollector(file_path)
        events = collector.collect()
        
        print(f"\nРезультаты тестирования:")
        print(f"  Получено событий: {len(events)}")
        
        # Показываем первые 3 события для примера
        if events:
            print("\nПримеры событий (первые 3):")
            for i, event in enumerate(events[:3]):
                print(f"\n--- Событие {i+1} ---")
                print(f"  Тип: {event.event_type}")
                if event.src_ip:
                    print(f"  Source IP: {event.src_ip}")
                if event.dest_ip:
                    print(f"  Dest IP: {event.dest_ip}")
                if event.alert_signature:
                    print(f"  Alert: {event.alert_signature}")
                if event.dns_query:
                    print(f"  DNS Query: {event.dns_query}")
        
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)
