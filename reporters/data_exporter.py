"""
Модуль для экспорта результатов анализа в структурированные форматы.
Поддерживает JSON (полные данные) и CSV (табличное представление).
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

import pandas as pd

from reporters.base import BaseReporter
from models.alert import Alert
from models.event import RawEvent
from utils.logger import logger


class DataExporter(BaseReporter):
    """
    Экспортер данных в JSON и CSV форматы.
    
    Особенности:
    - JSON: полные данные с сохранением структуры
    - CSV: плоское табличное представление для анализа в Excel
    - Раздельная выгрузка событий и алертов
    - Дата-штамп в именах файлов
    """
    
    def __init__(self, pretty_json: bool = True):
        """
        Инициализация экспортера.
        
        Args:
            pretty_json: Форматировать JSON с отступами
        """
        super().__init__("data_exporter")
        self.pretty_json = pretty_json
        
        self.logger.info(
            f"Экспортер данных инициализирован:\n"
            f"  Форматы: JSON, CSV\n"
            f"  JSON форматирование: {'да' if pretty_json else 'нет'}"
        )
    
    def _ensure_output_dir(self, output_dir: str) -> Path:
        """
        Создает директорию для выходных файлов.
        
        Args:
            output_dir: Путь к директории
        
        Returns:
            Path объект директории
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path
    
    def _get_timestamp(self) -> str:
        """Возвращает строку с текущим временем для имен файлов."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _alerts_to_dataframe(self, alerts: List[Alert]) -> pd.DataFrame:
        """
        Преобразует список алертов в pandas DataFrame.
        
        Args:
            alerts: Список алертов
        
        Returns:
            DataFrame с плоской структурой
        """
        data = []
        
        for alert in alerts:
            row = {
                'timestamp': alert.timestamp.isoformat(),
                'title': alert.title,
                'severity': alert.severity,
                'source': alert.source,
                'indicator': alert.indicator,
                'description': alert.description,
                'action_taken': alert.action_taken,
                'action_details': alert.action_details
            }
            
            # Добавляем ключевые поля из raw_data
            if alert.raw_data:
                if 'cvss' in alert.raw_data:
                    row['cvss_score'] = alert.raw_data['cvss']
                if 'malicious' in alert.raw_data:
                    row['malicious_count'] = alert.raw_data['malicious']
                if 'query_count' in alert.raw_data:
                    row['query_count'] = alert.raw_data['query_count']
            
            data.append(row)
        
        return pd.DataFrame(data)
    
    def _events_to_dataframe(self, events: List[RawEvent]) -> pd.DataFrame:
        """
        Преобразует список сырых событий в pandas DataFrame.
        
        Args:
            events: Список событий
        
        Returns:
            DataFrame с плоской структурой
        """
        data = []
        
        for event in events:
            row = {
                'timestamp': event.timestamp.isoformat(),
                'source': event.source,
                'event_type': getattr(event, 'event_type', 'unknown')
            }
            
            # Добавляем специфические поля в зависимости от типа
            if hasattr(event, 'src_ip') and event.src_ip:
                row['src_ip'] = event.src_ip
            
            if hasattr(event, 'dest_ip') and event.dest_ip:
                row['dest_ip'] = event.dest_ip
            
            if hasattr(event, 'dns_query') and event.dns_query:
                row['dns_query'] = event.dns_query
            
            if hasattr(event, 'vuln_id') and event.vuln_id:
                row['vuln_id'] = event.vuln_id
                row['cvss_score'] = getattr(event, 'cvss_score', 0)
            
            if hasattr(event, 'indicator') and event.indicator:
                row['indicator'] = event.indicator
                row['malicious_count'] = getattr(event, 'malicious_count', 0)
            
            data.append(row)
        
        return pd.DataFrame(data)
    
    def export_json(self, data: Any, output_dir: str, prefix: str) -> Optional[str]:
        """
        Экспортирует данные в JSON файл.
        
        Args:
            data: Данные для экспорта
            output_dir: Директория для сохранения
            prefix: Префикс имени файла
        
        Returns:
            Путь к сохраненному файлу или None при ошибке
        """
        output_path = self._ensure_output_dir(output_dir)
        filename = output_path / f"{prefix}_{self._get_timestamp()}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if self.pretty_json:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                else:
                    json.dump(data, f, ensure_ascii=False, default=str)
            
            file_size = filename.stat().st_size / 1024  # KB
            self.logger.info(f"JSON экспорт завершен: {filename} ({file_size:.1f} KB)")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"Ошибка при JSON экспорте: {e}")
            return None
    
    def export_csv(self, df: pd.DataFrame, output_dir: str, prefix: str) -> Optional[str]:
        """
        Экспортирует DataFrame в CSV файл.
        
        Args:
            df: DataFrame для экспорта
            output_dir: Директория для сохранения
            prefix: Префикс имени файла
        
        Returns:
            Путь к сохраненному файлу или None при ошибке
        """
        if df.empty:
            self.logger.warning(f"DataFrame пуст, CSV экспорт пропущен: {prefix}")
            return None
        
        output_path = self._ensure_output_dir(output_dir)
        filename = output_path / f"{prefix}_{self._get_timestamp()}.csv"
        
        try:
            df.to_csv(filename, index=False, encoding='utf-8')
            
            file_size = filename.stat().st_size / 1024  # KB
            self.logger.info(f"CSV экспорт завершен: {filename} ({file_size:.1f} KB)")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"Ошибка при CSV экспорте: {e}")
            return None
    
    def export(self, alerts: List[Alert], events: List[RawEvent], output_dir: str) -> Dict[str, List[str]]:
        """
        Экспортирует все данные в JSON и CSV форматы.
        
        Args:
            alerts: Список алертов
            events: Список сырых событий
            output_dir: Директория для сохранения
        
        Returns:
            Словарь с путями к файлам по форматам
        """
        self.logger.info(
            f"Начало экспорта данных:\n"
            f"  Алертов: {len(alerts)}\n"
            f"  Событий: {len(events)}\n"
            f"  Директория: {output_dir}"
        )
        
        results = {
            'json': [],
            'csv': []
        }
        
        # 1. Экспорт алертов
        if alerts:
            # JSON
            alerts_json = [alert.__dict__ for alert in alerts]
            json_file = self.export_json(alerts_json, output_dir, "alerts")
            if json_file:
                results['json'].append(json_file)
            
            # CSV
            alerts_df = self._alerts_to_dataframe(alerts)
            csv_file = self.export_csv(alerts_df, output_dir, "alerts")
            if csv_file:
                results['csv'].append(csv_file)
        
        # 2. Экспорт сырых событий
        if events:
            # JSON
            events_json = []
            for event in events:
                event_dict = event.__dict__.copy()
                # Преобразуем timestamp в строку для JSON
                event_dict['timestamp'] = event.timestamp.isoformat()
                events_json.append(event_dict)
            
            json_file = self.export_json(events_json, output_dir, "events")
            if json_file:
                results['json'].append(json_file)
            
            # CSV
            events_df = self._events_to_dataframe(events)
            csv_file = self.export_csv(events_df, output_dir, "events")
            if csv_file:
                results['csv'].append(csv_file)
        
        # Итоговая статистика
        self.logger.info(
            f"Экспорт завершен:\n"
            f"  JSON файлов: {len(results['json'])}\n"
            f"  CSV файлов: {len(results['csv'])}"
        )
        
        return results
    
    def generate(self, alerts: List[Alert], output_dir: str, 
                 events: Optional[List[RawEvent]] = None) -> List[str]:
        """
        Обёртка над export() для соответствия интерфейсу BaseReporter.
        
        Args:
            alerts: Список алертов
            output_dir: Директория для сохранения
            events: Сырые события (опционально, если None — экспортируются только алерты)
        
        Returns:
            Список путей к сгенерированным файлам
        """
        # Если events не переданы, экспортируем только алерты
        events_to_export = events if events is not None else []
        
        # Вызываем основной метод export
        results = self.export(alerts, events_to_export, output_dir)
        
        # Возвращаем плоский список путей (как требует интерфейс)
        files = []
        for fmt_file_list in results.values():
            files.extend(fmt_file_list)
        
        return files  # ← Конец метода generate() и класса DataExporter


# Функция-фабрика
def create_reporter(pretty_json: bool = True) -> DataExporter:
    """
    Создает экземпляр экспортера данных.
    
    Args:
        pretty_json: Форматировать JSON с отступами
    
    Returns:
        Настроенный экспортер
    """
    return DataExporter(pretty_json=pretty_json)


# Блок тестирования
if __name__ == "__main__":
    import tempfile
    from datetime import datetime
    
    # Настраиваем логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)
    
    # Создаем тестовые данные
    test_alerts = [
        Alert(
            title="Test Alert 1",
            severity="HIGH",
            source="test",
            description="Test description",
            indicator="test.indicator.com",
            timestamp=datetime.now(),
            raw_data={'cvss': 8.5, 'malicious': 5}
        ),
        Alert(
            title="Test Alert 2",
            severity="MEDIUM",
            source="test",
            description="Another test",
            indicator="192.168.1.100",
            timestamp=datetime.now(),
            raw_data={'query_count': 150}
        )
    ]
    
    test_events = [
        RawEvent(
            source='test',
            raw_data={'test': 'data'},
            timestamp=datetime.now()
        )
    ]
    
    # Создаем временную директорию
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\nТестовая директория: {tmpdir}")
        
        # Создаем экспортер
        exporter = DataExporter(pretty_json=True)
        
        # Экспортируем данные
        results = exporter.export(test_alerts, test_events, tmpdir)
        
        print(f"\nРезультаты экспорта:")
        for fmt, files in results.items():
            print(f"\n{fmt.upper()}:")
            for file in files:
                size = Path(file).stat().st_size
                print(f"  - {Path(file).name} ({size} bytes)")
