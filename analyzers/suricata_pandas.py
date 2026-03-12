"""
Suricata Pandas Analyzer 
Анализирует логи Suricata, обнаруживает сканирования портов и IP из черных списков
"""
import pandas as pd
from typing import List, Any
from datetime import datetime

from analyzers.base import BaseAnalyzer
from models.alert import Alert
from models.event import SuricataEvent
from config import Config
from utils.logger import logger


class SuricataPandasAnalyzer(BaseAnalyzer):
    """
    Анализатор логов Suricata с использованием Pandas.
    
    Возможности:
    - Создание DataFrame из событий Suricata
    - Группировка по сигнатурам
    - Подсчет частоты событий
    - Выявление сканирования портов
    - Обнаружение IP из черных списков
    """
    
    def __init__(self):
        super().__init__("suricata_pandas")
        
        # Пороговые значения из конфига или по умолчанию
        self.signature_threshold = 3  # Минимальное количество повторений сигнатуры для алерта
        self.scan_threshold = 5       # Минимальное количество портов для детекта сканирования
        
        # Ключевые слова для черных списков
        self.blacklist_keywords = ['DROP', 'CINS', 'COMPROMISED', 'Dshield', 'BLOCK', 'MALWARE']
        
        self.logger.info(
            f"Suricata Pandas анализатор инициализирован:\n"
            f"  Порог сигнатур: {self.signature_threshold}\n"
            f"  Порог сканирования: {self.scan_threshold}"
        )
    
    def _events_to_dataframe(self, events: List[SuricataEvent]) -> pd.DataFrame:
        """
        Преобразует список событий Suricata в Pandas DataFrame.
        
        Args:
            events: Список событий Suricata
            
        Returns:
            DataFrame с колонками: timestamp, src_ip, dest_ip, dest_port, 
            signature, severity, category, event_type, proto
        """
        data = []
        
        for event in events:
            if not isinstance(event, SuricataEvent):
                continue
                
            # Извлекаем данные из raw_data
            raw = event.raw_data if hasattr(event, 'raw_data') and event.raw_data else {}
            alert_data = raw.get('alert', {}) if isinstance(raw, dict) else {}
            
            # Получаем signature из разных мест
            signature = None
            if event.alert_signature:
                signature = event.alert_signature
            elif isinstance(alert_data, dict):
                signature = alert_data.get('signature', 'unknown')
            
            # Получаем severity
            severity = None
            if event.alert_severity:
                severity = event.alert_severity
            elif isinstance(alert_data, dict):
                severity = alert_data.get('severity', 3)
            
            row = {
                'timestamp': event.timestamp if event.timestamp else datetime.now(),
                'src_ip': event.src_ip if event.src_ip else 'unknown',
                'dest_ip': event.dest_ip if event.dest_ip else 'unknown',
                'dest_port': raw.get('dest_port') if isinstance(raw, dict) else None,
                'signature': signature or 'unknown',
                'severity': severity or 3,
                'category': alert_data.get('category', 'unknown') if isinstance(alert_data, dict) else 'unknown',
                'event_type': event.event_type or 'unknown',
                'proto': raw.get('proto', 'unknown') if isinstance(raw, dict) else 'unknown'
            }
            data.append(row)
        
        if not data:
            return pd.DataFrame()
        
        df = pd.DataFrame(data)
        
        # Преобразуем timestamp в datetime если он еще не в этом формате
        if 'timestamp' in df.columns and not pd.api.types.is_datetime64_any_dtype(df['timestamp']):
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        self.logger.info(f"Создан DataFrame с {len(df)} строками и {len(df.columns)} колонками")
        return df
    
    def _analyze_port_scans(self, df: pd.DataFrame) -> List[Alert]:
        """
        Анализирует сканирования портов.
        
        Группирует по src_ip и считает уникальные порты.
        
        Args:
            df: DataFrame с событиями
            
        Returns:
            Список алертов
        """
        alerts = []
        
        if df.empty or 'src_ip' not in df.columns or 'dest_port' not in df.columns:
            return alerts
        
        # Удаляем строки без портов
        df_ports = df.dropna(subset=['dest_port'])
        
        if df_ports.empty:
            return alerts
        
        # Группируем по IP и считаем уникальные порты
        port_scans = df_ports.groupby('src_ip')['dest_port'].nunique().reset_index()
        port_scans.columns = ['src_ip', 'port_count']
        
        # Фильтруем те, где много портов
        suspicious_scans = port_scans[port_scans['port_count'] >= self.scan_threshold]
        
        for _, row in suspicious_scans.iterrows():
            src_ip = row['src_ip']
            port_count = row['port_count']
            
            # Получаем список портов для этого IP
            ports = df_ports[df_ports['src_ip'] == src_ip]['dest_port'].unique()
            
            alert = Alert(
                title="Обнаружено сканирование портов",
                severity="HIGH",
                source=self.name,
                description=f"IP {src_ip} обратился к {port_count} различным портам",
                indicator=src_ip,
                raw_data={
                    'src_ip': src_ip,
                    'port_count': int(port_count),
                    'ports': ports.tolist(),
                    'analysis_type': 'port_scan'
                }
            )
            alerts.append(alert)
            self.logger.info(f"Сканирование портов: {src_ip} -> {port_count} портов")
        
        return alerts
    
    def _analyze_blacklisted_ips(self, df: pd.DataFrame) -> List[Alert]:
        """
        Анализирует IP из черных списков на основе сигнатур.
        
        Args:
            df: DataFrame с событиями
            
        Returns:
            Список алертов
        """
        alerts = []
        
        if df.empty or 'signature' not in df.columns or 'src_ip' not in df.columns:
            return alerts
        
        # Создаем маску для черных списков
        blacklist_mask = df['signature'].str.contains('|'.join(self.blacklist_keywords), case=False, na=False)
        blacklisted_events = df[blacklist_mask]
        
        if blacklisted_events.empty:
            return alerts
        
        # Группируем по IP
        blacklisted_ips = blacklisted_events.groupby('src_ip').agg({
            'signature': lambda x: list(x.unique()),
            'timestamp': 'count'
        }).reset_index()
        blacklisted_ips.columns = ['src_ip', 'signatures', 'count']
        
        for _, row in blacklisted_ips.iterrows():
            src_ip = row['src_ip']
            signatures = row['signatures']
            count = row['count']
            
            alert = Alert(
                title="IP из черного списка",
                severity="CRITICAL",
                source=self.name,
                description=f"IP {src_ip} обнаружен в {count} событиях с сигнатурами из черных списков",
                indicator=src_ip,
                raw_data={
                    'src_ip': src_ip,
                    'signatures': signatures[:3],  # Первые 3 для краткости
                    'total_count': int(count),
                    'analysis_type': 'blacklisted'
                }
            )
            alerts.append(alert)
            self.logger.info(f"Черный список: {src_ip} - {count} событий")
        
        return alerts
    
    def _generate_statistics(self, df: pd.DataFrame) -> dict:
        """
        Генерирует статистику по данным.
        
        Args:
            df: DataFrame с событиями
            
        Returns:
            Словарь со статистикой
        """
        stats = {}
        
        if df.empty:
            return stats
        
        stats['total_events'] = len(df)
        
        if 'src_ip' in df.columns:
            stats['unique_src_ips'] = int(df['src_ip'].nunique())
        
        if 'dest_ip' in df.columns:
            stats['unique_dest_ips'] = int(df['dest_ip'].nunique())
        
        if 'signature' in df.columns:
            stats['unique_signatures'] = int(df['signature'].nunique())
            # Топ-5 сигнатур
            top_sigs = df['signature'].value_counts().head(5).to_dict()
            stats['top_signatures'] = {str(k): int(v) for k, v in top_sigs.items()}
        
        if 'severity' in df.columns:
            severity_counts = df['severity'].value_counts().to_dict()
            stats['severity_distribution'] = {f"severity_{k}": int(v) for k, v in severity_counts.items()}
        
        if 'timestamp' in df.columns:
            # Безопасное получение временного диапазона
            ts_series = df['timestamp'].dropna()
            if not ts_series.empty:
                min_ts = ts_series.min()
                max_ts = ts_series.max()
                stats['time_min'] = min_ts.isoformat() if pd.notna(min_ts) else None
                stats['time_max'] = max_ts.isoformat() if pd.notna(max_ts) else None
        
        return stats
    
    def analyze(self, events: List[Any]) -> List[Alert]:
        """
        Анализирует события Suricata с использованием Pandas.
        
        Args:
            events: Список событий
            
        Returns:
            Список алертов (без дедупликации)
        """
        self.logger.info(f"Начало Pandas-анализа, получено событий: {len(events)}")
        
        # Фильтруем только SuricataEvent
        suricata_events = [e for e in events if isinstance(e, SuricataEvent)]
        self.logger.info(f"Suricata событий: {len(suricata_events)}")
        
        if not suricata_events:
            self.logger.warning("Нет событий Suricata для анализа")
            return []
        
        # Создаем DataFrame
        df = self._events_to_dataframe(suricata_events)
        
        if df.empty:
            self.logger.warning("DataFrame пуст после преобразования")
            return []
        
        # Генерируем статистику
        stats = self._generate_statistics(df)
        self.logger.info(f"Статистика: {stats}")
        
        alerts = []
        
        # Применяем различные методы анализа
        alerts.extend(self._analyze_port_scans(df))
        alerts.extend(self._analyze_blacklisted_ips(df))
        
        self.logger.info(f"Анализ завершен: всего создано алертов: {len(alerts)}")
        
        return alerts


def create_analyzer() -> SuricataPandasAnalyzer:
    """Создает экземпляр Pandas анализатора."""
    return SuricataPandasAnalyzer()
