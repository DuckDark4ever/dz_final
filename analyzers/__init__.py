"""
Пакет для анализа данных и выявления угроз.
"""
from analyzers.base import BaseAnalyzer
from analyzers.cvss_analyzer import CVSSAnalyzer
from analyzers.traffic_analyzer import TrafficAnalyzer

__all__ = [
    'BaseAnalyzer',
    'CVSSAnalyzer',
    'TrafficAnalyzer',
    'SuricataPandasAnalyzer'
]
