"""
Пакет для сбора данных из различных источников.
"""
from collectors.base import BaseCollector
from collectors.suricata_log import SuricataLogCollector
from collectors.virustotal import VirusTotalCollector
from collectors.vulners import VulnersCollector

__all__ = [
    'BaseCollector',
    'SuricataLogCollector',
    'VirusTotalCollector',
    'VulnersCollector'
]
