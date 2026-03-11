"""
Модели для сырых событий из различных источников.
Используем dataclasses для автоматического создания __init__ и repr.
"""
from dataclasses import dataclass, field
from typing import Optional, Any, Dict
from datetime import datetime


@dataclass
class RawEvent:
    """
    Базовый класс для всех сырых событий.
    Содержит только самые общие поля.
    """
    source: str  # 'virustotal', 'vulners', 'suricata'
    raw_data: Dict[str, Any]  # Исходный JSON ответа
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SuricataEvent(RawEvent):
    """Специализированное событие для Suricata с типизированными полями."""
    event_type: str = ""  # alert, dns, http, etc.
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    alert_severity: Optional[int] = None
    alert_signature: Optional[str] = None
    dns_query: Optional[str] = None
    dns_type: Optional[str] = None


@dataclass
class VulnerabilityEvent(RawEvent):
    """Событие уязвимости из Vulners."""
    vuln_id: str = ""
    title: str = ""
    cvss_score: float = 0.0
    description: str = ""
    affected_software: str = ""


@dataclass
class ThreatIntelEvent(RawEvent):
    """Событие из VirusTotal."""
    indicator: str = ""  # IP, domain, hash
    indicator_type: str = ""  # 'ip', 'domain', 'file'
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    undetected_count: int = 0
