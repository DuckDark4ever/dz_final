"""
Модель для сработавших угроз (алертов).
Именно эти объекты будут передаваться в responders.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, Dict


@dataclass
class Alert:
    """
    Алерт о найденной угрозе.
    Содержит всю информацию, необходимую для реагирования и отчетов.
    """
    title: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    source: str  # Какой анализатор сработал
    description: str
    indicator: str  # IP, домен, ID уязвимости
    raw_data: Optional[Dict[str, Any]] = None  # Ссылка на исходные данные
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Поля для имитации блокировки/реагирования
    action_taken: str = ""  # 'blocked', 'notified', 'none'
    action_details: str = ""
