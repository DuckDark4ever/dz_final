"""
Анализатор для выявления критических уязвимостей на основе CVSS.
Фильтрует события от Vulners коллектора по пороговому значению.
"""
from typing import List

from analyzers.base import BaseAnalyzer
from models.event import VulnerabilityEvent, RawEvent
from models.alert import Alert
from config import Config
from utils.logger import logger


class CVSSAnalyzer(BaseAnalyzer):
    """
    Анализатор CVSS баллов уязвимостей.
    
    Создает алерты для уязвимостей с CVSS >= порогового значения.
    """
    
    # Маппинг CVSS в уровень критичности
    SEVERITY_MAP = [
        (9.0, 10.0, 'CRITICAL'),
        (7.0, 8.9, 'HIGH'),
        (4.0, 6.9, 'MEDIUM'),
        (0.1, 3.9, 'LOW')
    ]
    
    def __init__(self):
        """Инициализация CVSS анализатора."""
        super().__init__("cvss_analyzer")
        self.threshold = Config.get_cvss_threshold()
        
        self.logger.info(
            f"CVSS анализатор инициализирован:\n"
            f"  Порог: {self.threshold}"
        )
    
    def _get_severity_from_cvss(self, cvss: float) -> str:
        """
        Определяет уровень критичности по CVSS баллу.
        
        Args:
            cvss: CVSS балл
        
        Returns:
            Уровень критичности (LOW, MEDIUM, HIGH, CRITICAL)
        """
        for min_score, max_score, severity in self.SEVERITY_MAP:
            if min_score <= cvss <= max_score:
                return severity
        return 'UNKNOWN'
    
    def analyze(self, events: List[RawEvent]) -> List[Alert]:
        """
        Анализирует события уязвимостей и создает алерты.
        
        Args:
            events: Список сырых событий
        
        Returns:
            Список алертов для критических уязвимостей
        """
        self.logger.info(f"Начало анализа CVSS, получено событий: {len(events)}")
        
        alerts = []
        
        for event in events:
            # Проверяем, что это событие уязвимости
            if not isinstance(event, VulnerabilityEvent):
                continue
            
            # Проверяем порог CVSS
            if event.cvss_score < self.threshold:
                self.logger.debug(
                    f"Уязвимость {event.vuln_id} ниже порога: "
                    f"{event.cvss_score} < {self.threshold}"
                )
                continue
            
            # Определяем критичность
            severity = self._get_severity_from_cvss(event.cvss_score)
            
            # Создаем алерт
            alert = Alert(
                title=f"Уязвимость: {event.vuln_id}",
                severity=severity,
                source=self.name,
                description=(
                    f"{event.title}\n"
                    f"CVSS: {event.cvss_score}\n"
                    f"Затронутое ПО: {event.affected_software}"
                ),
                indicator=event.vuln_id,
                raw_data={
                    'vuln_id': event.vuln_id,
                    'cvss': event.cvss_score,
                    'affected_software': event.affected_software,
                    'description': event.description[:200]  # Обрезаем для краткости
                }
            )
            
            alerts.append(alert)
            self.logger.info(
                f"Обнаружена уязвимость: {event.vuln_id} "
                f"(CVSS: {event.cvss_score}, {severity})"
            )
        
        self.logger.info(f"Анализ завершен, создано алертов: {len(alerts)}")
        return alerts


# Функция-фабрика
def create_analyzer() -> CVSSAnalyzer:
    """Создает экземпляр CVSS анализатора."""
    return CVSSAnalyzer()


# Блок тестирования
if __name__ == "__main__":
    from utils.logger import setup_logger
    setup_logger(console_level=10)
    
    # Создаем тестовые события
    test_events = [
        VulnerabilityEvent(
            source='vulners',
            raw_data={},
            vuln_id='CVE-2024-1234',
            title='Critical RCE in nginx',
            cvss_score=9.8,
            description='Remote code execution...',
            affected_software='nginx 1.18.0'
        ),
        VulnerabilityEvent(
            source='vulners',
            raw_data={},
            vuln_id='CVE-2024-5678',
            title='XSS vulnerability',
            cvss_score=5.5,
            description='Cross-site scripting...',
            affected_software='apache 2.4.49'
        )
    ]
    
    analyzer = CVSSAnalyzer()
    alerts = analyzer.analyze(test_events)
    
    print(f"\nРезультаты анализа:")
    print(f"Создано алертов: {len(alerts)}")
    
    for alert in alerts:
        print(f"\n--- {alert.indicator} ---")
        print(f"Severity: {alert.severity}")
        print(f"Description: {alert.description[:100]}...")
