"""
Модуль для имитации реагирования через вывод в консоль.
Соответствует требованию ТЗ о простом реагировании (блокировка или уведомление).
"""
from typing import List
from datetime import datetime

from responders.base import BaseResponder
from models.alert import Alert
from utils.logger import logger


class ConsoleLogger(BaseResponder):
    """
    Имитатор реагирования на угрозы через консоль.
    
    Выводит цветные сообщения о блокировке или уведомлении.
    Реальное взаимодействие с системами блокировки не требуется.
    """
    
    # ANSI цветовые коды для красивого вывода
    COLORS = {
        'CRITICAL': '\033[91m',  # Красный
        'HIGH': '\033[91m',       # Красный (яркий)
        'MEDIUM': '\033[93m',     # Желтый
        'LOW': '\033[94m',        # Синий
        'INFO': '\033[92m',       # Зеленый
        'RESET': '\033[0m'        # Сброс цвета
    }
    
    def __init__(self, simulate_blocking: bool = True):
        """
        Инициализация консольного логгера.
        
        Args:
            simulate_blocking: Если True, имитирует блокировку,
                              если False - только уведомление
        """
        super().__init__("console_logger")
        self.simulate_blocking = simulate_blocking
        
        self.logger.info(
            f"Консольный логгер инициализирован:\n"
            f"  Режим: {'БЛОКИРОВКА' if simulate_blocking else 'УВЕДОМЛЕНИЕ'}"
        )
    
    def _colorize(self, text: str, color: str) -> str:
        """
        Добавляет ANSI цвет к тексту.
        
        Args:
            text: Текст для раскрашивания
            color: Ключ цвета из COLORS
        
        Returns:
            Текст с ANSI кодами
        """
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['RESET']}"
    
    def _print_separator(self, char: str = "=", length: int = 60) -> None:
        """Печатает разделитель."""
        print(char * length)
    
    def _print_alert_header(self, alert: Alert) -> None:
        """
        Печатает заголовок алерта с цветом.
        
        Args:
            alert: Алерт для отображения
        """
        color = self.COLORS.get(alert.severity, '')
        
        print()
        self._print_separator()
        print(f"{color}[{alert.severity}]{self.COLORS['RESET']} {alert.title}")
        self._print_separator("-")
    
    def _print_alert_details(self, alert: Alert) -> None:
        """
        Печатает детали алерта.
        
        Args:
            alert: Алерт для отображения
        """
        print(f"  {self._colorize('Время:', 'INFO')} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {self._colorize('Источник:', 'INFO')} {alert.source}")
        print(f"  {self._colorize('Индикатор:', 'INFO')} {alert.indicator}")
        print(f"  {self._colorize('Описание:', 'INFO')}")
        print(f"    {alert.description}")
    
    def _print_action(self, alert: Alert) -> None:
        """
        Печатает информацию о предпринятом действии.
        
        Args:
            alert: Алерт для обработки
        """
        if self.simulate_blocking:
            action = "БЛОКИРОВКА"
            color = "CRITICAL"
            message = f"Имитация блокировки индикатора: {alert.indicator}"
        else:
            action = "УВЕДОМЛЕНИЕ"
            color = "MEDIUM"
            message = f"Обнаружена угроза, требуется ручная проверка: {alert.indicator}"
        
        print()
        print(f"  {self._colorize('ДЕЙСТВИЕ:', color)} {action}")
        print(f"  {self._colorize('Статус:', 'INFO')} {message}")
        
        # Сохраняем информацию в алерт
        alert.action_taken = action.lower()
        alert.action_details = message
    
    def _print_raw_data(self, alert: Alert) -> None:
        """
        Печатает сырые данные, если они есть.
        
        Args:
            alert: Алерт для отображения
        """
        if alert.raw_data:
            print()
            print(f"  {self._colorize('Дополнительные данные:', 'INFO')}")
            for key, value in alert.raw_data.items():
                if isinstance(value, (int, float, str)):
                    print(f"    {key}: {value}")
    
    def respond(self, alerts: List[Alert]) -> None:
        """
        Реагирует на список алертов через консоль.
        
        Args:
            alerts: Список обнаруженных угроз
        """
        if not alerts:
            self.logger.info("Нет алертов для реагирования")
            print(self._colorize("\n✅ Угроз не обнаружено. Система чиста.", "INFO"))
            return
        
        self.logger.info(f"Начало реагирования на {len(alerts)} алертов")
        
        print()
        self._print_separator("=")
        print(self._colorize("🔴 ОБНАРУЖЕНЫ УГРОЗЫ", "CRITICAL"))
        self._print_separator("=")
        print(f"Всего обнаружено: {len(alerts)}")
        
        # Сортируем по критичности
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(
            alerts,
            key=lambda a: severity_order.get(a.severity, 999)
        )
        
        # Обрабатываем каждый алерт
        for i, alert in enumerate(sorted_alerts, 1):
            self._print_alert_header(alert)
            self._print_alert_details(alert)
            self._print_raw_data(alert)
            self._print_action(alert)
            
            if i < len(sorted_alerts):
                print("\n" + self._colorize("---", "INFO"))
        
        # Итог
        print()
        self._print_separator("=")
        print(self._colorize("📋 ИТОГ ОБРАБОТКИ", "INFO"))
        self._print_separator("-")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = sum(1 for a in alerts if a.severity == severity)
            if count > 0:
                color = severity if severity in self.COLORS else 'INFO'
                print(f"  {self._colorize(f'{severity}:', color)} {count}")
        
        print()
        self.logger.info("Реагирование завершено")


# Функция-фабрика
def create_responder(simulate_blocking: bool = True) -> ConsoleLogger:
    """
    Создает экземпляр консольного логгера.
    
    Args:
        simulate_blocking: Режим блокировки или уведомления
    
    Returns:
        Настроенный responder
    """
    return ConsoleLogger(simulate_blocking=simulate_blocking)


# Блок тестирования
if __name__ == "__main__":
    from datetime import datetime
    
    # Настраиваем логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)
    
    # Создаем тестовые алерты
    test_alerts = [
        Alert(
            title="Критическая уязвимость в nginx",
            severity="CRITICAL",
            source="cvss_analyzer",
            description="Remote Code Execution в nginx 1.18.0 (CVE-2024-1234)",
            indicator="CVE-2024-1234",
            timestamp=datetime.now(),
            raw_data={'cvss': 9.8, 'affected': 'nginx 1.18.0'}
        ),
        Alert(
            title="Подозрительный DNS трафик",
            severity="HIGH",
            source="traffic_analyzer",
            description="Аномально высокая частота запросов к c2-malware.com",
            indicator="c2-malware.com",
            timestamp=datetime.now(),
            raw_data={'query_count': 150, 'unique_sources': 5}
        ),
        Alert(
            title="IP в черных списках",
            severity="MEDIUM",
            source="virustotal",
            description="IP обнаружен в 3 черных списках",
            indicator="185.130.5.133",
            timestamp=datetime.now(),
            raw_data={'malicious': 3, 'suspicious': 2}
        )
    ]
    
    # Тест с режимом блокировки
    print("\n" + "=" * 60)
    print("ТЕСТ: РЕЖИМ БЛОКИРОВКИ")
    print("=" * 60)
    
    responder_block = ConsoleLogger(simulate_blocking=True)
    responder_block.respond(test_alerts)
    
    # Тест с режимом уведомления
    print("\n" + "=" * 60)
    print("ТЕСТ: РЕЖИМ УВЕДОМЛЕНИЯ")
    print("=" * 60)
    
    responder_notify = ConsoleLogger(simulate_blocking=False)
    responder_notify.respond(test_alerts)
    
    # Тест с пустым списком
    print("\n" + "=" * 60)
    print("ТЕСТ: НЕТ УГРОЗ")
    print("=" * 60)
    
    responder_block.respond([])
