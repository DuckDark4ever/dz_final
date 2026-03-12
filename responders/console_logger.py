"""
Модуль для имитации реагирования через вывод в консоль.
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
        Реагирует на список алертов через консоль с дедупликацией по IP.
        
        Args:
            alerts: Список обнаруженных угроз
        """
        if not alerts:
            self.logger.info("Нет алертов для реагирования")
            print(self._colorize("\n✅ Угроз не обнаружено. Система чиста.", "INFO"))
            return
        
        # Дедупликация по IP
        self.logger.info(f"Начало дедупликации алертов, получено: {len(alerts)}")
        
        # Группируем по IP
        ip_alerts = {}
        
        for alert in alerts:
            # Пытаемся получить IP из разных источников
            src_ip = None
            if alert.raw_data and isinstance(alert.raw_data, dict):
                src_ip = alert.raw_data.get('src_ip')
            
            if not src_ip and alert.indicator:
                indicator = alert.indicator
                if indicator.count('.') == 3 and all(part.isdigit() for part in indicator.split('.')):
                    src_ip = indicator
            
            if not src_ip:
                src_ip = "unknown"
            
            if src_ip not in ip_alerts:
                ip_alerts[src_ip] = []
            ip_alerts[src_ip].append(alert)
        
        # Веса для severity
        severity_weight = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        
        # Для каждого IP выбираем самый критичный алерт
        deduplicated = []
        ip_stats = {}
        
        for src_ip, alerts_list in ip_alerts.items():
            if not alerts_list:
                continue
            
            # Выбираем алерт с наивысшим весом severity
            best_alert = max(alerts_list, 
                           key=lambda a: severity_weight.get(a.severity, 0))
            
            # Сохраняем статистику для логирования
            ip_stats[src_ip] = {
                'total': len(alerts_list),
                'best_severity': best_alert.severity,
                'severities': list(set(a.severity for a in alerts_list))
            }
            
            # Добавляем информацию о количестве в raw_data
            if best_alert.raw_data is None:
                best_alert.raw_data = {}
            best_alert.raw_data['total_alerts_for_ip'] = len(alerts_list)
            best_alert.raw_data['unique_severities'] = list(set(a.severity for a in alerts_list))
            
            deduplicated.append(best_alert)
        
        self.logger.info(f"Дедупликация завершена: {len(alerts)} -> {len(deduplicated)} алертов")
        
        # Логируем статистику по IP
        self.logger.info("Статистика по IP после дедупликации:")
        for src_ip, stats in list(ip_stats.items())[:10]:  # Первые 10 для лога
            self.logger.info(f"  {src_ip}: {stats['total']} алертов, лучший: {stats['best_severity']}")
        
        # Реагирование на дедуплицированные алерты
        self.logger.info(f"Начало реагирования на {len(deduplicated)} алертов")
        
        print()
        self._print_separator("=")
        print(self._colorize("🔴 ОБНАРУЖЕНЫ УГРОЗЫ", "CRITICAL"))
        self._print_separator("=")
        print(f"Всего обнаружено: {len(deduplicated)} (из {len(alerts)} исходных)")
        
        # Сортируем по критичности
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(
            deduplicated,
            key=lambda a: severity_order.get(a.severity, 999)
        )
        
        # Обрабатываем каждый алерт
        for i, alert in enumerate(sorted_alerts, 1):
            # Добавляем информацию о дубликатах в описание
            total_for_ip = alert.raw_data.get('total_alerts_for_ip', 1)
            unique_sevs = alert.raw_data.get('unique_severities', [alert.severity])
            
            self._print_alert_header(alert)
            self._print_alert_details(alert)
            
            # Дополнительная информация о дубликатах
            if total_for_ip > 1:
                print(f"  {self._colorize('📊 Статистика:', 'INFO')} всего {total_for_ip} алертов от этого IP")
                print(f"     Уровни критичности: {', '.join(unique_sevs)}")
            
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
            count = sum(1 for a in deduplicated if a.severity == severity)
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
