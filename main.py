#!/usr/bin/env python3
"""
Главный оркестратор Threat Detector.
Координирует работу всех модулей: сбор -> анализ -> реагирование -> отчет.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional

from models.alert import Alert
from models.event import RawEvent

from utils.logger import logger, setup_logger
from config import Config


class ThreatDetector:
    """
    Основной класс приложения.
    Управляет жизненным циклом обработки угроз.
    """
    
    def __init__(self):
        self.logger = logger.getChild("core")
        self.collectors = []
        self.analyzers = []
        self.responders = []
        self.reporters = []
        
        self.logger.info("Threat Detector инициализирован")
        self.logger.info(f"Режим работы: {'DEVELOPMENT' if Config.is_development() else 'PRODUCTION'}")
    
    def register_components(self):
        """
        Регистрирует все компоненты системы.
        Пока заглушка - будет заполняться по мере реализации модулей.
        """
        self.logger.debug("Регистрация компонентов...")
        # TODO: Инициализация реальных коллекторов, анализаторов и т.д.
        pass
    
    def run(self, targets: Optional[List[str]] = None):
        """
        Запускает полный цикл обработки.
        
        Args:
            targets: Список целей для анализа (IP, файлы, и т.д.)
        """
        self.logger.info("=" * 50)
        self.logger.info("Запуск цикла обнаружения угроз")
        self.logger.info("=" * 50)
        
        if targets:
            self.logger.info(f"Цели для анализа: {', '.join(targets)}")
        
        # Шаг 1: Сбор данных
        self.logger.info("Этап 1: Сбор данных")
        raw_events = self._collect_data(targets)
        self.logger.info(f"Собрано событий: {len(raw_events)}")
        
        if not raw_events:
            self.logger.warning("Нет данных для анализа. Завершение работы.")
            return
        
        # Шаг 2: Анализ данных
        self.logger.info("Этап 2: Анализ данных")
        alerts = self._analyze_data(raw_events)
        self.logger.info(f"Обнаружено угроз: {len(alerts)}")
        
        if not alerts:
            self.logger.info("Угроз не обнаружено. Формирование отчета.")
        
        # Шаг 3: Реагирование
        self.logger.info("Этап 3: Реагирование")
        self._respond_to_alerts(alerts)
        
        # Шаг 4: Отчетность
        self.logger.info("Этап 4: Формирование отчетов")
        self._generate_reports(raw_events, alerts)
        
        self.logger.info("=" * 50)
        self.logger.info("Цикл обработки завершен")
        self.logger.info("=" * 50)
    
    def _collect_data(self, targets: Optional[List[str]] = None) -> List[RawEvent]:
        """
        Внутренний метод сбора данных.
        TODO: Заменить на реальные вызовы коллекторов.
        """
        events = []
        # Пока заглушка для демонстрации
        self.logger.debug("Сбор данных (заглушка)")
        return events
    
    def _analyze_data(self, events: List[RawEvent]) -> List[Alert]:
        """
        Внутренний метод анализа данных.
        TODO: Заменить на реальные вызовы анализаторов.
        """
        alerts = []
        self.logger.debug("Анализ данных (заглушка)")
        return alerts
    
    def _respond_to_alerts(self, alerts: List[Alert]) -> None:
        """
        Внутренний метод реагирования.
        TODO: Заменить на реальные вызовы responders.
        """
        self.logger.debug("Реагирование (заглушка)")
    
    def _generate_reports(self, events: List[RawEvent], alerts: List[Alert]) -> None:
        """
        Внутренний метод формирования отчетов.
        TODO: Заменить на реальные вызовы reporters.
        """
        self.logger.debug("Формирование отчетов (заглушка)")


def parse_arguments():
    """
    Парсинг аргументов командной строки.
    """
    parser = argparse.ArgumentParser(
        description="Threat Detector - инструмент для обнаружения угроз",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --check-ip 8.8.8.8 1.1.1.1
  %(prog)s --suricata-log /var/log/suricata/eve.json
  %(prog)s --vuln-nginx 1.18.0
        """
    )
    
    # Группа для источников данных
    source_group = parser.add_argument_group('Источники данных')
    source_group.add_argument(
        '--suricata-log', 
        type=str, 
        help='Путь к логу Suricata (eve.json)'
    )
    source_group.add_argument(
        '--check-ip', 
        nargs='+', 
        help='Список IP адресов для проверки через VirusTotal'
    )
    source_group.add_argument(
        '--check-domain', 
        nargs='+', 
        help='Список доменов для проверки через VirusTotal'
    )
    source_group.add_argument(
        '--vuln-software', 
        type=str, 
        help='Поиск уязвимостей для софта (например "nginx 1.18.0")'
    )
    
    # Группа для настроек
    config_group = parser.add_argument_group('Настройки')
    config_group.add_argument(
        '--verbose', '-v', 
        action='store_true', 
        help='Подробный вывод (DEBUG уровень)'
    )
    config_group.add_argument(
        '--no-telegram', 
        action='store_true', 
        help='Отключить отправку уведомлений в Telegram'
    )
    
    # Группа для выходных данных
    output_group = parser.add_argument_group('Выходные данные')
    output_group.add_argument(
        '--output-dir', 
        type=str, 
        default='./reports',
        help='Директория для сохранения отчетов'
    )
    
    return parser.parse_args()


def main():
    """
    Точка входа в приложение.
    """
    args = parse_arguments()
    
    # Настройка логирования в зависимости от verbose режима
    if args.verbose:
        setup_logger(console_level=10)  # DEBUG
        logger.debug("Включен режим отладки")
    
    # Создаем директорию для отчетов
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Отчеты будут сохранены в: {output_dir.absolute()}")
    
    # Проверка наличия API ключей (только предупреждение)
    if not Config.get_virustotal_api_key():
        logger.warning("VIRUSTOTAL_API_KEY не найден. Проверка IP/доменов может не работать.")
    
    # Инициализация и запуск детектора
    detector = ThreatDetector()
    
    # Формируем список целей из аргументов
    targets = []
    if args.check_ip:
        targets.extend([f"ip:{ip}" for ip in args.check_ip])
    if args.check_domain:
        targets.extend([f"domain:{domain}" for domain in args.check_domain])
    if args.vuln_software:
        targets.append(f"software:{args.vuln_software}")
    if args.suricata_log:
        targets.append(f"suricata:{args.suricata_log}")
    
    # Запуск
    try:
        detector.run(targets if targets else None)
    except KeyboardInterrupt:
        logger.info("Получен сигнал прерывания. Завершение работы.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
