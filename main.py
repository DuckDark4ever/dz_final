#!/usr/bin/env python3
"""
Главный оркестратор Threat Detector.
Координирует работу всех модулей: сбор -> анализ -> реагирование -> отчет.
"""
import argparse
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable

# Модели
from models.alert import Alert
from models.event import RawEvent

# Утилиты
from utils.logger import logger, setup_logger
from config import Config

# Коллекторы
from collectors.suricata_log import SuricataLogCollector
from collectors.virustotal import VirusTotalCollector, VirusTotalAuthError
from collectors.vulners import VulnersCollector

# Анализаторы
from analyzers.cvss_analyzer import CVSSAnalyzer
from analyzers.traffic_analyzer import TrafficAnalyzer
from analyzers.suricata_pandas import SuricataPandasAnalyzer

# Responders
from responders.console_logger import ConsoleLogger
from responders.telegram_notifier import TelegramNotifier, TelegramAuthError

# Reporters
from reporters.data_exporter import DataExporter
from reporters.chart_generator import ChartGenerator


class ThreatDetector:
    """
    Основной класс приложения.
    Управляет жизненным циклом обработки угроз.
    """
    
    def __init__(self, args: argparse.Namespace):
        """
        Инициализация детектора с параметрами командной строки.
        
        Args:
            args: Распарсенные аргументы командной строки
        """
        self.args = args
        self.logger = logger.getChild("core")
        
        # Контейнеры для компонентов
        self.collectors: Dict[str, Any] = {}  # Именованные экземпляры коллекторов
        self.analyzers: List[Any] = []        # Список анализаторов
        self.responders: List[Any] = []       # Список responders
        self.reporters: List[Any] = []        # Список reporters
        
        # Регистрируем компоненты
        self._register_components()
        
        self.logger.info("=" * 50)
        self.logger.info("Threat Detector инициализирован")
        self.logger.info(f"Режим работы: {'DEVELOPMENT' if Config.is_development() else 'PRODUCTION'}")
        self.logger.info("=" * 50)
    
    def _register_components(self) -> None:
        """
        Регистрирует все компоненты системы с обработкой ошибок.
        Использует единый паттерн: все компоненты хранятся как экземпляры.
        """
        self.logger.info("Регистрация компонентов...")
        
        # === 1. КОЛЛЕКТОРЫ ===
        self.logger.debug("Регистрация коллекторов...")
        
        # Suricata: фабрика (требует путь к файлу при создании)
        # Храним класс, но будем вызывать его с путем при использовании
        self.collectors['suricata'] = SuricataLogCollector
        
        # VirusTotal: проверяем ключ, но не падаем при ошибке
        if Config.get_virustotal_api_key():
            try:
                self.collectors['virustotal'] = VirusTotalCollector()
                self.logger.info("  ✓ VirusTotal коллектор зарегистрирован")
            except VirusTotalAuthError as e:
                self.logger.warning(f"  ✗ VirusTotal: {e}")
            except Exception as e:
                self.logger.warning(f"  ✗ VirusTotal: неожиданная ошибка {e}")
        else:
            self.logger.warning("  ✗ VirusTotal: API ключ не настроен, пропускаем")
        
        # Vulners: публичный доступ работает и без ключа
        try:
            # Параметр use_api_key определяет, пытаться ли использовать ключ из конфига
            self.collectors['vulners'] = VulnersCollector(
                use_api_key=bool(Config.get_vulners_api_key()),
                max_cache_size=500
            )
            key_status = "с ключом" if Config.get_vulners_api_key() else "публичный режим"
            self.logger.info(f"  ✓ Vulners коллектор зарегистрирован ({key_status})")
        except Exception as e:
            self.logger.warning(f"  ✗ Vulners: ошибка инициализации {e}")
        
        self.logger.info(f"  → Коллекторов зарегистрировано: {len(self.collectors)}")
        
        # === 2. АНАЛИЗАТОРЫ ===
        self.logger.debug("Регистрация анализаторов...")
        
        self.analyzers = [
            CVSSAnalyzer(),
            TrafficAnalyzer(),
            SuricataPandasAnalyzer(),
        ]
        
        self.logger.info(f"  → Анализаторов зарегистрировано: {len(self.analyzers)}")
        
        # === 3. RESPONDERS ===
        self.logger.debug("Регистрация responders...")
        
        # ConsoleLogger: всегда доступен
        self.responders.append(
            ConsoleLogger(simulate_blocking=not self.args.no_block)
        )
        self.logger.info("  ✓ ConsoleLogger зарегистрирован")
        
        # TelegramNotifier: только если настроен и не отключен флагом
        if not self.args.no_telegram:
            if Config.get_telegram_token() and Config.get_telegram_chat_id():
                try:
                    # В dry-run режиме не отправляем реальные сообщения
                    dry_run = self.args.dry_run or Config.is_development()
                    self.responders.append(TelegramNotifier(dry_run=dry_run))
                    self.logger.info("  ✓ Telegram notifier зарегистрирован")
                except TelegramAuthError as e:
                    self.logger.warning(f"  ✗ Telegram: {e}")
                except Exception as e:
                    self.logger.warning(f"  ✗ Telegram: ошибка {e}")
            else:
                self.logger.warning("  ✗ Telegram: токен или chat_id не настроены, пропускаем")
        else:
            self.logger.info("  ○ Telegram отключен пользователем (--no-telegram)")
        
        self.logger.info(f"  → Responders зарегистрировано: {len(self.responders)}")
        
        # === 4. REPORTERS ===
        self.logger.debug("Регистрация reporters...")
        
        self.reporters = [
            DataExporter(pretty_json=Config.is_development()),
            ChartGenerator(theme=self.args.theme)
        ]
        
        self.logger.info(f"  → Reporters зарегистрировано: {len(self.reporters)}")
        
        # Итог
        total = (len(self.collectors) + len(self.analyzers) + 
                 len(self.responders) + len(self.reporters))
        self.logger.info(f"Всего зарегистрировано компонентов: {total}")
    
    def _collect_data(self, targets: Optional[List[str]] = None) -> List[RawEvent]:
        """
        Сбор данных из всех источников, указанных в targets.
        
        Args:
            targets: Список целей в формате "тип:значение"
        
        Returns:
            Список сырых событий
        """
        events = []
        
        if not targets:
            self.logger.debug("Нет целей для сбора данных")
            return events
        
        self.logger.info(f"Сбор данных из {len(targets)} источников")
        
        for target in targets:
            try:
                # Разбираем цель
                if ':' not in target:
                    self.logger.warning(f"Некорректный формат цели: {target}, ожидается 'тип:значение'")
                    continue
                
                target_type, target_value = target.split(':', 1)
                
                # === Suricata логи ===
                if target_type == 'suricata':
                    if 'suricata' not in self.collectors:
                        self.logger.warning("Suricata коллектор не зарегистрирован")
                        continue
                    
                    self.logger.info(f"Анализ лога Suricata: {target_value}")
                    
                    # Создаем экземпляр с путем к файлу
                    collector = self.collectors['suricata'](target_value)
                    file_events = collector.collect()
                    events.extend(file_events)
                    self.logger.info(f"  → Получено событий: {len(file_events)}")
                
                # === VirusTotal проверка ===
                elif target_type in ('ip', 'domain'):
                    if 'virustotal' not in self.collectors:
                        self.logger.warning("VirusTotal коллектор недоступен")
                        continue
                    
                    self.logger.info(f"Проверка {target_type}: {target_value}")
                    
                    collector = self.collectors['virustotal']
                    result = collector.check_indicator(target_value)
                    if result:
                        events.append(result)
                        self.logger.info(f"  → Результат: malicious={result.malicious_count}")
                    else:
                        self.logger.warning(f"  → Не удалось проверить {target_value}")
                
                # === Vulners поиск уязвимостей ===
                elif target_type == 'software':
                    if 'vulners' not in self.collectors:
                        self.logger.warning("Vulners коллектор недоступен")
                        continue
                    
                    self.logger.info(f"Поиск уязвимостей для: {target_value}")
                    
                    collector = self.collectors['vulners']
                    vulns = collector.collect([target_value])
                    events.extend(vulns)
                    self.logger.info(f"  → Найдено уязвимостей: {len(vulns)}")
                
                else:
                    self.logger.warning(f"Неизвестный тип цели: {target_type}")
                    
            except Exception as e:
                self.logger.error(f"Ошибка при сборе данных для {target}: {e}", exc_info=self.args.verbose)
        
        self.logger.info(f"Всего собрано событий: {len(events)}")
        return events
    
    def _analyze_data(self, events: List[RawEvent]) -> List[Alert]:
        """
        Анализ данных всеми зарегистрированными анализаторами.
        
        Args:
            events: Список сырых событий
        
        Returns:
            Список алертов
        """
        if not events:
            return []
        
        if not self.analyzers:
            self.logger.warning("Нет зарегистрированных анализаторов")
            return []
        
        self.logger.info(f"Запуск анализаторов ({len(self.analyzers)})...")
        
        all_alerts = []
        
        for analyzer in self.analyzers:
            try:
                analyzer_name = getattr(analyzer, 'name', type(analyzer).__name__)
                self.logger.debug(f"Запуск анализатора: {analyzer_name}")
                
                alerts = analyzer.analyze(events)
                all_alerts.extend(alerts)
                
                self.logger.info(f"  → {analyzer_name}: {len(alerts)} алертов")
                
            except Exception as e:
                self.logger.error(f"Ошибка в анализаторе {analyzer}: {e}", exc_info=self.args.verbose)
        
        self.logger.info(f"Всего обнаружено алертов: {len(all_alerts)}")
        return all_alerts
    
    def _respond_to_alerts(self, alerts: List[Alert]) -> None:
        """
        Реагирование на алерты через все зарегистрированные responders.
        
        Args:
            alerts: Список алертов
        """
        if not alerts:
            self.logger.info("Нет алертов для реагирования")
            return
        
        if not self.responders:
            self.logger.warning("Нет зарегистрированных responders")
            return
        
        self.logger.info(f"Запуск responders ({len(self.responders)})...")
        
        for responder in self.responders:
            try:
                responder_name = getattr(responder, 'name', type(responder).__name__)
                self.logger.debug(f"Запуск responder: {responder_name}")
                
                responder.respond(alerts)
                
            except Exception as e:
                self.logger.error(f"Ошибка в responder {responder}: {e}", exc_info=self.args.verbose)
    
    def _generate_reports(self, events: List[RawEvent], alerts: List[Alert]) -> None:
        """
        Генерация отчетов через все зарегистрированные reporters.
        
        Args:
            events: Список сырых событий
            alerts: Список алертов
        """
        if not self.reporters:
            self.logger.warning("Нет зарегистрированных reporters")
            return
        
        self.logger.info(f"Запуск reporters ({len(self.reporters)})...")
        
        output_dir = self.args.output_dir
        
        for reporter in self.reporters:
            try:
                reporter_name = getattr(reporter, 'name', type(reporter).__name__)
                self.logger.debug(f"Запуск reporter: {reporter_name}")
                
                # Разные reporters имеют разные интерфейсы
                if hasattr(reporter, 'generate') and hasattr(reporter, 'export'):
                    # DataExporter
                    results = reporter.export(alerts, events, output_dir)
                    self.logger.info(f"  → {reporter_name}: {results}")
                elif hasattr(reporter, 'generate'):
                    # ChartGenerator
                    files = reporter.generate(alerts, output_dir)
                    self.logger.info(f"  → {reporter_name}: {len(files)} файлов")
                else:
                    self.logger.warning(f"  → {reporter_name}: неизвестный интерфейс")
                
            except Exception as e:
                self.logger.error(f"Ошибка в reporter {reporter}: {e}", exc_info=self.args.verbose)
    
    def run(self) -> None:
        """
        Запускает полный цикл обработки на основе аргументов командной строки.
        """
        self.logger.info("=" * 50)
        self.logger.info("Запуск цикла обнаружения угроз")
        self.logger.info("=" * 50)
        
        # Формируем список целей из аргументов
        targets = []
        
        if self.args.suricata_log:
            targets.append(f"suricata:{self.args.suricata_log}")
        
        if self.args.check_ip:
            for ip in self.args.check_ip:
                targets.append(f"ip:{ip}")
        
        if self.args.check_domain:
            for domain in self.args.check_domain:
                targets.append(f"domain:{domain}")
        
        if self.args.vuln_software:
            targets.append(f"software:{self.args.vuln_software}")
        
        if not targets:
            self.logger.warning("Не указаны цели для анализа. Используйте --help для справки.")
            return
        
        self.logger.info(f"Цели для анализа: {len(targets)}")
        for target in targets:
            self.logger.info(f"  • {target}")
        
        # Шаг 1: Сбор данных
        self.logger.info("")
        self.logger.info("▶ ЭТАП 1: СБОР ДАННЫХ")
        raw_events = self._collect_data(targets)
        
        if not raw_events:
            self.logger.warning("Нет данных для анализа. Завершение работы.")
            return
        
        # Шаг 2: Анализ данных
        self.logger.info("")
        self.logger.info("▶ ЭТАП 2: АНАЛИЗ ДАННЫХ")
        alerts = self._analyze_data(raw_events)
        
        # Шаг 3: Реагирование
        self.logger.info("")
        self.logger.info("▶ ЭТАП 3: РЕАГИРОВАНИЕ")
        self._respond_to_alerts(alerts)
        
        # Шаг 4: Отчетность
        self.logger.info("")
        self.logger.info("▶ ЭТАП 4: ФОРМИРОВАНИЕ ОТЧЕТОВ")
        self._generate_reports(raw_events, alerts)
        
        self.logger.info("")
        self.logger.info("=" * 50)
        self.logger.info("ЦИКЛ ОБРАБОТКИ ЗАВЕРШЕН")
        self.logger.info("=" * 50)


def parse_arguments():
    """
    Парсинг аргументов командной строки.
    """
    parser = argparse.ArgumentParser(
        description="Threat Detector - инструмент для обнаружения угроз",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --suricata-log /var/log/suricata/eve.json
  %(prog)s --check-ip 8.8.8.8 1.1.1.1 --check-domain google.com
  %(prog)s --vuln-software "nginx 1.18.0" --output-dir ./reports
        """
    )
    
    # Источники данных
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
    
    # Настройки
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
    config_group.add_argument(
        '--no-block', 
        action='store_true', 
        help='Режим только уведомления (без имитации блокировки)'
    )
    config_group.add_argument(
        '--dry-run', 
        action='store_true', 
        help='Тестовый режим (без реальных действий)'
    )
    config_group.add_argument(
        '--theme', 
        choices=['dark', 'light'],
        default='dark',
        help='Тема графиков (dark/light)'
    )
    
    # Выходные данные
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
    
    # Настройка логирования
    log_level = 10 if args.verbose else 20  # DEBUG vs INFO
    setup_logger(console_level=log_level)
    
    # Создаем директорию для отчетов
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Отчеты будут сохранены в: {output_dir.absolute()}")
    
    # Запуск детектора
    try:
        detector = ThreatDetector(args)
        detector.run()
        
    except KeyboardInterrupt:
        logger.info("Получен сигнал прерывания. Завершение работы.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
