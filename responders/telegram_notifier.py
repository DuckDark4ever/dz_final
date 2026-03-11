"""
Модуль для отправки уведомлений об угрозах через Telegram Bot API.
Поддерживает форматирование Markdown/HTML, повторные попытки при ошибках
и защиту от rate limiting.
"""
import time
from typing import List, Optional, Dict, Any
from datetime import datetime
import requests

from responders.base import BaseResponder
from models.alert import Alert
from config import Config
from utils.logger import logger


class TelegramNotifierError(Exception):
    """Базовое исключение для ошибок Telegram уведомлений."""
    pass


class TelegramAuthError(TelegramNotifierError):
    """Ошибка аутентификации (неверный токен)."""
    pass


class TelegramRateLimitError(TelegramNotifierError):
    """Превышение лимита отправки сообщений."""
    pass


class TelegramNotifier(BaseResponder):
    """
    Отправляет уведомления об угрозах в Telegram.
    
    Особенности:
    - Форматирование Markdown/HTML для красивого отображения
    - Экранирование специальных символов Markdown (безопасность)
    - Повторные попытки при временных ошибках
    - Защита от rate limiting (30 сообщений/сек)
    - Эмодзи для визуальной индикации критичности
    """
    
    # Константы для настройки поведения
    RATE_LIMIT_BUFFER = 25  # сообщений/сек (оставляем запас от лимита 30)
    MAX_SEND_RETRIES = 3     # максимальное количество попыток отправки
    RETRY_BASE_DELAY = 2      # базовая задержка для экспоненциальной retry (сек)
    SEND_TIMEOUT = 15         # таймаут HTTP запроса (сек)
    
    # Эмодзи для разных уровней критичности
    SEVERITY_EMOJIS = {
        'CRITICAL': '🔴',  # Красный круг
        'HIGH': '🟠',       # Оранжевый круг
        'MEDIUM': '🟡',     # Желтый круг
        'LOW': '🔵'         # Синий круг
    }
    
    # Символы, требующие экранирования в Markdown v2
    MARKDOWN_ESCAPE_CHARS = r'_*[]()~`>#+-=|{}.!'
    
    def __init__(self, dry_run: bool = False):
        """
        Инициализация Telegram уведомителя.
        
        Args:
            dry_run: Если True, сообщения выводятся в лог, но не отправляются
            
        Raises:
            TelegramAuthError: Если токен не настроен и не dry_run режим
        """
        super().__init__("telegram")
        
        self.dry_run = dry_run
        self.token = Config.get_telegram_token()
        self.chat_id = Config.get_telegram_chat_id()
        
        # Проверяем конфигурацию
        self._check_configuration()
        
        # Статистика для rate limiting
        self.message_count = 0
        self.last_reset_time = time.time()
        
        self.session = self._create_session()
        
        self.logger.info(
            f"Telegram уведомитель инициализирован:\n"
            f"  Режим: {'DRY RUN' if dry_run else 'LIVE'}\n"
            f"  Chat ID: {self.chat_id if self.chat_id else 'не указан'}\n"
            f"  Токен: {'установлен' if self.token else 'ОТСУТСТВУЕТ'}"
        )
    
    def _check_configuration(self) -> None:
        """
        Проверяет наличие необходимых настроек.
        
        Raises:
            TelegramAuthError: В live-режиме без токена
        """
        if self.dry_run:
            self.logger.info("Dry-run режим: пропускаем проверку токена")
            return
        
        if not self.token:
            error_msg = "TELEGRAM_BOT_TOKEN не найден в .env файле"
            self.logger.error(error_msg)
            raise TelegramAuthError(error_msg)
        
        if not self.chat_id:
            error_msg = "TELEGRAM_CHAT_ID не найден в .env файле"
            self.logger.error(error_msg)
            raise TelegramAuthError(error_msg)
    
    def _create_session(self) -> requests.Session:
        """
        Создает настроенную сессию requests.
        
        Returns:
            Сессия с базовыми заголовками
        """
        session = requests.Session()
        session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'ThreatDetector/1.0'
        })
        return session
    
    def _escape_markdown(self, text: str) -> str:
        """
        Экранирует специальные символы Markdown v2 для безопасного отображения.
        
        Telegram Markdown v2 требует экранирования следующих символов:
        _ * [ ] ( ) ~ ` > # + - = | { } . !
        
        Args:
            text: Исходный текст (может содержать спецсимволы)
        
        Returns:
            Текст с экранированными символами
        """
        result = []
        for char in text:
            if char in self.MARKDOWN_ESCAPE_CHARS:
                result.append('\\' + char)
            else:
                result.append(char)
        return ''.join(result)
    
    def _format_alert_message(self, alert: Alert) -> str:
        """
        Форматирует алерт в красивое сообщение для Telegram.
        Использует Markdown с экранированием спецсимволов.
        
        Args:
            alert: Алерт для форматирования
        
        Returns:
            Отформатированное сообщение в Markdown
        """
        emoji = self.SEVERITY_EMOJIS.get(alert.severity, '⚪')
        
        # Экранируем все пользовательские данные
        safe_title = self._escape_markdown(alert.title)
        safe_indicator = self._escape_markdown(alert.indicator)
        safe_description = self._escape_markdown(alert.description)
        safe_source = self._escape_markdown(alert.source)
        
        # Заголовок с эмодзи и уровнем критичности
        message = [
            f"{emoji} *{safe_title}*",
            f"`{alert.severity}`",
            "",
            f"*Источник:* {safe_source}",
            f"*Время:* {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"*Индикатор:* `{safe_indicator}`",
            "",
            f"*Описание:*",
            f"{safe_description}"
        ]
        
        # Добавляем дополнительную информацию, если есть
        if alert.raw_data:
            message.append("")
            message.append("*Детали:*")
            
            # Форматируем сырые данные красиво
            for key, value in alert.raw_data.items():
                if key in ['domain', 'query_count', 'unique_sources', 'entropy', 
                          'cvss', 'malicious', 'suspicious']:
                    key_pretty = key.replace('_', ' ').title()
                    safe_key = self._escape_markdown(key_pretty)
                    
                    if isinstance(value, float):
                        message.append(f"  • {safe_key}: `{value:.2f}`")
                    else:
                        safe_value = self._escape_markdown(str(value))
                        message.append(f"  • {safe_key}: `{safe_value}`")
        
        # Добавляем информацию о действии, если есть
        if alert.action_taken:
            safe_action = self._escape_markdown(alert.action_taken)
            message.append("")
            message.append(f"*Действие:* {safe_action}")
            if alert.action_details:
                safe_details = self._escape_markdown(alert.action_details)
                message.append(f"`{safe_details}`")
        
        return "\n".join(message)
    
    def _check_rate_limit(self) -> None:
        """
        Проверяет и соблюдает rate limiting Telegram Bot API.
        Сбрасывает счетчик каждую секунду.
        """
        current_time = time.time()
        
        # Сбрасываем счетчик каждую секунду
        if current_time - self.last_reset_time >= 1.0:
            self.message_count = 0
            self.last_reset_time = current_time
        
        # Проверяем превышение лимита
        if self.message_count >= self.RATE_LIMIT_BUFFER:
            sleep_time = 1.0 - (current_time - self.last_reset_time)
            if sleep_time > 0:
                self.logger.warning(
                    f"Rate limit достигнут, ожидание {sleep_time:.2f}с"
                )
                time.sleep(sleep_time)
                self.message_count = 0
                self.last_reset_time = time.time()
    
    def _send_with_retry(self, message: str) -> bool:
        """
        Отправляет сообщение с повторными попытками при ошибках.
        
        Args:
            message: Текст сообщения в Markdown
        
        Returns:
            True если отправка успешна, False если все попытки исчерпаны
        """
        if self.dry_run:
            self.logger.info(f"[DRY RUN] Сообщение для отправки:\n{message}")
            return True
        
        # Исправлено: f-string для формирования URL без пробелов
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        
        payload = {
            'chat_id': self.chat_id,
            'text': message,
            'parse_mode': 'MarkdownV2',  # Используем MarkdownV2 (более строгий)
            'disable_web_page_preview': True
        }
        
        for attempt in range(self.MAX_SEND_RETRIES):
            try:
                # Проверяем rate limit
                self._check_rate_limit()
                
                response = self.session.post(url, json=payload, timeout=self.SEND_TIMEOUT)
                
                # Увеличиваем счетчик сообщений
                self.message_count += 1
                
                # Обработка специфических ошибок
                if response.status_code == 429:
                    retry_after = response.json().get('parameters', {}).get('retry_after', 5)
                    self.logger.warning(f"Rate limit от Telegram, пауза {retry_after}с")
                    time.sleep(retry_after)
                    continue
                
                if response.status_code == 401:
                    self.logger.error("Неверный токен Telegram бота")
                    raise TelegramAuthError("Invalid token")
                
                # Проверка на ошибки форматирования Markdown
                if response.status_code == 400:
                    error_data = response.json()
                    if 'can\'t parse entities' in error_data.get('description', ''):
                        self.logger.error(
                            f"Ошибка парсинга Markdown. "
                            f"Проблемное сообщение (первые 200 символов): {message[:200]}"
                        )
                        # Пробуем отправить без форматирования как fallback
                        payload['parse_mode'] = None
                        self.logger.info("Повторная отправка без Markdown форматирования")
                        continue
                
                response.raise_for_status()
                
                # Проверяем успешность по содержимому ответа
                result = response.json()
                if result.get('ok'):
                    self.logger.debug(f"Сообщение отправлено успешно (попытка {attempt + 1})")
                    return True
                else:
                    self.logger.error(f"Telegram API вернул ошибку: {result}")
                    
            except requests.exceptions.Timeout:
                self.logger.warning(
                    f"Таймаут при отправке (попытка {attempt + 1}/{self.MAX_SEND_RETRIES})"
                )
            except requests.exceptions.ConnectionError:
                self.logger.warning(
                    f"Ошибка соединения (попытка {attempt + 1}/{self.MAX_SEND_RETRIES})"
                )
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"HTTP ошибка: {e}")
                if attempt == self.MAX_SEND_RETRIES - 1:
                    return False
            except Exception as e:
                self.logger.error(f"Неожиданная ошибка: {e}")
                if attempt == self.MAX_SEND_RETRIES - 1:
                    return False
            
            # Экспоненциальная задержка между попытками
            if attempt < self.MAX_SEND_RETRIES - 1:
                sleep_time = (attempt + 1) * self.RETRY_BASE_DELAY
                self.logger.info(f"Повторная попытка через {sleep_time}с")
                time.sleep(sleep_time)
        
        self.logger.error(f"Не удалось отправить сообщение после {self.MAX_SEND_RETRIES} попыток")
        return False
    
    def send_test_message(self) -> bool:
        """
        Отправляет тестовое сообщение для проверки конфигурации.
        
        Returns:
            True если тест успешен
        """
        test_alert = Alert(
            title="Тестовое уведомление",
            severity="LOW",
            source="telegram_notifier",
            description="Это тестовое сообщение для проверки работы Telegram бота.",
            indicator="test_indicator_123",
            raw_data={
                'test_field': 'значение с *звездочкой* и _подчеркиванием_',
                'test_number': 123.45
            }
        )
        
        self.logger.info("Отправка тестового сообщения...")
        message = self._format_alert_message(test_alert)
        success = self._send_with_retry(message)
        
        if success:
            self.logger.info("Тестовое сообщение отправлено успешно")
        else:
            self.logger.error("Ошибка отправки тестового сообщения")
        
        return success
    
    def respond(self, alerts: List[Alert]) -> None:
        """
        Отправляет уведомления о всех алертах.
        
        Args:
            alerts: Список обнаруженных угроз
        """
        if not alerts:
            self.logger.info("Нет алертов для отправки")
            return
        
        self.logger.info(f"Начало отправки {len(alerts)} уведомлений")
        
        successful = 0
        failed = 0
        
        # Сортируем по критичности для отправки сначала важные
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_alerts = sorted(
            alerts,
            key=lambda a: severity_order.get(a.severity, 999)
        )
        
        for i, alert in enumerate(sorted_alerts, 1):
            self.logger.debug(f"Отправка {i}/{len(alerts)}: {alert.title}")
            
            # Форматируем и отправляем
            message = self._format_alert_message(alert)
            success = self._send_with_retry(message)
            
            if success:
                successful += 1
                # Отмечаем в алерте, что уведомление отправлено
                alert.action_taken = "telegram_notified"
                alert.action_details = f"Уведомление отправлено в Telegram (chat_id: {self.chat_id})"
            else:
                failed += 1
                alert.action_taken = "telegram_failed"
                alert.action_details = "Не удалось отправить уведомление в Telegram"
        
        # Итоговая статистика
        self.logger.info(
            f"Отправка уведомлений завершена:\n"
            f"  Всего: {len(alerts)}\n"
            f"  Успешно: {successful}\n"
            f"  Ошибок: {failed}"
        )
        
        # Если были ошибки и это не dry-run, логируем предупреждение
        if failed > 0 and not self.dry_run:
            self.logger.warning(
                f"Не удалось отправить {failed} уведомлений. "
                f"Проверьте конфигурацию Telegram бота."
            )


# Функция-фабрика для создания уведомителя
def create_responder(dry_run: bool = False) -> TelegramNotifier:
    """
    Создает и возвращает экземпляр Telegram уведомителя.
    
    Args:
        dry_run: Если True, сообщения не отправляются реально
    
    Returns:
        Настроенный уведомитель
    
    Raises:
        TelegramAuthError: Если токен отсутствует и не dry-run режим
    """
    return TelegramNotifier(dry_run=dry_run)


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Тестирование Telegram уведомителя.
    
    Режимы:
        python -m responders.telegram_notifier --test     # Тест с реальной отправкой
        python -m responders.telegram_notifier --dry-run  # Тест без отправки
        python -m responders.telegram_notifier --help     # Справка
    """
    import sys
    import argparse
    
    # Настраиваем логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)  # DEBUG
    
    parser = argparse.ArgumentParser(description="Тестирование Telegram уведомителя")
    parser.add_argument('--test', action='store_true', help='Отправить тестовое сообщение')
    parser.add_argument('--dry-run', action='store_true', help='Режим без реальной отправки')
    parser.add_argument('--message', type=str, help='Свой текст сообщения (опционально)')
    
    args = parser.parse_args()
    
    if not args.test and not args.dry_run:
        parser.print_help()
        sys.exit(0)
    
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ TELEGRAM УВЕДОМИТЕЛЯ")
    print("=" * 60)
    
    try:
        # Создаем уведомитель
        notifier = TelegramNotifier(dry_run=args.dry_run)
        
        if args.test:
            print(f"\nРежим: {'DRY-RUN' if args.dry_run else 'LIVE'}")
            
            if args.message:
                # Отправка пользовательского сообщения
                print(f"\nОтправка пользовательского сообщения...")
                custom_alert = Alert(
                    title="Пользовательское сообщение",
                    severity="LOW",
                    source="manual",
                    description=args.message,
                    indicator="manual_input"
                )
                notifier.respond([custom_alert])
            else:
                # Отправка тестового сообщения
                print(f"\nОтправка тестового сообщения...")
                success = notifier.send_test_message()
                
                if success:
                    print("\n✅ Тест успешен! Сообщение отправлено.")
                else:
                    print("\n❌ Ошибка отправки тестового сообщения.")
            
            # Демонстрация разных уровней критичности
            print(f"\n{'='*60}")
            print("ДЕМОНСТРАЦИЯ ФОРМАТИРОВАНИЯ")
            print(f"{'='*60}")
            
            test_alerts = [
                Alert(
                    title="Критическая уязвимость с *звездочкой*",
                    severity="CRITICAL",
                    source="vulners",
                    description="Найдена уязвимость с CVSS 9.8 в nginx 1.18.0 [CVE-2024-1234]",
                    indicator="CVE-2024-1234",
                    raw_data={'cvss': 9.8, 'affected': 'nginx 1.18.0'}
                ),
                Alert(
                    title="Подозрительный DNS трафик (c2-malware.com)",
                    severity="HIGH",
                    source="traffic_analyzer",
                    description="Аномально высокая частота запросов к c2-malware.com",
                    indicator="c2-malware.com",
                    raw_data={'query_count': 150, 'unique_sources': 5}
                ),
                Alert(
                    title="Потенциально опасный IP (185.130.5.133)",
                    severity="MEDIUM",
                    source="virustotal",
                    description="IP обнаружен в 3 черных списках",
                    indicator="185.130.5.133",
                    raw_data={'malicious': 3, 'suspicious': 2}
                ),
                Alert(
                    title="Информационное сообщение [OK]",
                    severity="LOW",
                    source="system",
                    description="Плановое сканирование завершено (успешно)",
                    indicator="system_scan_123"
                )
            ]
            
            if not args.dry_run:
                print("\nОтправка демонстрационных алертов...")
                notifier.respond(test_alerts)
            else:
                print("\nДемонстрационные алерты (dry-run):")
                for alert in test_alerts:
                    print(f"\n--- {alert.severity} ---")
                    print(notifier._format_alert_message(alert))
        
    except TelegramAuthError as e:
        print(f"\n❌ Ошибка аутентификации: {e}")
        print("\nДля тестирования необходимо настроить:")
        print("  TELEGRAM_BOT_TOKEN=your_token")
        print("  TELEGRAM_CHAT_ID=your_chat_id")
        print("\nПолучите токен у @BotFather и chat_id у @userinfobot")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Неожиданная ошибка: {e}")
        sys.exit(1)
