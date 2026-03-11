"""
Конфигурация приложения.
Все секреты загружаются из переменных окружения (.env файла).
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Загружаем переменные из .env файла, если он существует
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)


class Config:
    """
    Класс-синглтон для доступа к конфигурации.
    Все методы статические для простоты использования.
    """
    
    @staticmethod
    def get_virustotal_api_key() -> Optional[str]:
        """Возвращает API ключ VirusTotal или None."""
        return os.getenv('VIRUSTOTAL_API_KEY')
    
    @staticmethod
    def get_vulners_api_key() -> Optional[str]:
        """Возвращает API ключ Vulners (опционально) или None."""
        return os.getenv('VULNERS_API_KEY')
    
    @staticmethod
    def get_telegram_token() -> Optional[str]:
        """Возвращает токен Telegram бота."""
        return os.getenv('TELEGRAM_BOT_TOKEN')
    
    @staticmethod
    def get_telegram_chat_id() -> Optional[str]:
        """Возвращает ID чата для уведомлений."""
        return os.getenv('TELEGRAM_CHAT_ID')
    
    @staticmethod
    def get_max_file_size_mb() -> int:
        """Максимальный размер файла для загрузки в МБ."""
        return int(os.getenv('MAX_FILE_SIZE_MB', '10'))
    
    @staticmethod
    def get_cvss_threshold() -> float:
        """Порог CVSS для критических уязвимостей."""
        return float(os.getenv('CVSS_THRESHOLD', '7.0'))
    
    @staticmethod
    def get_dns_threshold() -> int:
        """Порог DNS запросов для детекта аномалий."""
        return int(os.getenv('DNS_QUERY_THRESHOLD', '50'))
    
    @staticmethod
    def is_development() -> bool:
        """Проверка режима разработки."""
        return os.getenv('ENVIRONMENT', 'production').lower() == 'development'
