"""
Настройка логирования для всего приложения.
Обеспечивает разделение на файловый и консольный вывод с разными уровнями.
"""
import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str = "threat_detector",
    log_file: Optional[str] = "app.log",
    console_level: int = logging.INFO,
    file_level: int = logging.DEBUG
) -> logging.Logger:
    """
    Настраивает логгер с выводом в консоль и файл.
    
    Args:
        name: Имя логгера
        log_file: Путь к файлу лога (None если не нужен)
        console_level: Уровень для консоли (INFO по умолчанию)
        file_level: Уровень для файла (DEBUG по умолчанию)
    
    Returns:
        Настроенный экземпляр логгера
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)  # Самый низкий уровень, фильтруют обработчики
    
    # Предотвращаем дублирование при повторных вызовах
    if logger.handlers:
        return logger
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    
    # Консольный handler (только от INFO и выше)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Файловый handler (все уровни)
    if log_file:
        # Создаем директорию для логов, если её нет
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(file_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# Создаем глобальный экземпляр логгера для использования во всем приложении
logger = setup_logger()
