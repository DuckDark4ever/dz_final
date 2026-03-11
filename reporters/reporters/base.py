"""
Базовый класс для всех модулей отчётности.
Определяет интерфейс, который должны реализовать все репортеры.
"""
from abc import ABC, abstractmethod
from typing import List, Any
from utils.logger import logger


class BaseReporter(ABC):
    """
    Абстрактный базовый класс для модулей формирования отчётов.
    """
    
    def __init__(self, name: str):
        """
        Args:
            name: Имя репортера (для логирования)
        """
        self.name = name
        self.logger = logger.getChild(f"reporter.{name}")
    
    @abstractmethod
    def generate(self, *args, **kwargs) -> Any:
        """
        Основной метод генерации отчёта.
        
        Реализация зависит от конкретного типа отчёта.
        """
        pass
