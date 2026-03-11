"""
Базовый класс для всех коллекторов данных.
Определяет интерфейс, который должны реализовать все коллекторы.
"""
from abc import ABC, abstractmethod
from typing import List, Optional, Any
from models.event import RawEvent
from utils.logger import logger


class BaseCollector(ABC):
    """
    Абстрактный базовый класс для сбора данных из различных источников.
    Каждый наследник должен реализовать метод collect().
    """
    
    def __init__(self, name: str):
        """
        Args:
            name: Имя коллектора (для логирования)
        """
        self.name = name
        self.logger = logger.getChild(f"collector.{name}")
    
    @abstractmethod
    def collect(self, *args, **kwargs) -> List[RawEvent]:
        """
        Основной метод сбора данных.
        
        Returns:
            Список сырых событий RawEvent
        """
        pass
    
    def validate_data(self, data: Any) -> bool:
        """
        Базовая валидация входных данных.
        Может быть переопределена в наследниках.
        """
        return data is not None
