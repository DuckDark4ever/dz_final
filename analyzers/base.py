"""
Базовый класс для всех анализаторов.
Преобразует сырые события в алерты.
"""
from abc import ABC, abstractmethod
from typing import List
from models.event import RawEvent
from models.alert import Alert
from utils.logger import logger


class BaseAnalyzer(ABC):
    """
    Абстрактный базовый класс для анализа данных.
    Принимает список RawEvent, возвращает список Alert.
    """
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logger.getChild(f"analyzer.{name}")
    
    @abstractmethod
    def analyze(self, events: List[RawEvent]) -> List[Alert]:
        """
        Анализирует список событий и возвращает найденные угрозы.
        
        Args:
            events: Список сырых событий для анализа
            
        Returns:
            Список алертов
        """
        pass
