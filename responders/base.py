"""
Базовый класс для всех обработчиков реагирования.
Выполняет действия при обнаружении угроз.
"""
from abc import ABC, abstractmethod
from typing import List
from models.alert import Alert
from utils.logger import logger


class BaseResponder(ABC):
    """
    Базовый класс для модулей реагирования.
    Получает список алертов и выполняет действия.
    """
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logger.getChild(f"responder.{name}")
    
    @abstractmethod
    def respond(self, alerts: List[Alert]) -> None:
        """
        Реагирует на список алертов.
        
        Args:
            alerts: Список обнаруженных угроз
        """
        pass
