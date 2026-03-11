"""
Анализатор сетевого трафика для выявления аномалий.
Специализируется на DNS-трафике: поиск частых запросов, подозрительных доменов.
"""
from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import math

import pandas as pd
import numpy as np

from analyzers.base import BaseAnalyzer
from models.event import SuricataEvent, RawEvent
from models.alert import Alert
from config import Config
from utils.logger import logger


class TrafficAnalyzer(BaseAnalyzer):
    """
    Анализатор сетевого трафика для выявления подозрительной активности.
    
    Основные методы детекта:
    1. Аномально высокая частота DNS-запросов к одному домену (DGA, C2)
    2. Подозрительные DNS-имена (случайные символы, длинные поддомены)
    3. Статистические выбросы (Z-score)
    
    Использует pandas для агрегации и анализа.
    """
    
    def __init__(self):
        """Инициализация анализатора трафика."""
        super().__init__("traffic_analyzer")
        
        # Пороговые значения из конфига
        self.dns_threshold = Config.get_dns_threshold()
        
        # Дополнительные настройки
        self.time_window_minutes = 5  # Окно анализа
        self.entropy_threshold = 4.0  # Порог энтропии для случайных доменов
        self.zscore_threshold = 3.0   # Порок для статистических выбросов
        
        self.logger.info(
            f"Traffic анализатор инициализирован:\n"
            f"  DNS порог: {self.dns_threshold}\n"
            f"  Окно анализа: {self.time_window_minutes} мин\n"
            f"  Порог энтропии: {self.entropy_threshold}"
        )
    
    def _filter_dns_events(self, events: List[RawEvent]) -> List[SuricataEvent]:
        """
        Фильтрует только DNS события из общего списка.
        
        Args:
            events: Список сырых событий
        
        Returns:
            Список DNS событий (SuricataEvent с заполненным dns_query)
        """
        dns_events = []
        
        for event in events:
            # Проверяем, что это событие Suricata
            if not isinstance(event, SuricataEvent):
                continue
            
            # Проверяем тип и наличие DNS-запроса
            if event.event_type == 'dns' and event.dns_query:
                dns_events.append(event)
        
        self.logger.debug(f"Отфильтровано DNS событий: {len(dns_events)} из {len(events)}")
        return dns_events
    
    def _calculate_entropy(self, domain: str) -> float:
        """
        Вычисляет энтропию Шеннона для доменного имени.
        Высокая энтропия указывает на случайную генерацию (DGA).
        
        Args:
            domain: Доменное имя
        
        Returns:
            Значение энтропии (0 - полностью детерминировано, 8+ - случайно)
        """
        # Берем только поддомен (первую часть) для анализа
        subdomain = domain.split('.')[0]
        
        if len(subdomain) < 6:
            return 0.0  # Короткие имена не анализируем
        
        # Подсчет частоты символов
        freq = {}
        for char in subdomain.lower():
            freq[char] = freq.get(char, 0) + 1
        
        # Вычисление энтропии по формуле Шеннона
        entropy = 0.0
        length = len(subdomain)
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    def _detect_high_frequency_dns(self, dns_events: List[SuricataEvent]) -> List[Alert]:
        """
        Детектит аномально высокую частоту DNS-запросов.
        Использует pandas для группировки и агрегации.
        
        Args:
            dns_events: Список DNS-событий
        
        Returns:
            Список алертов
        """
        alerts = []
        
        if not dns_events:
            return alerts
        
        # Преобразуем в pandas DataFrame для анализа
        data = []
        for event in dns_events:
            data.append({
                'timestamp': event.timestamp,
                'domain': event.dns_query,
                'src_ip': event.src_ip or 'unknown',
                'query_type': event.dns_type or 'A'
            })
        
        df = pd.DataFrame(data)
        
        if df.empty:
            return alerts
        
        # Добавляем временное окно
        df['time_window'] = df['timestamp'].dt.floor(f'{self.time_window_minutes}min')
        
        # Группируем по окну и домену
        domain_stats = df.groupby(['time_window', 'domain']).agg({
            'src_ip': 'nunique',  # Уникальные источники
            'timestamp': 'count'   # Количество запросов
        }).rename(columns={'timestamp': 'query_count', 'src_ip': 'unique_sources'})
        
        # Сбрасываем индекс для удобной фильтрации
        domain_stats = domain_stats.reset_index()
        
        # Фильтруем по порогу
        suspicious = domain_stats[domain_stats['query_count'] >= self.dns_threshold]
        
        self.logger.debug(f"Найдено подозрительных доменов (частота): {len(suspicious)}")
        
        # Создаем алерты
        for _, row in suspicious.iterrows():
            alert = Alert(
                title="Высокая частота DNS-запросов",
                severity="MEDIUM" if row['query_count'] < self.dns_threshold * 2 else "HIGH",
                source=self.name,
                description=(
                    f"Домен {row['domain']} получил {row['query_count']} запросов "
                    f"за {self.time_window_minutes} минут от {row['unique_sources']} уникальных источников"
                ),
                indicator=row['domain'],
                raw_data={
                    'domain': row['domain'],
                    'query_count': int(row['query_count']),
                    'unique_sources': int(row['unique_sources']),
                    'time_window': str(row['time_window'])
                }
            )
            
            # Дополнительный анализ энтропии
            entropy = self._calculate_entropy(row['domain'])
            if entropy > self.entropy_threshold:
                alert.title = "Высокочастотный DNS с подозрительной структурой"
                alert.severity = "HIGH"
                alert.description += f" (высокая энтропия: {entropy:.2f})"
                alert.raw_data['entropy'] = round(entropy, 2)
            
            alerts.append(alert)
        
        return alerts
    
    def _detect_entropy_anomalies(self, dns_events: List[SuricataEvent]) -> List[Alert]:
        """
        Детектит домены с высокой энтропией (вероятно DGA) даже при низкой частоте.
        
        Args:
            dns_events: Список DNS-событий
        
        Returns:
            Список алертов
        """
        alerts = []
        
        # Собираем уникальные домены с их частотой
        domain_counter = Counter()
        domain_samples = {}
        
        for event in dns_events:
            if event.dns_query:
                domain_counter[event.dns_query] += 1
                if event.dns_query not in domain_samples:
                    domain_samples[event.dns_query] = event
        
        # Анализируем каждый домен
        for domain, count in domain_counter.items():
            # Пропускаем уже обнаруженные по частоте
            if count >= self.dns_threshold:
                continue
            
            # Проверяем энтропию
            entropy = self._calculate_entropy(domain)
            
            if entropy > self.entropy_threshold:
                # Находим пример события для этого домена
                sample_event = domain_samples.get(domain)
                
                alert = Alert(
                    title="Подозрительная структура домена (возможно DGA)",
                    severity="MEDIUM",
                    source=self.name,
                    description=(
                        f"Домен {domain} имеет высокую энтропию ({entropy:.2f}), "
                        f"что характерно для алгоритмов генерации доменов (DGA)"
                    ),
                    indicator=domain,
                    raw_data={
                        'domain': domain,
                        'entropy': round(entropy, 2),
                        'query_count': count,
                        'example_src': sample_event.src_ip if sample_event else None
                    }
                )
                alerts.append(alert)
        
        self.logger.debug(f"Найдено подозрительных доменов (энтропия): {len(alerts)}")
        return alerts
    
    def _detect_statistical_outliers(self, dns_events: List[SuricataEvent]) -> List[Alert]:
        """
        Детектит статистические выбросы используя Z-score.
        Находит домены, чья частота значительно выше среднего.
        
        Args:
            dns_events: Список DNS-событий
        
        Returns:
            Список алертов
        """
        alerts = []
        
        if len(dns_events) < 10:  # Нужна минимальная статистика
            return alerts
        
        # Считаем частоту по доменам
        domain_counts = Counter()
        for event in dns_events:
            if event.dns_query:
                domain_counts[event.dns_query] += 1
        
        if len(domain_counts) < 5:
            return alerts
        
        # Преобразуем в массив для статистики
        counts = np.array(list(domain_counts.values()))
        
        # Вычисляем среднее и стандартное отклонение
        mean = np.mean(counts)
        std = np.std(counts)
        
        if std == 0:  # Избегаем деления на ноль
            return alerts
        
        # Находим выбросы
        for domain, count in domain_counts.items():
            zscore = (count - mean) / std
            
            if zscore > self.zscore_threshold:
                # Проверяем, не попал ли уже в другие детекторы
                if count < self.dns_threshold:
                    alert = Alert(
                        title="Статистическая аномалия DNS-трафика",
                        severity="LOW",
                        source=self.name,
                        description=(
                            f"Домен {domain} имеет частоту {count} "
                            f"(Z-score: {zscore:.2f}), что выше среднего"
                        ),
                        indicator=domain,
                        raw_data={
                            'domain': domain,
                            'query_count': count,
                            'zscore': round(zscore, 2),
                            'mean': round(mean, 2),
                            'std': round(std, 2)
                        }
                    )
                    alerts.append(alert)
        
        self.logger.debug(f"Найдено статистических выбросов: {len(alerts)}")
        return alerts
    
    def analyze(self, events: List[RawEvent]) -> List[Alert]:
        """
        Основной метод анализа трафика.
        Применяет все методы детекта и объединяет результаты.
        
        Args:
            events: Список сырых событий (ожидаются SuricataEvent)
        
        Returns:
            Список обнаруженных алертов
        """
        self.logger.info(f"Начало анализа трафика, получено событий: {len(events)}")
        
        # Фильтруем DNS-события
        dns_events = self._filter_dns_events(events)
        
        if not dns_events:
            self.logger.info("DNS события не найдены, анализ пропущен")
            return []
        
        self.logger.info(f"Найдено DNS событий для анализа: {len(dns_events)}")
        
        # Применяем различные методы детекта
        alerts = []
        
        # 1. Детект высокой частоты
        frequency_alerts = self._detect_high_frequency_dns(dns_events)
        alerts.extend(frequency_alerts)
        self.logger.info(f"Обнаружено частотных аномалий: {len(frequency_alerts)}")
        
        # 2. Детект энтропии
        entropy_alerts = self._detect_entropy_anomalies(dns_events)
        alerts.extend(entropy_alerts)
        self.logger.info(f"Обнаружено энтропийных аномалий: {len(entropy_alerts)}")
        
        # 3. Детект статистических выбросов
        outlier_alerts = self._detect_statistical_outliers(dns_events)
        alerts.extend(outlier_alerts)
        self.logger.info(f"Обнаружено статистических выбросов: {len(outlier_alerts)}")
        
        # Дедупликация алертов по домену (оставляем самый критичный)
        unique_alerts = self._deduplicate_alerts(alerts)
        
        self.logger.info(
            f"Анализ завершен:\n"
            f"  Всего алертов: {len(alerts)}\n"
            f"  Уникальных: {len(unique_alerts)}"
        )
        
        return unique_alerts
    
    def _deduplicate_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """
        Дедуплицирует алерты по домену, оставляя самый критичный.
        
        Args:
            alerts: Список алертов
        
        Returns:
            Список уникальных алертов
        """
        if not alerts:
            return alerts
        
        # Группируем по домену
        domain_alerts = defaultdict(list)
        for alert in alerts:
            domain_alerts[alert.indicator].append(alert)
        
        # Для каждого домена оставляем алерт с наивысшим severity
        unique = []
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        
        for domain, domain_alert_list in domain_alerts.items():
            best_alert = max(
                domain_alert_list,
                key=lambda a: severity_order.get(a.severity, 0)
            )
            unique.append(best_alert)
        
        return unique


# Функция-фабрика для создания анализатора
def create_analyzer() -> TrafficAnalyzer:
    """
    Создает и возвращает экземпляр анализатора трафика.
    
    Returns:
        Настроенный анализатор
    """
    return TrafficAnalyzer()


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Тестирование анализатора на синтетических данных.
    
    Генерирует тестовый набор DNS-запросов с аномалиями:
    - Высокочастотный домен (c2-malware.com)
    - DGA-подобный домен (gq8w7fhs9d.net)
    - Нормальный трафик
    """
    import sys
    from datetime import datetime, timedelta
    import random
    import string
    
    # Настраиваем логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)  # DEBUG
    
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ АНАЛИЗАТОРА ТРАФИКА")
    print("=" * 60)
    
    # Создаем тестовые данные
    def generate_random_domain(length=10):
        """Генерирует случайное доменное имя (для имитации DGA)."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + '.net'
    
    # Создаем список событий
    test_events = []
    base_time = datetime.now() - timedelta(minutes=10)
    
    # 1. Нормальный трафик (Google, Cloudflare)
    for i in range(50):
        event = SuricataEvent(
            source='suricata',
            raw_data={},
            event_type='dns',
            dns_query='google.com',
            src_ip='192.168.1.100',
            timestamp=base_time + timedelta(seconds=i*10)
        )
        test_events.append(event)
    
    for i in range(30):
        event = SuricataEvent(
            source='suricata',
            raw_data={},
            event_type='dns',
            dns_query='cloudflare.com',
            src_ip='192.168.1.101',
            timestamp=base_time + timedelta(seconds=i*15)
        )
        test_events.append(event)
    
    # 2. Высокочастотный подозрительный домен (C2)
    for i in range(100):  # Превышает порог (50)
        event = SuricataEvent(
            source='suricata',
            raw_data={},
            event_type='dns',
            dns_query='c2-malware.com',
            src_ip='192.168.1.200',
            timestamp=base_time + timedelta(seconds=i*2)  # Очень часто
        )
        test_events.append(event)
    
    # 3. DGA-подобный домен (высокая энтропия)
    dga_domain = generate_random_domain(15)
    for i in range(20):  # Ниже порога частоты
        event = SuricataEvent(
            source='suricata',
            raw_data={},
            event_type='dns',
            dns_query=dga_domain,
            src_ip='192.168.1.150',
            timestamp=base_time + timedelta(minutes=i)
        )
        test_events.append(event)
    
    # Перемешиваем события для реалистичности
    random.shuffle(test_events)
    
    print(f"\nСгенерировано тестовых событий: {len(test_events)}")
    print(f"  - google.com: 50 запросов")
    print(f"  - cloudflare.com: 30 запросов")
    print(f"  - c2-malware.com: 100 запросов (аномалия)")
    print(f"  - {dga_domain}: 20 запросов (DGA)")
    
    # Запускаем анализатор
    analyzer = TrafficAnalyzer()
    alerts = analyzer.analyze(test_events)
    
    print(f"\n{'='*60}")
    print(f"РЕЗУЛЬТАТЫ АНАЛИЗА")
    print(f"{'='*60}")
    
    if alerts:
        print(f"\nОбнаружено алертов: {len(alerts)}")
        for i, alert in enumerate(alerts, 1):
            print(f"\n--- Алерт #{i} ---")
            print(f"  Название: {alert.title}")
            print(f"  Критичность: {alert.severity}")
            print(f"  Индикатор: {alert.indicator}")
            print(f"  Описание: {alert.description}")
    else:
        print("\nАлертов не обнаружено")
    
    # Дополнительная статистика
    print(f"\n{'='*60}")
    print("СТАТИСТИКА АНАЛИЗА")
    dns_events = [e for e in test_events if isinstance(e, SuricataEvent) and e.dns_query]
    print(f"  Всего DNS событий: {len(dns_events)}")
    
    # Уникальные домены
    unique_domains = set(e.dns_query for e in dns_events if e.dns_query)
    print(f"  Уникальных доменов: {len(unique_domains)}")
    
    # Частота по доменам
    from collections import Counter
    domain_counts = Counter(e.dns_query for e in dns_events if e.dns_query)
    print("\n  Топ доменов по частоте:")
    for domain, count in domain_counts.most_common():
        print(f"    {domain}: {count}")
