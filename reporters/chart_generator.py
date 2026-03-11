"""
Модуль для визуализации результатов анализа угроз.
Создает графики распределения CVSS, топ индикаторов и структуру алертов.
Использует matplotlib и seaborn для профессионального вида.
"""
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import Counter

import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np

from reporters.base import BaseReporter
from models.alert import Alert
from models.event import VulnerabilityEvent, ThreatIntelEvent
from utils.logger import logger


class ChartGenerator(BaseReporter):
    """
    Генератор графиков для визуализации результатов анализа.
    
    Создаемые графики:
    1. Гистограмма распределения CVSS-баллов (из VulnerabilityEvent)
    2. Bar chart топ-5 подозрительных индикаторов (IP/домены)
    3. Pie chart распределения алертов по severity
    
    Особенности:
    - Темная тема для лучшей читаемости в консольных средах
    - Высокое разрешение (300 dpi) для печати/презентаций
    - Автоматическое сохранение в PNG
    - Возврат путей к сгенерированным файлам
    """
    
    # Палитра для разных уровней severity (темная тема)
    SEVERITY_COLORS = {
        'CRITICAL': '#ff4444',  # Ярко-красный
        'HIGH': '#ff8800',       # Оранжевый
        'MEDIUM': '#ffbb33',     # Желтый
        'LOW': '#00C851'         # Зеленый
    }
    
    # Настройки графика по умолчанию
    FIGURE_SIZE = (12, 8)
    DPI = 300
    FONT_SIZE = 10
    TITLE_FONT_SIZE = 14
    
    def __init__(self, theme: str = 'dark'):
        """
        Инициализация генератора графиков.
        
        Args:
            theme: Тема оформления ('dark' или 'light')
        """
        super().__init__("chart_generator")
        self.theme = theme
        
        # Настройка стилей
        self._setup_style()
        
        self.logger.info(
            f"Генератор графиков инициализирован:\n"
            f"  Тема: {theme}\n"
            f"  Размер фигур: {self.FIGURE_SIZE}\n"
            f"  DPI: {self.DPI}"
        )
    
    def _setup_style(self) -> None:
        """Настраивает стили matplotlib/seaborn в зависимости от темы."""
        if self.theme == 'dark':
            # Темная тема для консоли
            plt.style.use('dark_background')
            sns.set_palette("husl")
            self.text_color = '#ffffff'
            self.grid_color = '#333333'
            self.face_color = '#1e1e1e'
        else:
            # Светлая тема (по умолчанию)
            plt.style.use('default')
            sns.set_palette("deep")
            self.text_color = '#000000'
            self.grid_color = '#dddddd'
            self.face_color = '#ffffff'
        
        # Общие настройки для всех графиков
        plt.rcParams['figure.facecolor'] = self.face_color
        plt.rcParams['axes.facecolor'] = self.face_color
        plt.rcParams['axes.edgecolor'] = self.text_color
        plt.rcParams['axes.labelcolor'] = self.text_color
        plt.rcParams['xtick.color'] = self.text_color
        plt.rcParams['ytick.color'] = self.text_color
        plt.rcParams['text.color'] = self.text_color
        plt.rcParams['font.size'] = self.FONT_SIZE
        plt.rcParams['figure.titlesize'] = self.TITLE_FONT_SIZE
    
    def _ensure_output_dir(self, output_dir: str) -> Path:
        """
        Создает директорию для выходных файлов, если её нет.
        
        Args:
            output_dir: Путь к директории
        
        Returns:
            Path объект директории
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        return output_path
    
    def _get_timestamp(self) -> str:
        """Возвращает строку с текущим временем для имен файлов."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _extract_cvss_scores(self, alerts: List[Alert]) -> List[float]:
        """
        Извлекает CVSS баллы из алертов, связанных с уязвимостями.
        
        Args:
            alerts: Список алертов
        
        Returns:
            Список CVSS баллов
        """
        scores = []
        
        for alert in alerts:
            # Проверяем, есть ли raw_data с cvss
            if alert.raw_data and 'cvss' in alert.raw_data:
                scores.append(float(alert.raw_data['cvss']))
            # Также проверяем, если alert пришел из VulnerabilityEvent
            elif alert.source == 'vulners' and alert.raw_data:
                # Может быть вложенная структура
                if isinstance(alert.raw_data, dict):
                    cvss = alert.raw_data.get('cvss_score') or alert.raw_data.get('cvss')
                    if cvss:
                        scores.append(float(cvss))
        
        self.logger.debug(f"Извлечено CVSS баллов: {len(scores)}")
        return scores
    
    def _extract_top_indicators(self, alerts: List[Alert], top_n: int = 5) -> pd.DataFrame:
        """
        Извлекает топ-N индикаторов (IP/домены) по частоте появления.
        
        Args:
            alerts: Список алертов
            top_n: Количество топ индикаторов
        
        Returns:
            DataFrame с колонками indicator и count
        """
        # Считаем частоту индикаторов
        indicator_counter = Counter()
        
        for alert in alerts:
            if alert.indicator and alert.indicator != 'unknown':
                indicator_counter[alert.indicator] += 1
        
        # Берем топ-N
        top_indicators = indicator_counter.most_common(top_n)
        
        if not top_indicators:
            return pd.DataFrame()
        
        df = pd.DataFrame(top_indicators, columns=['indicator', 'count'])
        return df
    
    def _extract_severity_distribution(self, alerts: List[Alert]) -> pd.DataFrame:
        """
        Извлекает распределение алертов по уровням критичности.
        
        Args:
            alerts: Список алертов
        
        Returns:
            DataFrame с колонками severity и count
        """
        severity_counter = Counter()
        
        for alert in alerts:
            severity_counter[alert.severity] += 1
        
        df = pd.DataFrame(
            severity_counter.most_common(),
            columns=['severity', 'count']
        )
        
        return df
    
    def generate_cvss_histogram(self, alerts: List[Alert], output_dir: str) -> Optional[str]:
        """
        Генерирует гистограмму распределения CVSS-баллов.
        
        Args:
            alerts: Список алертов
            output_dir: Директория для сохранения
        
        Returns:
            Путь к сохраненному файлу или None, если нет данных
        """
        scores = self._extract_cvss_scores(alerts)
        
        if not scores:
            self.logger.info("Нет CVSS данных для построения гистограммы")
            return None
        
        output_path = self._ensure_output_dir(output_dir)
        filename = output_path / f"cvss_distribution_{self._get_timestamp()}.png"
        
        try:
            # Создаем фигуру
            fig, ax = plt.subplots(figsize=self.FIGURE_SIZE)
            
            # Строим гистограмму
            n, bins, patches = ax.hist(
                scores,
                bins=10,
                range=(0, 10),
                color='#ff6b6b',
                edgecolor='white',
                alpha=0.7,
                rwidth=0.9
            )
            
            # Добавляем вертикальные линии для порогов
            ax.axvline(x=4.0, color='yellow', linestyle='--', alpha=0.5, label='Medium (4.0)')
            ax.axvline(x=7.0, color='orange', linestyle='--', alpha=0.5, label='High (7.0)')
            ax.axvline(x=9.0, color='red', linestyle='--', alpha=0.5, label='Critical (9.0)')
            
            # Настройки осей
            ax.set_xlabel('CVSS Score', fontsize=12, color=self.text_color)
            ax.set_ylabel('Frequency', fontsize=12, color=self.text_color)
            ax.set_title('Distribution of CVSS Scores', fontsize=self.TITLE_FONT_SIZE, color=self.text_color)
            ax.grid(True, alpha=0.3, color=self.grid_color)
            
            # Добавляем легенду
            ax.legend(loc='upper right', facecolor=self.face_color, edgecolor=self.text_color)
            
            # Добавляем подписи значений на столбцах
            for i, (count, bin_edge) in enumerate(zip(n, bins[:-1])):
                if count > 0:
                    ax.text(
                        bin_edge + 0.4, count, int(count),
                        ha='center', va='bottom', color=self.text_color, fontweight='bold'
                    )
            
            # Статистика
            stats_text = f"Total: {len(scores)} | Mean: {np.mean(scores):.2f} | Max: {np.max(scores):.1f}"
            ax.text(
                0.02, 0.98, stats_text,
                transform=ax.transAxes,
                verticalalignment='top',
                bbox=dict(boxstyle='round', facecolor=self.face_color, alpha=0.8, edgecolor=self.text_color),
                color=self.text_color
            )
            
            plt.tight_layout()
            plt.savefig(filename, dpi=self.DPI, bbox_inches='tight', facecolor=self.face_color)
            plt.close()
            
            self.logger.info(f"CVSS гистограмма сохранена: {filename}")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании CVSS гистограммы: {e}")
            plt.close()
            return None
    
    def generate_top_indicators_chart(self, alerts: List[Alert], output_dir: str) -> Optional[str]:
        """
        Генерирует bar chart топ-5 подозрительных индикаторов.
        
        Args:
            alerts: Список алертов
            output_dir: Директория для сохранения
        
        Returns:
            Путь к сохраненному файлу или None, если нет данных
        """
        df = self._extract_top_indicators(alerts, top_n=5)
        
        if df.empty:
            self.logger.info("Нет данных индикаторов для построения графика")
            return None
        
        output_path = self._ensure_output_dir(output_dir)
        filename = output_path / f"top_indicators_{self._get_timestamp()}.png"
        
        try:
            # Создаем фигуру
            fig, ax = plt.subplots(figsize=self.FIGURE_SIZE)
            
            # Строим горизонтальный bar chart для лучшей читаемости длинных имен
            colors = sns.color_palette("husl", len(df))
            bars = ax.barh(df['indicator'], df['count'], color=colors, alpha=0.8)
            
            # Добавляем подписи значений
            for bar in bars:
                width = bar.get_width()
                ax.text(
                    width + 0.1, bar.get_y() + bar.get_height()/2,
                    f'{int(width)}',
                    ha='left', va='center', color=self.text_color, fontweight='bold'
                )
            
            # Настройки осей
            ax.set_xlabel('Number of Alerts', fontsize=12, color=self.text_color)
            ax.set_ylabel('Indicator', fontsize=12, color=self.text_color)
            ax.set_title('Top 5 Suspicious Indicators', fontsize=self.TITLE_FONT_SIZE, color=self.text_color)
            ax.grid(True, alpha=0.3, color=self.grid_color, axis='x')
            
            # Инвертируем ось Y, чтобы самый частый был сверху
            ax.invert_yaxis()
            
            plt.tight_layout()
            plt.savefig(filename, dpi=self.DPI, bbox_inches='tight', facecolor=self.face_color)
            plt.close()
            
            self.logger.info(f"График топ индикаторов сохранен: {filename}")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании графика индикаторов: {e}")
            plt.close()
            return None
    
    def generate_severity_pie_chart(self, alerts: List[Alert], output_dir: str) -> Optional[str]:
        """
        Генерирует круговую диаграмму распределения алертов по severity.
        
        Args:
            alerts: Список алертов
            output_dir: Директория для сохранения
        
        Returns:
            Путь к сохраненному файлу или None, если нет данных
        """
        df = self._extract_severity_distribution(alerts)
        
        if df.empty:
            self.logger.info("Нет данных о severity для построения диаграммы")
            return None
        
        output_path = self._ensure_output_dir(output_dir)
        filename = output_path / f"severity_distribution_{self._get_timestamp()}.png"
        
        try:
            # Создаем фигуру с двумя сабплотами: pie chart и таблица
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(self.FIGURE_SIZE[0] * 1.5, self.FIGURE_SIZE[1]))
            
            # Подготовка данных
            labels = df['severity'].tolist()
            sizes = df['count'].tolist()
            colors = [self.SEVERITY_COLORS.get(sev, '#888888') for sev in labels]
            
            # Функция для форматирования процентов
            def autopct_format(pct):
                total = sum(sizes)
                val = int(round(pct * total / 100.0))
                return f'{pct:.1f}%\n({val})'
            
            # Строим pie chart
            wedges, texts, autotexts = ax1.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct=autopct_format,
                startangle=90,
                textprops={'color': 'white', 'fontweight': 'bold'},
                wedgeprops={'edgecolor': self.text_color, 'linewidth': 1}
            )
            
            # Делаем проценты более заметными
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontsize(10)
                autotext.set_fontweight('bold')
            
            ax1.set_title('Alert Distribution by Severity', fontsize=self.TITLE_FONT_SIZE, color=self.text_color)
            
            # Добавляем таблицу с деталями
            ax2.axis('off')
            table_data = []
            for sev, count in zip(labels, sizes):
                percentage = (count / sum(sizes)) * 100
                table_data.append([sev, count, f"{percentage:.1f}%"])
            
            table = ax2.table(
                cellText=table_data,
                colLabels=['Severity', 'Count', 'Percentage'],
                cellLoc='center',
                loc='center',
                colColours=['#444444'] * 3
            )
            
            # Настройка таблицы
            table.auto_set_font_size(False)
            table.set_fontsize(10)
            table.scale(1, 1.5)
            
            # Раскрашиваем строки таблицы по severity
            for i, sev in enumerate(labels):
                table[(i + 1, 0)].set_facecolor(self.SEVERITY_COLORS.get(sev, '#888888'))
                table[(i + 1, 1)].set_facecolor('#333333')
                table[(i + 1, 2)].set_facecolor('#333333')
            
            ax2.set_title('Detailed Statistics', fontsize=self.TITLE_FONT_SIZE, color=self.text_color)
            
            plt.tight_layout()
            plt.savefig(filename, dpi=self.DPI, bbox_inches='tight', facecolor=self.face_color)
            plt.close()
            
            self.logger.info(f"Диаграмма severity сохранена: {filename}")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"Ошибка при создании диаграммы severity: {e}")
            plt.close()
            return None
    
    def generate(self, alerts: List[Alert], output_dir: str) -> List[str]:
        """
        Генерирует все графики на основе списка алертов.
        
        Args:
            alerts: Список обнаруженных угроз
            output_dir: Директория для сохранения графиков
        
        Returns:
            Список путей к сгенерированным файлам
        """
        self.logger.info(f"Начало генерации графиков, получено алертов: {len(alerts)}")
        
        if not alerts:
            self.logger.warning("Нет алертов для визуализации")
            return []
        
        generated_files = []
        
        # 1. CVSS гистограмма
        cvss_chart = self.generate_cvss_histogram(alerts, output_dir)
        if cvss_chart:
            generated_files.append(cvss_chart)
        
        # 2. Топ индикаторов
        top_chart = self.generate_top_indicators_chart(alerts, output_dir)
        if top_chart:
            generated_files.append(top_chart)
        
        # 3. Severity pie chart
        severity_chart = self.generate_severity_pie_chart(alerts, output_dir)
        if severity_chart:
            generated_files.append(severity_chart)
        
        self.logger.info(
            f"Генерация графиков завершена:\n"
            f"  Создано файлов: {len(generated_files)}"
        )
        
        return generated_files


# Функция-фабрика для создания генератора графиков
def create_reporter(theme: str = 'dark') -> ChartGenerator:
    """
    Создает и возвращает экземпляр генератора графиков.
    
    Args:
        theme: Тема оформления ('dark' или 'light')
    
    Returns:
        Настроенный генератор
    """
    return ChartGenerator(theme=theme)


# Блок для самостоятельного тестирования модуля
if __name__ == "__main__":
    """
    Тестирование генератора графиков на синтетических данных.
    
    Генерирует тестовый набор алертов и создает все графики.
    """
    import sys
    import tempfile
    from datetime import datetime, timedelta
    import random
    
    # Настраиваем логирование
    from utils.logger import setup_logger
    setup_logger(console_level=10)  # DEBUG
    
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ ГЕНЕРАТОРА ГРАФИКОВ")
    print("=" * 60)
    
    # Создаем тестовые алерты
    def generate_test_alerts(count: int = 50) -> List[Alert]:
        """Генерирует тестовый набор алертов."""
        alerts = []
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        sources = ['vulners', 'virustotal', 'traffic_analyzer']
        
        # Генерация CVSS алертов
        for i in range(count // 2):
            cvss = random.uniform(2.0, 10.0)
            alerts.append(Alert(
                title=f"Test Vulnerability {i}",
                severity=random.choice(severities),
                source='vulners',
                description=f"Test vulnerability with CVSS {cvss:.1f}",
                indicator=f"CVE-2024-{1000 + i}",
                raw_data={'cvss': cvss}
            ))
        
        # Генерация индикаторных алертов
        domains = ['malware.com', 'c2-server.net', 'phishing.org', 'botnet.xyz', 'dga.dynamic', 
                   'suspicious.io', 'attack.com', 'evil.org', 'bad.net', 'ransomware.tech']
        
        for i in range(count // 2):
            domain = random.choice(domains)
            severity = random.choice(severities)
            alerts.append(Alert(
                title=f"Suspicious Domain",
                severity=severity,
                source=random.choice(['virustotal', 'traffic_analyzer']),
                description=f"Malicious activity detected for {domain}",
                indicator=domain,
                raw_data={
                    'malicious': random.randint(1, 10),
                    'query_count': random.randint(10, 500)
                }
            ))
        
        # Добавляем временную метку
        base_time = datetime.now()
        for i, alert in enumerate(alerts):
            alert.timestamp = base_time - timedelta(minutes=random.randint(0, 60))
        
        return alerts
    
    # Создаем временную директорию для графиков
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\nВременная директория для тестов: {tmpdir}")
        
        # Генерируем тестовые данные
        test_alerts = generate_test_alerts(100)
        print(f"\nСгенерировано тестовых алертов: {len(test_alerts)}")
        
        # Показываем статистику по severity
        severity_counts = Counter(a.severity for a in test_alerts)
        print("\nРаспределение по severity:")
        for sev, count in severity_counts.most_common():
            print(f"  {sev}: {count}")
        
        # Создаем генератор и строим графики
        print(f"\n{'='*60}")
        print("ГЕНЕРАЦИЯ ГРАФИКОВ")
        print(f"{'='*60}")
        
        # Тестируем обе темы
        for theme in ['dark', 'light']:
            print(f"\n--- Тема: {theme.upper()} ---")
            
            generator = ChartGenerator(theme=theme)
            files = generator.generate(test_alerts, tmpdir)
            
            print(f"\nСгенерировано файлов: {len(files)}")
            for i, file_path in enumerate(files, 1):
                print(f"  {i}. {Path(file_path).name}")
        
        print(f"\n{'='*60}")
        print("ПРОВЕРКА ОТДЕЛЬНЫХ МЕТОДОВ")
        print(f"{'='*60}")
        
        generator = ChartGenerator(theme='dark')
        
        # Тест с пустым списком
        print("\nТест с пустым списком алертов:")
        empty_files = generator.generate([], tmpdir)
        print(f"  Результат: {empty_files}")
        
        # Тест без CVSS данных
        no_cvss_alerts = [Alert(
            title="No CVSS",
            severity="LOW",
            source="test",
            description="No CVSS data",
            indicator="test"
        )]
        
        print("\nТест без CVSS данных:")
        files = generator.generate(no_cvss_alerts, tmpdir)
        print(f"  Создано файлов: {len(files)}")
        print(f"  Файлы: {[Path(f).name for f in files]}")
        
        print(f"\n{'='*60}")
        print("ТЕСТИРОВАНИЕ ЗАВЕРШЕНО")
        print(f"{'='*60}")
        print("\n✅ Все графики успешно сгенерированы (проверь визуально)")
