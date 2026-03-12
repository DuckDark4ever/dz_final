#Итоговое ДЗ по предмету "Программирование на Python" - модульный инструмент для обнаружения киберугроз, агрегации данных из множества источников и автоматического реагирования. 

 **Результаты работы**: Все скриншоты, логи выполнения и сгенерированные отчёты доступны в директории [`logs&results/`](./logs&results).

---

## **Содержание**

- [Возможности](#-возможности)
- [Архитектура](#-архитектура)
- [Установка](#-установка)
- [Настройка](#-настройка)
- [Быстрый старт](#-быстрый-старт)
- [Примеры использования](#-примеры-использования)
- [Конфигурация](#-конфигурация)
- [Разработка и тестирование](#-разработка-и-тестирование)
- [Безопасность](#-безопасность)


---

##  **Возможности**

###  **Сбор данных (Collectors)**

| Модуль | Описание | Формат данных |
|--------|----------|---------------|
| `suricata_log.py` | Парсинг логов Suricata EVE JSON | NDJSON / JSON Array |
| `virustotal.py` | Проверка IoC через VirusTotal API v3 | IP, домены, хэши |
| `vulners.py` | Поиск уязвимостей по ПО через Vulners API | `software:version` |

###  **Анализ угроз (Analyzers)**

| Модуль | Метод детекта | Выходные данные |
|--------|---------------|-----------------|
| `cvss_analyzer.py` | Фильтрация уязвимостей по порогу CVSS | Alert с severity |
| `traffic_analyzer.py` | DNS-аномалии: частота, энтропия, Z-score | Алерты на DGA/C2 |
| `suricata_pandas.py` | Pandas-анализ: сканирование портов, чёрные списки | Алерты на сканирование |

###  **Реагирование (Responders)**

| Модуль | Действие | Режимы |
|--------|----------|--------|
| `console_logger.py` | Цветной вывод в консоль + дедупликация по IP | Блокировка / Уведомление |
| `telegram_notifier.py` | Отправка алертов в Telegram с Markdown | Live / Dry-run |

###  **Отчётность (Reporters)**

| Модуль | Формат | Описание |
|--------|--------|----------|
| `data_exporter.py` | JSON, CSV | Полные данные + табличное представление |
| `chart_generator.py` | PNG (300 DPI) | Гистограммы, bar/pie charts, темная/светлая тема |

---

## **Архитектура**

threat_detector/
├── main.py # Оркестратор (точка входа)
├── config.py # Конфигурация из .env
├── requirements.txt # Зависимости
├── .env.example # Шаблон конфигурации
│
├── models/ # Модели данных
│ ├── alert.py # Класс Alert
│ └── event.py # RawEvent, SuricataEvent, VulnerabilityEvent
│
├── collectors/ # Сбор данных
│ ├── base.py
│ ├── suricata_log.py
│ ├── virustotal.py
│ └── vulners.py
│
├── analyzers/ # Анализ данных
│ ├── base.py
│ ├── cvss_analyzer.py
│ ├── traffic_analyzer.py
│ └── suricata_pandas.py
│
├── responders/ # Реагирование
│ ├── base.py
│ ├── console_logger.py
│ └── telegram_notifier.py
│
├── reporters/ # Отчётность
│ ├── base.py
│ ├── data_exporter.py
│ └── chart_generator.py
│
├── utils/ # Утилиты
│ ├── logger.py
│ └── init.py
│
├── tests/ # Тесты
│ └── init.py
└── logs&results

###  **Поток данных**

``mermaid
graph LR
    A[Collectors] --> B[Raw Events]
    B --> C[Analyzers]
    C --> D[Alerts]
    D --> E[Reporters]
    D --> F[Responders]
    E --> G[JSON/CSV/PNG]
    F --> H[Console/Telegram]
    
    style A fill:#ff9900,stroke:#333,stroke-width:2px
    style C fill:#0066cc,stroke:#333,stroke-width:2px
    style E fill:#00cc66,stroke:#333,stroke-width:2px
    style F fill:#cc3300,stroke:#333,stroke-width:2px

## **Установка**

Предварительные требования
Python 3.8 или выше

pip и virtualenv (рекомендуется)

Доступ к интернету (для API-коллекторов)

Пошаговая установка
bash

# 1. Клонирование репозитория
git clone https://github.com/DuckDark4ever/dz_final.git
cd dz_final

# 2. Создание виртуального окружения
python -m venv venv

# 3. Активация окружения
# Linux/macOS:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# 4. Установка зависимостей
pip install -r requirements.txt

# 5. Настройка конфигурации
cp .env.example .env
# Отредактируйте .env, добавьте API ключи
## **Настройка**
Файл .env
env

# === API Keys (опционально) ===
VIRUSTOTAL_API_KEY=your_virustotal_key_here
VULNERS_API_KEY=your_vulners_key_here

# === Telegram уведомления (опционально) ===
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# === Пороговые значения ===
CVSS_THRESHOLD=7.0              # Уязвимости с CVSS >= 7.0 считаются критическими
DNS_QUERY_THRESHOLD=50           # Мин. частота DNS-запросов для детекта аномалий
SCAN_THRESHOLD=5                 # Мин. количество портов для детекта сканирования
MAX_FILE_SIZE_MB=100             # Макс. размер файла лога для защиты от OOM

# === Режим работы ===
ENVIRONMENT=development          # development/production

## **Быстрый старт**

Проверка установки

bash
python main.py --help

Минимальный запуск (без внешних API)

bash
python main.py --suricata-log /var/log/suricata/eve.json

Проверка результатов

bash
# Просмотр сгенерированных отчётов
ls -la ./reports/

# Просмотр логов и скриншотов
ls -la logs&results/

## **Примеры использования**

1️⃣ Анализ логов Suricata
bash
# Базовый анализ
python main.py --suricata-log /var/log/suricata/eve.json

# С выбором анализаторов
python main.py \
  --suricata-log eve.json \
  --analyzers pandas,cvss \
  --output-dir ./reports

# С подробным выводом
python main.py --suricata-log eve.json --verbose

2️⃣ Проверка индикаторов через VirusTotal
bash
# Проверка одного IP
python main.py --check-ip 8.8.8.8

# Проверка нескольких индикаторов
python main.py \
  --check-ip 8.8.8.8 1.1.1.1 \
  --check-domain google.com malware-test.com

# С сохранением результатов
python main.py \
  --check-ip 185.130.5.133 \
  --output-dir ./vt_results

3️⃣ Поиск уязвимостей через Vulners

bash
# Для конкретного ПО
python main.py --vuln-software "nginx 1.18.0"

# Для ПО с пробелами в названии
python main.py --vuln-software "Apache HTTP Server 2.4.49"

# С порогом CVSS из конфига
python main.py --vuln-software "openssl 1.1.1" --verbose

4️⃣ Полный цикл с уведомлениями

bash
# Все источники + отчёты + Telegram
python main.py \
  --suricata-log /var/log/suricata/eve.json \
  --check-ip 185.130.5.133 \
  --check-domain malware-test.com \
  --vuln-software "nginx 1.18.0" \
  --output-dir ./full_report \
  --theme dark \
  --verbose

5️⃣ Тестовые режимы
bash
# Dry-run: без реальных действий
python main.py --check-ip 8.8.8.8 --dry-run

# Без Telegram-уведомлений
python main.py --suricata-log eve.json --no-telegram

# Только уведомления (без имитации блокировки)
python main.py --suricata-log eve.json --no-block

# Светлая тема для графиков
python main.py --suricata-log eve.json --theme light

## **Конфигурация**
Параметры командной строки
bash
python main.py [OPTIONS]

Источники данных:
  --suricata-log PATH      Путь к логу Suricata (eve.json)
  --check-ip IP [IP ...]   Список IP для проверки через VirusTotal
  --check-domain DOM [DOM ...]  Список доменов для проверки
  --vuln-software TEXT     Поиск уязвимостей: "nginx 1.18.0"

Настройки:
  --verbose, -v            Подробный вывод (уровень DEBUG)
  --no-telegram            Отключить отправку уведомлений в Telegram
  --no-block               Режим только уведомления (без имитации блокировки)
  --dry-run                Тестовый режим (без реальных действий)
  --theme {dark,light}     Тема графиков (по умолчанию: dark)
  --analyzers TEXT         Анализаторы: all, cvss, traffic, pandas (через запятую)

Выходные данные:
  --output-dir DIR         Директория для сохранения отчетов (по умолч.: ./reports)

 ## **Разработка и тестирование**
Установка зависимостей для разработки

bash
pip install -r requirements.txt
pip install pytest pytest-cov flake8 mypy black isort

Запуск тестов

bash
# Все тесты с покрытием
pytest tests/ --cov=threat_detector --cov-report=html

# Конкретный модуль
pytest tests/test_analyzers.py -v

# Быстрая проверка синтаксиса
python -m py_compile threat_detector/**/*.py
Проверка стиля кода
bash
# PEP8
flake8 threat_detector/ --max-line-length=120

# Типизация
mypy threat_detector/

# Форматирование
black --check threat_detector/
isort --check threat_detector/
Авто-форматирование
bash
black threat_detector/
isort threat_detector/

## **Безопасность**

Принципы, реализованные в проекте

Секреты вне кода	Все API-ключи через .env, файл в .gitignore
Валидация входа	Проверка размера файлов, типов данных, форматов
Rate limiting	Экспоненциальные задержки для всех внешних API
Экранирование	Защита от Markdown-инъекций в Telegram
Безопасные пути	Использование pathlib, проверка существования файлов
Graceful degradation	При отсутствии ключей модули отключаются, но приложение работает

Что НЕ хранить в репозитории

bash
# .gitignore уже исключает:
.env                    # Реальные ключи
__pycache__/            # Кэш Python
*.pyc                   # Скомпилированные файлы
venv/                   # Виртуальное окружение
reports/                # Сгенерированные отчёты
logs&results/*.log      # Логи с чувствительными данными
