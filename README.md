#Итоговое ДЗ по предмету "Программирование на Python"

##  **Архитектура**

Проект построен по модульному принципу с четким разделением ответственности:
dz_final/
├── .env.example
├── .gitignore
├── main.py
├── config.py
├── requirements.txt
├── collectors/
│   ├── __init__.py
│   ├── base.py
│   ├── virustotal.py
│   ├── vulners.py
│   └── suricata_log.py
├── analyzers/
│   ├── __init__.py
│   ├── base.py
│   ├── cvss_analyzer.py
│   └── traffic_analyzer.py
├── responders/
│   ├── __init__.py
│   ├── base.py
│   ├── console_logger.py
│   └── telegram_notifier.py
├── reporters/
│   ├── __init__.py
│   ├── data_exporter.py
│   └── chart_generator.py
├── utils/
│   ├── __init__.py
│   └── logger.py
├── models/
│   ├── __init__.py
│   ├── alert.py
│   └── event.py
└── tests/
    └── __init__.py

# Установка
Предварительные требования
Python 3.8 или выше

pip и virtualenv (рекомендуется)

API ключи для внешних сервисов (опционально)

Пошаговая установка

# 1. Клонирование репозитория
git clone https://github.com/yourusername/threat-detector.git
cd threat-detector

# 2. Создание виртуального окружения
python -m venv venv

# 3. Активация виртуального окружения
# Linux/Mac:
source venv/bin/activate
# Windows:
# venv\Scripts\activate

# 4. Установка зависимостей
pip install -r requirements.txt

# 5. Настройка конфигурации
cp .env.example .env
# Отредактируйте .env, добавьте API ключи


# Настройка
Файл .env
env
# API Keys (опционально, без них функционал ограничен)
VIRUSTOTAL_API_KEY=your_key_here
VULNERS_API_KEY=your_key_here

# Telegram notifications (опционально)
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Thresholds (пороговые значения)
CVSS_THRESHOLD=7.0           # Уязвимости с CVSS >= 7.0 считаются критическими
DNS_QUERY_THRESHOLD=50       # DNS-запросов за окно для детекта аномалий

# Security
MAX_FILE_SIZE_MB=10          # Максимальный размер загружаемого лога

# Environment
ENVIRONMENT=development      # или production

# Безопасность
Принципы безопасности, реализованные в проекте
API ключи — хранятся только в .env (файл исключен из git через .gitignore)

Валидация входных данных — проверка размера файлов (защита от OOM)

Rate limiting — для всех внешних API (экспоненциальные задержки)

Экранирование — Markdown-символы в Telegram (защита от инъекций)

Безопасная работа с файлами — использование Path и проверка существования

Graceful degradation — при отсутствии ключей отключаются соответствующие модули, но приложение продолжает работу

Что НЕ хранить в репозитории
❌ .env — файл с реальными ключами
❌ __pycache__/ — кэш Python
❌ *.pyc — скомпилированные файлы
❌ venv/ — виртуальное окружение
❌ reports/ — сгенерированные отчеты

