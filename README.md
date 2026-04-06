Инструмент для автоматической проверки конфигураций на соответствие требованиям безопасности с использованием политик Rego (OPA).

УСТАНОВКА
1. Установите зависимости Python
pip install -r requirements.txt

2. Установите системные утилиты
OPA (Open Policy Agent):
curl -L -o opa https://openpolicyagent.org/downloads/v0.60.0/opa_linux_amd64_static
chmod 755 ./opa
sudo mv ./opa /usr/local/bin/opa

Conftest:
wget https://github.com/open-policy-agent/conftest/releases/download/v0.48.0/conftest_0.48.0_Linux_x86_64.tar.gz
tar -xzf conftest_0.48.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/

Docker (если требуется проверка контейнеров):
# Следуйте официальной инструкции: https://docs.docker.com/get-docker/

СТРУКТУРА ПРОЕКТА
Import-Policy/
├── excel_tables/              # Требования безопасности (Excel)
│   ├── Требования_MariaDB.xlsx
│   ├── Требования_MongoDB.xlsx
│   ├── Требования_Nginx.xlsx
│   ├── Требования_PostgreSQL.xlsx
│   ├── Требования_Prometheus.xlsx
│   └── Требования_RabbitMQ.xlsx
│
├── policies/                  # Сгенерированные Rego-политики
│   ├── mariadb.rego
│   ├── mongodb.rego
│   ├── nginx.rego
│   ├── postgres.rego
│   ├── prom.rego
│   └── rabbitmq.rego
│
├── results/                   # Отчеты о проверках (JSON)
│
├── src/
│   ├── check.py              # Основной скрипт проверки
│   ├── rego_conv.py          # Конвертер Excel → Rego
│   
│
├── .gitignore
└── requirements.txt

ИСПОЛЬЗОВАНИЕ
1. Генерация Rego-политик из Excel
python src/rego_conv.py excel_tables/Требования_Nginx.xlsx -o policies/
Конвертация нескольких файлов:
python src/rego_conv.py excel_tables/*.xlsx -o policies/

2. Проверка конфигурации (локально)
python src/check.py \
    -c /path/to/nginx.conf \
    -p policies/nginx.rego \
    -o results/nginx_audit.json

3. Проверка конфигурации в Docker-контейнере
Запущенный контейнер:
python src/check.py \
    -c /etc/nginx/nginx.conf \
    -p policies/nginx.rego \
    -o results/nginx_docker_audit.json \
    -d <container_id>

Docker-образ (создаст временный контейнер):
python src/check.py \
    -c /etc/nginx/nginx.conf \
    -p policies/nginx.rego \
    -o results/nginx_image_audit.json \
    -i nginx:latest

python src/check.py \
    -c /etc/nginx/nginx.conf \
    -p policies/nginx.rego \
    -o results/nginx_remote_audit.json \
    -r user@remote_host_ip

ПАРАМЕТРЫ КОМАНДНОЙ СТРОКИ
Параметр
Описание
Пример
-c, --config
Путь к конфигурационному файлу
-c /etc/nginx/nginx.conf
-p, --policy
Путь к Rego-политике
-p policies/nginx.rego
-o, --output
Путь к выходному JSON-файлу
-o results/report.json
-f, --files
Дополнительные файлы для проверки прав
-f /etc/ssl/cert.pem
-d, --docker-id
ID запущенного контейнера
-d abc123
-i, --image
Имя Docker-образа
-i nginx:latest
Удаленный хост
-r user@remote_host_ip