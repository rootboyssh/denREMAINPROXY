#!/bin/bash
# Скрипт для создания прокси-сервера 3proxy с двумя IPv6 адресами и рандомной авторизацией.
# Требуется запуск от root.

set -e

# Функция для проверки и установки пакета через apt-get (для Debian/Ubuntu)
install_package() {
    if ! dpkg -s "$1" &>/dev/null; then
        echo "Пакет $1 не найден. Устанавливаем..."
        apt-get update -qq
        apt-get install -y "$1"
    fi
}

# Проверка, что скрипт запущен от root
if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: скрипт должен быть запущен от root."
    exit 1
fi

# Проверяем и устанавливаем необходимые пакеты
for pkg in wget tar make gcc curl openssl; do
    install_package "$pkg"
done

# Функция для проверки наличия 3proxy; если не найден – установить через apt или собрать из исходников
install_3proxy() {
    if ! command -v 3proxy &>/dev/null; then
        echo "3proxy не найден. Пробуем установить через apt-get..."
        if apt-get install -y 3proxy; then
            echo "3proxy успешно установлен через apt-get."
        else
            echo "Установка 3proxy через apt-get не удалась. Собираем из исходников..."
            TMPDIR=$(mktemp -d)
            cd "$TMPDIR"
            wget -q https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz -O 3proxy-0.9.4.tar.gz
            tar -xf 3proxy-0.9.4.tar.gz
            cd 3proxy-0.9.4
            make -f Makefile.Linux
            if [ -f "bin/3proxy" ]; then
                cp bin/3proxy /usr/local/bin/3proxy
                chmod +x /usr/local/bin/3proxy
                echo "3proxy собран и установлен."
            else
                echo "Ошибка сборки 3proxy."
                exit 1
            fi
            cd /
            rm -rf "$TMPDIR"
        fi
    else
        echo "3proxy найден."
    fi
}

install_3proxy

# Запрашиваем у пользователя IPv6 адреса поочередно
read -rp "Введите первый IPv6 адрес: " IPV6_1
read -rp "Введите второй IPv6 адрес: " IPV6_2

# Запрашиваем стартовый порт (по умолчанию 3000)
read -rp "Введите стартовый порт [3000]: " START_PORT
START_PORT=${START_PORT:-3000}

# Запрашиваем данные для авторизации (формат user:password). Если оставлено пустым – будет сгенерирована рандомная пара.
read -rp "Введите данные для авторизации (формат user:password) или оставьте пустым для рандомной авторизации: " AUTH

if [ -z "$AUTH" ]; then
    # Генерация случайных строки по 8 символов
    RAND_USER=$(openssl rand -hex 4)
    RAND_PASS=$(openssl rand -hex 4)
    AUTH="${RAND_USER}:${RAND_PASS}"
    echo "Сгенерирована рандомная пара авторизации:"
    echo "Логин: $RAND_USER, Пароль: $RAND_PASS"
fi

# Путь к конфигурационному файлу и логам
CONFIG_FILE="/etc/3proxy.cfg"
LOG_FILE="/var/log/3proxy.log"

# Формируем конфигурационный файл 3proxy
echo "Формирование конфигурационного файла 3proxy..."
cat > "$CONFIG_FILE" <<EOF
daemon
maxconn 100

# DNS-сервер и кэш
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
EOF

# Настройка авторизации
USER=$(echo "$AUTH" | cut -d':' -f1)
PASS=$(echo "$AUTH" | cut -d':' -f2)
cat >> "$CONFIG_FILE" <<EOF

auth strong
users $USER:CL:$PASS
allow $USER
EOF

# Запись настроек для двух IPv6 адресов (используем тип socks5)
cat >> "$CONFIG_FILE" <<EOF

# Прокси на IPv6 адресе $IPV6_1
socks -p$START_PORT -i$IPV6_1 -e$IPV6_1

# Прокси на IPv6 адресе $IPV6_2
socks -p$(($START_PORT+1)) -i$IPV6_2 -e$IPV6_2
EOF

echo "Конфигурационный файл создан: $CONFIG_FILE"

# Запуск 3proxy с созданной конфигурацией
echo "Запуск 3proxy..."
3proxy "$CONFIG_FILE" > "$LOG_FILE" 2>&1 &

sleep 1
if pgrep -f "$CONFIG_FILE" > /dev/null; then
    echo "Прокси-сервер запущен успешно."
else
    echo "Ошибка при запуске 3proxy. Проверьте лог: $LOG_FILE"
    exit 1
fi

# Вывод итоговых данных
echo "------------------------------------------"
echo "Созданы следующие прокси:"
echo "Прокси 1: [IPv6: $IPV6_1] порт: $START_PORT"
echo "Прокси 2: [IPv6: $IPV6_2] порт: $(($START_PORT+1))"
echo "Используемая авторизация: $USER:$PASS"
echo "------------------------------------------"
echo "Для просмотра лога работы 3proxy смотрите: $LOG_FILE"
