#!/bin/bash
set -e  # Прерывание при ошибке, за исключением команд с "|| true"

# ANSI цвета и стили
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Функция отображения шапки
show_header() {
    clear
    echo -e "${RED}"
    echo "███╗   ██╗██████╗ ██████╗ ██████╗ ████████╗███████╗ █████╗ ███╗   ███╗"
    echo "████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║"
    echo "██╔██╗ ██║██████╔╝██████╔╝██████╔╝   ██║   █████╗  ███████║██╔████╔██║"
    echo "██║╚██╗██║██╔═══╝ ██╔═══╝ ██╔══██╗   ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║"
    echo "██║ ╚████║██║     ██║     ██║  ██║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║"
    echo "╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═╝  ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝"
    echo -e "${NC}"
    echo -e "${GREEN}------------------------------------------------"
    echo "Наши контакты:"
    echo "Наш ТГ — https://t.me/nppr_team"
    echo "Наш ВК — https://vk.com/npprteam"
    echo "ТГ нашего магазина — https://t.me/npprteamshop"
    echo "Магазин аккаунтов, бизнес-менеджеров ФБ и Google — https://npprteam.shop"
    echo "Наш антидетект-браузер Antik Browser — https://antik-browser.com/"
    echo -e "------------------------------------------------${NC}"
}

show_header

# Лог-файл
script_log_file="/var/tmp/ipv6-proxy-server-install.log"

# Вывод в лог и на экран через tee
exec > >(tee -a "$script_log_file") 2> >(tee -a "$script_log_file" >&2)

# Функция логирования ошибок
log_err() {
    echo -e "$1" >&2
    echo -e "$1\n" >> "$script_log_file"
}
log_err_and_exit() {
    log_err "$1"
    exit 1
}

# Функция is_auth_used
is_auth_used() {
    if [ "$use_random_auth" = true ]; then
        return 0
    fi
    if [ -n "$user" ] && [ -n "$password" ]; then
        return 0
    fi
    return 1
}

# Функция для автоматического определения IPv6-пула
get_available_ipv6_pool() {
    local iface
    iface=$(ip -br l | awk '$1 !~ /lo|vir|wl|@NONE/ { print $1; exit }')
    if [ -z "$iface" ]; then
        log_err_and_exit "Ошибка: не найден подходящий сетевой интерфейс"
    fi
    local pool=""
    for addr in $(ip -6 addr show dev "$iface" | grep -oP '(?<=inet6 )\S+'); do
        local mask
        mask=$(echo "$addr" | cut -d'/' -f2)
        if [ "$mask" != "128" ]; then
            pool="$addr"
            break
        fi
    done
    echo "$pool"
}

# Функция проверки формата IPv4 (для backconnect)
is_valid_ip() {
    if [[ "$1" =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3})$ ]]; then return 0; else return 1; fi
}

# Интерактивный ввод параметров
get_user_input() {
    echo "Пожалуйста, введите следующие параметры для установки прокси:"
    
    echo "Подсеть (например, 48, по умолчанию 64):"
    read -r subnet
    if [ -z "$subnet" ]; then subnet=64; fi
    
    echo "Логин и пароль:"
    echo "1) Указать"
    echo "2) Без логина и пароля"
    echo "3) Рандомные"
    read -r auth_choice
    case "$auth_choice" in
        1)
            echo "Введите логин:"
            read -r user
            echo "Введите пароль:"
            read -r password
            use_random_auth=false
            ;;
        2)
            user=""
            password=""
            use_random_auth=false
            ;;
        3)
            user=""
            password=""
            use_random_auth=true
            ;;
        *)
            echo "Неверный выбор, будут использованы рандомные логин и пароль."
            use_random_auth=true
            ;;
    esac
    
    echo "Тип прокси (по умолчанию socks5):"
    echo "1) Socks5"
    echo "2) Http"
    read -r proxies_choice
    if [ "$proxies_choice" = "2" ]; then
        proxies_type="http"
    else
        proxies_type="socks5"
    fi
    echo "Выбранный тип прокси: $proxies_type"
    
    echo "Интервал ротации (в минутах, 0 для отключения, по умолчанию 0):"
    read -r rotating_interval
    if [ -z "$rotating_interval" ]; then rotating_interval=0; fi
    
    echo "Количество прокси:"
    read -r proxy_count
    if [ -z "$proxy_count" ]; then proxy_count=100; fi
    
    echo "Режим работы:"
    echo "1) Универсальные (IPv4/IPv6)"
    echo "2) Только IPv6"
    read -r mode_choice
    case "$mode_choice" in
        2) mode_flag="-6" ;;
        *) mode_flag="-64" ;;
    esac
}

get_user_input

echo "Установка началась. Ожидайте..."
sleep 10

# Установка необходимых утилит
required_packages=("openssl" "zip" "curl" "jq")
for package in "${required_packages[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        echo "Устанавливаем $package..."
        apt-get update -qq
        apt-get install -y "$package"
    fi
done

if [ "$EUID" -ne 0 ]; then
  echo "Запустите скрипт от root"
  exit 1
fi

# Обработка параметров командной строки (оставляем как есть)
usage() { echo "Usage: $0 [options]" >&2; exit 1; }
options=$(getopt -o ldhs:c:u:p:t:r:m:f:i:b: --long help,localhost,disable-inet6-ifaces-check,random,uninstall,info,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,interface:,start-port:,backconnect-proxies-file:,backconnect-ip:,allowed-hosts:,denied-hosts: -- "$@")
if [ $? != 0 ]; then echo "Error: неверные аргументы" >&2; usage; fi
eval set -- "$options"

subnet=${subnet:-64}
proxies_type=${proxies_type:-"socks5"}
start_port=30000
rotating_interval=${rotating_interval:-0}
use_localhost=false
use_random_auth=${use_random_auth:-false}
uninstall=false
print_info=false
inet6_network_interfaces_configuration_check=true
backconnect_proxies_file="default"
interface_name=$(ip -br l | awk '$1 !~ /lo|vir|wl|@NONE/ { print $1; exit }')
backconnect_ipv4=""
cd ~
user_home_dir=$(pwd)
proxy_dir="$user_home_dir/proxyserver"
proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
proxyserver_info_file="$proxy_dir/running_server.info"
random_ipv6_list_file="$proxy_dir/ipv6.list"
random_users_list_file="$proxy_dir/random_users.list"
if [ "$backconnect_proxies_file" = "default" ]; then 
    backconnect_proxies_file="$proxy_dir/backconnect_proxies.list"
fi
startup_script_path="$proxy_dir/proxy-startup.sh"
cron_script_path="$proxy_dir/proxy-server.cron"
last_port=$(( start_port + proxy_count - 1 ))
credentials=$(( [ "$user" ] && [ "$password" ] && [ "$use_random_auth" = false ] ) && echo -n ":$user:$password" || echo -n "" )

# Функция проверки параметров
check_startup_parameters() {
    re='^[0-9]+$'
    if ! [[ "$proxy_count" =~ $re ]]; then
        log_err_and_exit "Error: Количество прокси должно быть положительным числом"
    fi
    if [ "$use_random_auth" = false ]; then
        if [ -z "$user" ] || [ -z "$password" ]; then
            log_err_and_exit "Error: Укажите логин и пароль для прокси"
        fi
    fi
    if [ "$proxies_type" != "http" ] && [ "$proxies_type" != "socks5" ]; then
        log_err_and_exit "Error: Неверный тип прокси (допустимые: http, socks5)"
    fi
    if (( subnet % 4 != 0 )); then
        log_err_and_exit "Error: Подсеть должна быть кратна 4"
    fi
    if [ "$rotating_interval" -lt 0 ] || [ "$rotating_interval" -gt 59 ]; then
        log_err_and_exit "Error: Интервал ротации должен быть от 0 до 59"
    fi
    if [ "$start_port" -lt 5000 ] || [ $(( start_port + proxy_count )) -gt 65536 ]; then
        log_err_and_exit "Error: Неверное значение стартового порта"
    fi
    if [ -n "$backconnect_ipv4" ]; then
        if ! is_valid_ip "$backconnect_ipv4"; then
            log_err_and_exit "Error: Неверный IPv4 адрес для backconnect"
        fi
    fi
}

# Автоматическое определение IPv6-пула
ipv6_pool=$(get_available_ipv6_pool)
if [ -n "$ipv6_pool" ]; then
    echo "Определён IPv6 пул: $ipv6_pool"
else
    echo "IPv6 пул не найден – будут использоваться автогенерируемые адреса"
fi

# Функции управления и проверки
is_proxyserver_installed() {
  if [ -d "$proxy_dir" ] && [ "$(ls -A "$proxy_dir")" ]; then return 0; fi
  return 1
}
is_proxyserver_running() {
  if ps aux | grep -q "$proxyserver_config_path"; then return 0; else return 1; fi
}
is_package_installed() {
  if [ $(dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -c "ok installed") -eq 0 ]; then return 1; else return 0; fi
}
create_random_string() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c "$1"; echo ''
}
kill_3proxy() {
  ps -ef | awk '/[3]proxy/{print $2}' | while read -r pid; do
    kill "$pid"
  done
}
remove_ipv6_addresses_from_iface() {
  if test -f "$random_ipv6_list_file"; then
    for ipv6_address in $(cat "$random_ipv6_list_file"); do
      ip -6 addr del "$ipv6_address" dev "$interface_name"
    done
    rm "$random_ipv6_list_file"
  fi
}
get_subnet_mask() {
  if [ -z "$subnet_mask" ]; then
    if is_proxyserver_running; then kill_3proxy; fi
    if is_proxyserver_installed; then remove_ipv6_addresses_from_iface; fi
    full_blocks_count=$(( subnet / 16 ))
    ipv6=$(ip -6 addr | awk '{print $2}' | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:)+[0-9a-fA-F]{1,4}' | cut -d'/' -f1)
    subnet_mask=$(echo "$ipv6" | grep -m1 -oP "^(?!fe80)([0-9a-fA-F]{1,4}:){$(( full_blocks_count - 1 ))}[0-9a-fA-F]{1,4}")
    if [ $(( subnet % 16 )) -ne 0 ]; then
      block_part=$(echo "$ipv6" | awk -v block=$(( full_blocks_count + 1 )) -F ':' '{print $block}' | tr -d ' ')
      while ((${#block_part} < 4)); do block_part="0$block_part"; done
      symbols_to_include=$(echo "$block_part" | head -c $(( (subnet % 16) / 4 )))
      subnet_mask="$subnet_mask:$symbols_to_include"
    fi
  fi
  echo "$subnet_mask"
}
delete_file_if_exists() {
  if test -f "$1"; then rm "$1"; fi
}
install_package() {
  if ! is_package_installed "$1"; then
    apt install "$1" -y >> "$script_log_file" 2>&1
    if ! is_package_installed "$1"; then
      log_err_and_exit "Error: cannot install \"$1\" package"
    fi
  fi
}
get_backconnect_ipv4() {
  if [ "$use_localhost" == true ]; then echo "127.0.0.1"; return; fi
  if [ -n "$backconnect_ipv4" ] && [ "$backconnect_ipv4" != " " ]; then echo "$backconnect_ipv4"; return; fi
  local maybe_ipv4
  maybe_ipv4=$(ip addr show "$interface_name" | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}')
  if is_valid_ip "$maybe_ipv4"; then echo "$maybe_ipv4"; return; fi
  if ! is_package_installed "curl"; then install_package "curl"; fi
  maybe_ipv4=$(curl -s https://ipinfo.io/ip)
  if is_valid_ip "$maybe_ipv4"; then echo "$maybe_ipv4"; return; fi
  log_err_and_exit "Error: cannot parse valid IPv4 address"
}
check_ipv6() {
  if test -f /proc/net/if_inet6; then
    echo "IPv6 interface enabled"
  else
    log_err_and_exit "Error: IPv6 is not enabled"
  fi
  if [[ $(ip -6 addr show scope global) ]]; then
    echo "IPv6 global address allocated"
  else
    log_err_and_exit "Error: no IPv6 global address allocated"
  fi
  local ifaces_config="/etc/network/interfaces"
  if [ "$inet6_network_interfaces_configuration_check" = true ]; then
    if [ -f "$ifaces_config" ]; then
      if ! grep -q 'inet6' "$ifaces_config"; then
        log_err_and_exit "Error: $ifaces_config has no inet6 configuration"
      fi
    else
      echo "Warning: $ifaces_config not found; skipping interface check"
    fi
  fi
  if ! ping6 -c 1 google.com &>/dev/null; then
    log_err_and_exit "Error: ping6 to google.com failed"
  fi
}
install_requred_packages() {
  apt update >> "$script_log_file" 2>&1
  requred_packages=("make" "g++" "wget" "curl" "cron")
  for package in "${requred_packages[@]}"; do
    install_package "$package"
  done
  echo -e "\nAll required packages installed successfully"
}
install_3proxy() {
  mkdir -p "$proxy_dir" && cd "$proxy_dir" || exit 1
  echo -e "\nDownloading proxy server source..."
  wget -q https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz
  tar -xf 0.9.4.tar.gz
  rm 0.9.4.tar.gz
  mv 3proxy-0.9.4 3proxy
  echo "Proxy server source downloaded successfully"
  echo -e "\nBuilding proxy server..."
  cd 3proxy || exit 1
  make -f Makefile.Linux >> "$script_log_file" 2>&1
  if test -f "$proxy_dir/3proxy/bin/3proxy"; then
    echo "Proxy server built successfully"
  else
    log_err_and_exit "Error: proxy server build failed"
  fi
  cd "$proxy_dir" || exit 1
}
configure_ipv6() {
  required_options=("conf.$interface_name.proxy_ndp" "conf.all.proxy_ndp" "conf.default.forwarding" "conf.all.forwarding" "ip_nonlocal_bind")
  for option in "${required_options[@]}"; do
    full_option="net.ipv6.$option=1"
    if ! grep -qx "$full_option" /etc/sysctl.conf; then
      echo "$full_option" >> /etc/sysctl.conf
    fi
  done
  sysctl -p >> "$script_log_file" 2>&1
  if [[ $(cat /proc/sys/net/ipv6/conf/"$interface_name"/proxy_ndp) == 1 ]] && [[ $(cat /proc/sys/net/ipv6/ip_nonlocal_bind) == 1 ]]; then
    echo "IPv6 sysctl configured successfully"
  else
    log_err_and_exit "Error: cannot configure IPv6 sysctl"
  fi
}
add_to_cron() {
  delete_file_if_exists "$cron_script_path"
  echo "@reboot $bash_location $startup_script_path" > "$cron_script_path"
  if [ "$rotating_interval" -ne 0 ]; then
    echo "*/$rotating_interval * * * * $bash_location $startup_script_path" >> "$cron_script_path"
  fi
  crontab -l 2>/dev/null | grep -v "$startup_script_path" >> "$cron_script_path"
  crontab "$cron_script_path"
  systemctl restart cron
  if crontab -l | grep -q "$startup_script_path"; then
    echo "Cron job added successfully"
  else
    log_err "Warning: failed to add cron job"
  fi
}
remove_from_cron() {
  crontab -l 2>/dev/null | grep -v "$startup_script_path" > "$cron_script_path"
  crontab "$cron_script_path"
  systemctl restart cron
  if crontab -l | grep -q "$startup_script_path"; then
    log_err "Warning: failed to remove cron job"
  else
    echo "Cron job removed successfully"
  fi
}
generate_random_users_if_needed() {
  if [ "$use_random_auth" != true ]; then return; fi
  delete_file_if_exists "$random_users_list_file"
  for i in $(seq 1 "$proxy_count"); do
    echo "$(create_random_string 8):$(create_random_string 8)" >> "$random_users_list_file"
  done
}

# Функция создания стартового скрипта для 3proxy
create_startup_script() {
  delete_file_if_exists "$startup_script_path"
  is_auth_used; local use_auth=$?
  cat > "$startup_script_path" <<-'EOF'
#!'"$bash_location"'
# Функция для удаления начальных пробелов
dedent() {
  local -n ref="$1"
  ref="$(echo "$ref" | sed 's/^[[:space:]]*//')"
}
# Сохраняем старые PID процессов 3proxy
proxyserver_process_pids=()
while read -r pid; do
  proxyserver_process_pids+=("$pid")
done < <(ps -ef | awk '/[3]proxy/{print $2}')
# Сохраняем старые IPv6 адреса для удаления
old_ipv6_list_file="'"$random_ipv6_list_file"'".old
if test -f "'"$random_ipv6_list_file"'"; then
  cp "'"$random_ipv6_list_file"'" "$old_ipv6_list_file"
  rm "'"$random_ipv6_list_file"'"
fi
# Функция генерации случайного hex символа
array=(1 2 3 4 5 6 7 8 9 0 a b c d e f)
rh() { echo "${array[RANDOM%16]}"; }
# Функция для автогенерации IPv6 адресов (без пула)
rnd_subnet_ip() {
  echo -n "$(get_subnet_mask)"
  symbol="'"$subnet"'"
  while (( symbol < 128 )); do
    if (( symbol % 16 == 0 )); then echo -n ":"; fi
    echo -n "$(rh)"
    let "symbol += 4"
  done
  echo
}
EOF

  # Если пул IPv6 найден, используем его для генерации адресов
  cat >> "$startup_script_path" <<'EOF'
if [ -n "'"$ipv6_pool"'" ]; then
  rnd_pool_ip() {
    pool_prefix=$(echo "'"$ipv6_pool"'" | cut -d '/' -f1)
    pool_mask=$(echo "'"$ipv6_pool"'" | cut -d '/' -f2)
    digits=$(( (128 - pool_mask) / 4 ))
    random_hex=""
    for ((i=0; i<digits; i++)); do
      random_hex="${random_hex}$(printf "%x" $(( RANDOM % 16 )))"
    done
    formatted=""
    while [ -n "$random_hex" ]; do
      group=${random_hex:0:4}
      formatted="${formatted}:${group}"
      random_hex=${random_hex:4}
    done
    formatted=${formatted#:}
    if [[ "$(echo "'"$ipv6_pool"'" | cut -d '/' -f1)" != *":" ]]; then
      echo "$(echo "'"$ipv6_pool"'" | cut -d '/' -f1):${formatted}"
    else
      echo "$(echo "'"$ipv6_pool"'" | cut -d '/' -f1)${formatted}"
    fi
  }
  rnd_function=rnd_pool_ip
else
  rnd_function=rnd_subnet_ip
fi
count=1
while [ "$count" -le "'"$proxy_count"'" ]; do
  $rnd_function >> "'"$random_ipv6_list_file"'"
  count=$((count+1))
done
immutable_config_part="daemon
  nserver 1.1.1.1
  nserver 2001:4860:4860::8888
  maxconn 200
  nscache 65536
  timeouts 1 5 30 60 180 1800 15 60
  setgid 65535
  setuid 65535"
dedent immutable_config_part
auth_part="auth iponly"
if [ '"$use_auth"' -eq 0 ]; then
  auth_part="
  auth strong
  users '"$user"':CL:'"$password"'"
fi
dedent auth_part
if [ -z "'"$allowed_hosts"'" ] && [ -z "'"$denied_hosts"'" ]; then
  access_rules_part="allow *"
else
  if [ -n "'"$denied_hosts"'" ]; then
    access_rules_part="
    deny * * '"$denied_hosts"'
    allow *"
  else
    access_rules_part="
    allow * * '"$allowed_hosts"'
    deny *"
  fi
fi
dedent access_rules_part
echo "${immutable_config_part}"$'\n'"${auth_part}"$'\n'"${access_rules_part}" > "'"$proxyserver_config_path"'"
port="'"$start_port"'"
count=0
if [ "'"$proxies_type"'" = "http" ]; then
  proxy_startup_depending_on_type="proxy '"$mode_flag"' -n -a"
else
  proxy_startup_depending_on_type="socks '"$mode_flag"' -a"
fi
if [ "$use_random_auth" = true ]; then
  readarray -t proxy_random_credentials < "'"$random_users_list_file"'"
fi
while read -r random_ipv6_address; do
  if [ "$use_random_auth" = true ]; then
    IFS=":" read -r username password <<< "${proxy_random_credentials[count]}"
    echo "flush" >> "'"$proxyserver_config_path"'"
    echo "users ${username}:CL:${password}" >> "'"$proxyserver_config_path"'"
    echo "${access_rules_part}" >> "'"$proxyserver_config_path"'"
    IFS=$' \t\n'
  fi
  echo "${proxy_startup_depending_on_type} -p${port} -i'"$backconnect_ipv4"' -e${random_ipv6_address}" >> "'"$proxyserver_config_path"'"
  port=$((port+1))
  count=$((count+1))
done < "'"$random_ipv6_list_file"'"
ulimit -n 600000
ulimit -u 600000
while read -r ipv6_address; do
  ip -6 addr add "${ipv6_address}" dev "'"$interface_name"'"
done < "'"$random_ipv6_list_file"'"
# Запускаем 3proxy в фоне, чтобы не блокировать выполнение
"'"$user_home_dir"'/proxyserver/3proxy/bin/3proxy" "'"$proxyserver_config_path"'" &
for pid in "${proxyserver_process_pids[@]}"; do
  kill "$pid"
done
if test -f "$old_ipv6_list_file"; then
  while read -r ipv6_address; do
    ip -6 addr del "${ipv6_address}" dev "'"$interface_name"'"
  done < "$old_ipv6_list_file"
  rm "$old_ipv6_list_file"
fi
exit 0
EOF

}

close_ufw_backconnect_ports() {
  if ! is_package_installed "ufw" || [ "$use_localhost" = true ] || ! test -f "$backconnect_proxies_file" ; then return; fi
  first_opened_port=$(head -n 1 "$backconnect_proxies_file" | awk -F ':' '{print $2}')
  last_opened_port=$(tail -n 1 "$backconnect_proxies_file" | awk -F ':' '{print $2}')
  ufw delete allow "$first_opened_port":"$last_opened_port"/tcp >> "$script_log_file" 2>&1 || true
  ufw delete allow "$first_opened_port":"$last_opened_port"/udp >> "$script_log_file" 2>&1 || true
  if ufw status | grep -qw "$first_opened_port":"$last_opened_port"; then
    log_err "Cannot delete UFW rules for backconnect proxies"
  else
    echo "UFW rules cleared successfully"
  fi
}
open_ufw_backconnect_ports() {
  close_ufw_backconnect_ports
  if [ "$use_localhost" = true ]; then return; fi
  if ! is_package_installed "ufw" ; then echo "Firewall not installed, ports opened successfully"; return; fi
  if ufw status | grep -qw active; then
    ufw allow "$start_port":"$last_port"/tcp >> "$script_log_file" 2>&1
    ufw allow "$start_port":"$last_port"/udp >> "$script_log_file" 2>&1
    if ufw status | grep -qw "$start_port":"$last_port"; then
      echo "UFW ports opened successfully"
    else
      log_err "$(ufw status)"
      log_err_and_exit "Cannot open ports for backconnect proxies, check ufw configuration"
    fi
  else
    echo "UFW disabled, ports opened successfully"
  fi
}
run_proxy_server() {
  if [ ! -f "$startup_script_path" ]; then log_err_and_exit "Error: startup script not found"; fi
  chmod +x "$startup_script_path"
  "$bash_location" "$startup_script_path"
  if is_proxyserver_running; then
    echo -e "\nIPv6 proxy server started successfully."
    echo "Backconnect IPv4 is available from $(get_backconnect_ipv4):$start_port$credentials to $(get_backconnect_ipv4):$last_port$credentials via $proxies_type protocol"
    echo "Proxies are listed in: $backconnect_proxies_file"
  else
    log_err_and_exit "Error: cannot run proxy server"
  fi
}
write_backconnect_proxies_to_file() {
  delete_file_if_exists "$backconnect_proxies_file"
  proxy_credentials="$credentials"
  if ! touch "$backconnect_proxies_file" 2>> "$script_log_file"; then
    echo "Backconnect proxies file: $backconnect_proxies_file" >> "$script_log_file"
    log_err "Warning: invalid path for backconnect proxies file"
    return
  fi
  if [ "$use_random_auth" = true ]; then
    local proxy_random_credentials
    local count=0
    readarray -t proxy_random_credentials < "$random_users_list_file"
  fi
  for port in $(eval echo "{$start_port..$last_port}"); do
    if [ "$use_random_auth" = true ]; then
      proxy_credentials=":${proxy_random_credentials[count]}"
      count=$((count+1))
    fi
    echo "$(get_backconnect_ipv4):$port$proxy_credentials" >> "$backconnect_proxies_file"
  done
}
write_proxyserver_info() {
  delete_file_if_exists "$proxyserver_info_file"
  cat > "$proxyserver_info_file" <<-EOF
User info:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  Proxy IP: $(get_backconnect_ipv4)
  Proxy ports: between $start_port and $last_port
  Auth: $(if [ "$user" ] && [ "$password" ] && [ "$use_random_auth" = false ]; then echo "user - $user, password - $password"; elif [ "$use_random_auth" = true ]; then echo "random user/password for each proxy"; else echo "disabled"; fi)
  Rules: $(if [ -n "$denied_hosts" ] || [ -n "$allowed_hosts" ]; then if [ -n "$denied_hosts" ]; then echo "denied hosts - $denied_hosts, all others allowed"; else echo "allowed hosts - $allowed_hosts, rest denied"; fi; else echo "no rules specified, all allowed"; fi)
  Backconnect proxies file: $backconnect_proxies_file
EOF
  cat >> "$proxyserver_info_file" <<-EOF
Technical info:
  Subnet: /$subnet
  Subnet mask: $(get_subnet_mask)
  IPv6 addresses file: $random_ipv6_list_file
  $(if [ "$rotating_interval" -ne 0 ]; then echo "Rotating interval: every $rotating_interval minutes"; else echo "Rotating: disabled"; fi)
EOF
}

if [ "$print_info" = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server not installed"; fi
  if ! is_proxyserver_running; then log_err_and_exit "Proxy server not running. Check log at $script_log_file"; fi
  if ! test -f "$proxyserver_info_file"; then log_err_and_exit "Proxy server info file not found"; fi
  cat "$proxyserver_info_file"
  exit 0
fi

if [ "$uninstall" = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server not installed"; fi
  remove_from_cron
  kill_3proxy
  remove_ipv6_addresses_from_iface
  close_ufw_backconnect_ports
  rm -rf "$proxy_dir"
  delete_file_if_exists "$backconnect_proxies_file"
  echo -e "\nIPv6 proxy server successfully uninstalled."
  exit 0
fi

# Первоначальные настройки системы (резервная копия sysctl.conf)
backup_sysctl="/etc/sysctl.conf.bak"
[ ! -f "$backup_sysctl" ] && cp /etc/sysctl.conf "$backup_sysctl"
grep -qx "net.ipv4.route.min_adv_mss = 1460" /etc/sysctl.conf || echo "net.ipv4.route.min_adv_mss = 1460" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_timestamps=0" /etc/sysctl.conf || echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_window_scaling=0" /etc/sysctl.conf || echo "net.ipv4.tcp_window_scaling=0" >> /etc/sysctl.conf
grep -qx "net.ipv4.icmp_echo_ignore_all = 1" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_max_syn_backlog = 4096" /etc/sysctl.conf || echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
grep -qx "net.ipv4.conf.all.forwarding=1" /etc/sysctl.conf || echo "net.ipv4.conf.all.forwarding=1" >> /etc/sysctl.conf
grep -qx "net.ipv4.ip_nonlocal_bind = 1" /etc/sysctl.conf || echo "net.ipv4.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
grep -qx "net.ipv6.conf.all.proxy_ndp=1" /etc/sysctl.conf || echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
grep -qx "net.ipv6.conf.default.forwarding=1" /etc/sysctl.conf || echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
grep -qx "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
grep -qx "net.ipv6.ip_nonlocal_bind = 1" /etc/sysctl.conf || echo "net.ipv6.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
sysctl -p >> "$script_log_file" 2>&1
# Остановка и отключение firewalld (ошибки игнорируются)
systemctl stop firewalld || true
systemctl disable firewalld || true
# TCP/IP настройки для имитации Windows
grep -qx "net.ipv4.ip_default_ttl=128" /etc/sysctl.conf || echo "net.ipv4.ip_default_ttl=128" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_syn_retries=2" /etc/sysctl.conf || echo "net.ipv4.tcp_syn_retries=2" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_fin_timeout=30" /etc/sysctl.conf || echo "net.ipv4.tcp_fin_timeout=30" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_keepalive_time=7200" /etc/sysctl.conf || echo "net.ipv4.tcp_keepalive_time=7200" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_rmem=4096 87380 6291456" /etc/sysctl.conf || echo "net.ipv4.tcp_rmem=4096 87380 6291456" >> /etc/sysctl.conf
grep -qx "net.ipv4.tcp_wmem=4096 16384 6291456" /etc/sysctl.conf || echo "net.ipv4.tcp_wmem=4096 16384 6291456" >> /etc/sysctl.conf
sysctl -p >> "$script_log_file" 2>&1

delete_file_if_exists "$script_log_file"
check_startup_parameters
check_ipv6
if is_proxyserver_installed; then
  echo -e "Proxy server already installed, reconfiguring:\n"
else
  configure_ipv6
  install_requred_packages
  install_3proxy
fi
backconnect_ipv4=$(get_backconnect_ipv4)
generate_random_users_if_needed
create_startup_script
add_to_cron
open_ufw_backconnect_ports
run_proxy_server
write_backconnect_proxies_to_file
write_proxyserver_info
mv "$proxy_dir/backconnect_proxies.list" "$proxy_dir/proxy.txt"

# В конце выводим сформированные прокси на экран
echo -e "\nСформированные прокси (файл: $proxy_dir/proxy.txt):"
if [ -f "$proxy_dir/proxy.txt" ]; then
    cat "$proxy_dir/proxy.txt"
else
    echo "Файл с прокси не найден!"
fi

echo -e "\nРабота скрипта завершена."

exit 0
