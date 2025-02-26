#!/bin/bash

# ANSI цвета и стили
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Функция для отображения шапки
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

# Функция для отображения анимационного прогресса
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Функция для отображения финального сообщения
show_final_message() {
    local download_link=$1
    local password=$2
    local local_path=$3

    local GREEN='\033[0;32m'
    local NC='\033[0m'
    echo -e "${GREEN}##################################################${NC}"
    echo -e "${GREEN}# Ваша ссылка на скачивание архива с прокси - ${download_link}${NC}"
    echo -e "${GREEN}# Пароль к архиву - ${password}${NC}"
    echo -e "${GREEN}# Файл с прокси можно найти по адресу - ${local_path}${NC}"
    echo -e "${GREEN}# Всегда ваш NPPRTEAM!${NC}"
    echo -e "${GREEN}# Наши контакты:${NC}"
    echo -e "${GREEN}# Наш ТГ — https://t.me/nppr_team${NC}"
    echo -e "${GREEN}# Наш ВК — https://vk.com/npprteam${NC}"
    echo -e "${GREEN}# ТГ нашего магазина — https://t.me/npprteamshop${NC}"
    echo -e "${GREEN}# Магазин аккаунтов, бизнес-менеджеров ФБ и Google — https://npprteam.shop${NC}"
    echo -e "${GREEN}# Наш антидетект-браузер Antik Browser — https://antik-browser.com/${NC}"
    echo -e "${GREEN}##################################################${NC}"
}

# Функция для интерактивного ввода параметров
get_user_input() {
    echo "Пожалуйста, введите следующие параметры для установки прокси:"
    echo "Подсеть (например, 48):"
    read subnet
    if [[ -z "$subnet" ]]; then subnet=64; fi
    echo "Логин и пароль:"
    echo "1) Указать"
    echo "2) Без логина и пароля"
    echo "3) Рандомные"
    read auth_choice
    case $auth_choice in
        1)
            echo "Введите логин:"
            read user
            echo "Введите пароль:"
            read password
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
    echo "Введите номер (1 или 2):"
    read proxies_choice
    if [[ "$proxies_choice" == "1" || -z "$proxies_choice" ]]; then
        proxies_type="socks5"
    elif [[ "$proxies_choice" == "2" ]]; then
        proxies_type="http"
    else
        echo "Неверный ввод, используется значение по умолчанию (socks5)."
        proxies_type="socks5"
    fi
    echo "Выбранный тип прокси: $proxies_type"
    echo "Интервал ротации (в минутах, 0 для отключения, по умолчанию 0):"
    read rotating_interval
    if [[ -z "$rotating_interval" ]]; then rotating_interval=0; fi
    echo "Количество прокси:"
    read proxy_count
    if [[ -z "$proxy_count" ]]; then proxy_count=100; fi
    echo "Режим работы:"
    echo "1) Универсальные (ipv4/ipv6)"
    echo "2) Только ipv6"
    read mode_choice
    case $mode_choice in
        1)
            mode_flag="-64"
            ;;
        2)
            mode_flag="-6"
            ;;
        *)
            echo "Неверный выбор, будет использован режим Универсальные (ipv4/ipv6)."
            mode_flag="-64"
            ;;
    esac
}

get_user_input

echo "Установка началась. Ожидайте..."
(sleep 10)

exec > /var/tmp/ipv6-proxy-server-install.log 2>&1

required_packages=("openssl" "zip" "curl" "jq")
for package in "${required_packages[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        echo "Устанавливаем $package..."
        apt-get update -qq
        apt-get install -y $package
    fi
done

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

function usage() { echo "Usage: $0 [options]" 1>&2; exit 1; }

options=$(getopt -o ldhs:c:u:p:t:r:m:f:i:b: --long help,localhost,disable-inet6-ifaces-check,random,uninstall,info,subnet:,proxy-count:,username:,password:,proxies-type:,rotating-interval:,ipv6-mask:,interface:,start-port:,backconnect-proxies-file:,backconnect-ip:,allowed-hosts:,denied-hosts: -- "$@")

if [ $? != 0 ]; then echo "Error: no arguments provided. Terminating..." >&2; usage; fi;

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
interface_name="$(ip -br l | awk '$1 !~ "lo|vir|wl|@NONE" { print $1 }' | awk 'NR==1')"
script_log_file="/var/tmp/ipv6-proxy-server-logs.log"
backconnect_ipv4=""

while true; do
  case "$1" in
    -h | --help ) usage; shift ;;
    -s | --subnet ) subnet="$2"; shift 2 ;;
    -c | --proxy-count ) proxy_count="$2"; shift 2 ;;
    -u | --username ) user="$2"; shift 2 ;;
    -p | --password ) password="$2"; shift 2 ;;
    -t | --proxies-type ) proxies_type="$2"; shift 2 ;;
    -r | --rotating-interval ) rotating_interval="$2"; shift 2 ;;
    -m | --ipv6-mask ) subnet_mask="$2"; shift 2 ;;
    -b | --backconnect-ip ) backconnect_ipv4="$2"; shift 2 ;;
    -f | --backconnect_proxies_file ) backconnect_proxies_file="$2"; shift 2 ;;
    -i | --interface ) interface_name="$2"; shift 2 ;;
    -l | --localhost ) use_localhost=true; shift ;;
    -d | --disable-inet6-ifaces-check ) inet6_network_interfaces_configuration_check=false; shift ;;
    --allowed-hosts ) allowed_hosts="$2"; shift 2 ;;
    --denied-hosts ) denied_hosts="$2"; shift 2 ;;
    --uninstall ) uninstall=true; shift ;;
    --info ) print_info=true; shift ;;
    --start-port ) start_port="$2"; shift 2 ;;
    --random ) use_random_auth=true; shift ;;
    -- ) shift; break ;;
    * ) break ;;
  esac
done

function log_err() {
  echo $1 1>&2;
  echo -e "$1\n" &>> $script_log_file;
}

function log_err_and_exit() {
  log_err "$1";
  exit 1;
}

function log_err_print_usage_and_exit() {
  log_err "$1";
  usage;
}

function is_valid_ip() {
  if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$ ]]; then return 0; else return 1; fi;
}

function is_auth_used() {
  if [ -z $user ] && [ -z $password ] && [ $use_random_auth = false ]; then false; return; else true; return; fi;
}

function check_startup_parameters() {
  re='^[0-9]+$'
  if ! [[ $proxy_count =~ $re ]]; then
    log_err_print_usage_and_exit "Error: Argument -c (proxy count) must be a positive integer number";
  fi;
  if ([ -z $user ] || [ -z $password ]) && is_auth_used && [ $use_random_auth = false ]; then
    log_err_print_usage_and_exit "Error: user and password for proxy with auth is required (specify both '--username' and '--password' startup parameters)";
  fi;
  if ([[ -n $user ]] || [[ -n $password ]]) && [ $use_random_auth = true ]; then
    log_err_print_usage_and_exit "Error: don't provide user or password as arguments, if '--random' flag is set.";
  fi;
  if [ $proxies_type != "http" ] && [ $proxies_type != "socks5" ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-t' (proxy type) parameter";
  fi;
  if [ $(expr $subnet % 4) != 0 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-s' (subnet) parameter, must be divisible by 4";
  fi;
  if [ $rotating_interval -lt 0 ] || [ $rotating_interval -gt 59 ]; then
    log_err_print_usage_and_exit "Error: invalid value of '-r' (proxy external ip rotating interval) parameter";
  fi;
  if [ $start_port -lt 5000 ] || (($start_port - $proxy_count > 65536)); then
    log_err_print_usage_and_exit "Wrong '--start-port' parameter value, it must be more than 5000 and '--start-port' + '--proxy-count' must be lower than 65536";
  fi;
  if [ ! -z $backconnect_ipv4 ]; then
    if ! is_valid_ip $backconnect_ipv4; then
      log_err_and_exit "Error: ip provided in 'backconnect-ip' argument is invalid. Provide valid IP or don't use this argument"
    fi;
  fi;
  if [ -n "$allowed_hosts" ] && [ -n "$denied_hosts" ]; then
    log_err_print_usage_and_exit "Error: if '--allow-hosts' is specified, you cannot use '--deny-hosts', the rest that isn't allowed is denied by default";
  fi;
  if cat /sys/class/net/$interface_name/operstate 2>&1 | grep -q "No such file or directory"; then
    log_err_print_usage_and_exit "Incorrect ethernet interface name \"$interface_name\", provide correct name using parameter '--interface'";
  fi;
}

bash_location="$(which bash)"
cd ~
user_home_dir="$(pwd)"
proxy_dir="$user_home_dir/proxyserver"
proxyserver_config_path="$proxy_dir/3proxy/3proxy.cfg"
proxyserver_info_file="$proxy_dir/running_server.info"

# Здесь используем фиксированный IPv6 адрес для прокси:
fixed_ipv6="2a06:f901:4001:0100:0000:0000:f4d0:61ed"

random_ipv6_list_file="$proxy_dir/ipv6.list"
random_users_list_file="$proxy_dir/random_users.list"
if [[ $backconnect_proxies_file == "default" ]]; then backconnect_proxies_file="$proxy_dir/backconnect_proxies.list"; fi;
startup_script_path="$proxy_dir/proxy-startup.sh"
cron_script_path="$proxy_dir/proxy-server.cron"
last_port=$(($start_port + $proxy_count - 1))
credentials=$(is_auth_used && [[ $use_random_auth == false ]] && echo -n ":$user:$password" || echo -n "")

function is_proxyserver_installed() {
  if [ -d $proxy_dir ] && [ "$(ls -A $proxy_dir)" ]; then return 0; fi;
  return 1;
}

function is_proxyserver_running() {
  if ps aux | grep -q $proxyserver_config_path; then return 0; else return 1; fi;
}

function is_package_installed() {
  if [ $(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -c "ok installed") -eq 0 ]; then return 1; else return 0; fi;
}

function create_random_string() {
  tr -dc A-Za-z0-9 </dev/urandom | head -c $1; echo ''
}

function kill_3proxy() {
  ps -ef | awk '/[3]proxy/{print $2}' | while read -r pid; do
    kill $pid
  done
}

function remove_ipv6_addresses_from_iface() {
  if test -f $random_ipv6_list_file; then
    for ipv6_address in $(cat $random_ipv6_list_file); do ip -6 addr del $ipv6_address dev $interface_name; done;
    rm $random_ipv6_list_file;
  fi;
}

function get_subnet_mask() {
  if [ -z $subnet_mask ]; then
    if is_proxyserver_running; then kill_3proxy; fi;
    if is_proxyserver_installed; then remove_ipv6_addresses_from_iface; fi;
    full_blocks_count=$(($subnet / 16))
    ipv6=$(ip -6 addr | awk '{print $2}' | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:)+[0-9a-fA-F]{1,4}' | cut -d '/' -f1)
    subnet_mask=$(echo $ipv6 | grep -m1 -oP '^(?!fe80)([0-9a-fA-F]{1,4}:){'$(($full_blocks_count - 1))'}[0-9a-fA-F]{1,4}')
    if [ $(expr $subnet % 16) -ne 0 ]; then
      block_part=$(echo $ipv6 | awk -v block=$(($full_blocks_count + 1)) -F ':' '{print $block}' | tr -d ' ')
      while ((${#block_part} < 4)); do block_part="0$block_part"; done;
      symbols_to_include=$(echo $block_part | head -c $(($(expr $subnet % 16) / 4)))
      subnet_mask="$subnet_mask:$symbols_to_include"
    fi;
  fi;
  echo $subnet_mask;
}

function delete_file_if_exists() {
  if test -f $1; then rm $1; fi;
}

function install_package() {
  if ! is_package_installed $1; then
    apt install $1 -y &>> $script_log_file;
    if ! is_package_installed $1; then
      log_err_and_exit "Error: cannot install \"$1\" package";
    fi;
  fi;
}

function get_backconnect_ipv4() {
  if [ $use_localhost == true ]; then echo "127.0.0.1"; return; fi;
  if [ ! -z "$backconnect_ipv4" -a "$backconnect_ipv4" != " " ]; then echo $backconnect_ipv4; return; fi;
  local maybe_ipv4=$(ip addr show $interface_name | awk '$1 == "inet" {gsub(/\/.*$/, "", $2); print $2}')
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;
  if ! is_package_installed "curl"; then install_package "curl"; fi;
  (maybe_ipv4=$(curl https://ipinfo.io/ip)) &> /dev/null
  if is_valid_ip $maybe_ipv4; then echo $maybe_ipv4; return; fi;
  log_err_and_exit "Error: curl package not installed and cannot parse valid IP from interface info";
}

function check_ipv6() {
  if test -f /proc/net/if_inet6; then
    echo "IPv6 interface is enabled";
  else
    log_err_and_exit "Error: inet6 (ipv6) interface is not enabled. Enable IP v6 on your system.";
  fi;
  if [[ $(ip -6 addr show scope global) ]]; then
    echo "IPv6 global address is allocated on server successfully";
  else
    log_err_and_exit "Error: IPv6 global address is not allocated on server, allocate it or contact your VPS/VDS support.";
  fi;
  local ifaces_config="/etc/network/interfaces";
  if [ $inet6_network_interfaces_configuration_check = true ]; then
    if [ -f $ifaces_config ]; then
      if grep 'inet6' $ifaces_config > /dev/null; then
        echo "Network interfaces for IPv6 configured correctly";
      else
        log_err_and_exit "Error: $ifaces_config has no inet6 (IPv6) configuration.";
      fi;
    else
      echo "Warning: $ifaces_config doesn't exist. Skipping interface configuration check.";
    fi;
  fi;
  if [[ $(ping6 -c 1 google.com) != *"Network is unreachable"* ]] &> /dev/null; then
    echo "Test ping google.com using IPv6 successfully";
  else
    log_err_and_exit "Error: test ping google.com through IPv6 failed, network is unreachable.";
  fi;
}

function install_requred_packages() {
  apt update &>> $script_log_file;
  requred_packages=("make" "g++" "wget" "curl" "cron");
  for package in ${requred_packages[@]}; do install_package $package; done;
  echo -e "\nAll required packages installed successfully";
}

function install_3proxy() {
  mkdir $proxy_dir && cd $proxy_dir
  echo -e "\nDownloading proxy server source...";
  ( wget https://github.com/3proxy/3proxy/archive/refs/tags/0.9.4.tar.gz &> /dev/null
    tar -xf 0.9.4.tar.gz
    rm 0.9.4.tar.gz
    mv 3proxy-0.9.4 3proxy ) &>> $script_log_file
  echo "Proxy server source code downloaded successfully";
  echo -e "\nStart building proxy server execution file from source...";
  cd 3proxy
  make -f Makefile.Linux &>> $script_log_file;
  if test -f "$proxy_dir/3proxy/bin/3proxy"; then
    echo "Proxy server built successfully"
  else
    log_err_and_exit "Error: proxy server build from source code failed."
  fi;
  cd ..
}

function configure_ipv6() {
  required_options=("conf.$interface_name.proxy_ndp" "conf.all.proxy_ndp" "conf.default.forwarding" "conf.all.forwarding" "ip_nonlocal_bind");
  for option in ${required_options[@]}; do
    full_option="net.ipv6.$option=1";
    if ! grep -v "#" /etc/sysctl.conf | grep -q "$full_option"; then echo $full_option >> /etc/sysctl.conf; fi;
  done;
  sysctl -p &>> $script_log_file;
  if [[ $(cat /proc/sys/net/ipv6/conf/$interface_name/proxy_ndp) == 1 ]] && [[ $(cat /proc/sys/net/ipv6/ip_nonlocal_bind) == 1 ]]; then
    echo "IPv6 network sysctl data configured successfully";
  else
    cat /etc/sysctl.conf &>> $script_log_file;
    log_err_and_exit "Error: cannot configure IPv6 config";
  fi;
}

function add_to_cron() {
  delete_file_if_exists $cron_script_path;
  echo "@reboot $bash_location $startup_script_path" > $cron_script_path;
  if [ $rotating_interval -ne 0 ]; then echo "*/$rotating_interval * * * * $bash_location $startup_script_path" >> "$cron_script_path"; fi;
  crontab -l | grep -v $startup_script_path >> $cron_script_path;
  crontab $cron_script_path;
  systemctl restart cron;
  if crontab -l | grep -q $startup_script_path; then
    echo "Proxy startup script added to cron autorun successfully";
  else
    log_err "Warning: adding script to cron autorun failed.";
  fi;
}

function remove_from_cron() {
  crontab -l | grep -v $startup_script_path > $cron_script_path;
  crontab $cron_script_path;
  systemctl restart cron;
  if crontab -l | grep -q $startup_script_path; then
    log_err "Warning: cannot delete proxy script from crontab";
  else
    echo "Proxy script deleted from crontab successfully";
  fi;
}

function generate_random_users_if_needed() {
  if [ $use_random_auth != true ]; then return; fi;
  delete_file_if_exists $random_users_list_file;
  for i in $(seq 1 $proxy_count); do
    echo $(create_random_string 8):$(create_random_string 8) >> $random_users_list_file;
  done;
}

# Функция создания стартового скрипта для 3proxy, использующая фиксированный IPv6 адрес для всех прокси
function create_startup_script() {
  delete_file_if_exists $startup_script_path
  is_auth_used;
  local use_auth=$?;
  cat > $startup_script_path <<-EOF
#!$bash_location
# Сохраняем старые PID процессов 3proxy, если они есть
proxyserver_process_pids=()
while read -r pid; do
  proxyserver_process_pids+=(\$pid)
done < <(ps -ef | awk '/[3]proxy/{print \$2}')

# Добавляем фиксированный IPv6 адрес на интерфейс (удаляем старую запись и добавляем новую)
ip -6 addr del $fixed_ipv6 dev $interface_name 2>/dev/null
ip -6 addr add $fixed_ipv6 dev $interface_name 2>/dev/null || true

immutable_config_part="daemon
nserver 1.1.1.1
maxconn 200
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
setgid 65535
setuid 65535"

auth_part="auth iponly"
if [ \$use_auth -eq 0 ]; then
  auth_part="auth strong
users $user:CL:$password"
fi

if [ -n "$denied_hosts" ]; then
  access_rules_part="deny * * $denied_hosts
allow *"
else
  access_rules_part="allow * * $allowed_hosts
deny *"
fi

echo "\$immutable_config_part" > $proxyserver_config_path
echo "\$auth_part" >> $proxyserver_config_path
echo "\$access_rules_part" >> $proxyserver_config_path

port=$start_port
count=1
if [ "$proxies_type" = "http" ]; then 
  proxy_startup_depending_on_type="proxy $mode_flag -n -a"
else 
  proxy_startup_depending_on_type="socks $mode_flag -a"
fi

while [ \$count -le $proxy_count ]
do
    if [ \$use_auth -eq 0 ]; then
      echo "flush" >> $proxyserver_config_path
      echo "users $user:CL:$password" >> $proxyserver_config_path
      echo "\$access_rules_part" >> $proxyserver_config_path
    fi
    echo "\$proxy_startup_depending_on_type -p\$port -i$backconnect_ipv4 -e$fixed_ipv6" >> $proxyserver_config_path
    ((port+=1))
    ((count+=1))
done

ulimit -n 600000
ulimit -u 600000
\$user_home_dir/proxyserver/3proxy/bin/3proxy \$proxyserver_config_path

for pid in "\${proxyserver_process_pids[@]}"; do
  kill \$pid;
done

exit 0
EOF

  chmod +x $startup_script_path
}

function close_ufw_backconnect_ports() {
  if ! is_package_installed "ufw" || [ $use_localhost = true ] || ! test -f $backconnect_proxies_file; then return; fi;
  local first_opened_port=$(head -n 1 $backconnect_proxies_file | awk -F ':' '{print $2}')
  local last_opened_port=$(tail -n 1 $backconnect_proxies_file | awk -F ':' '{print $2}')
  ufw delete allow $first_opened_port:$last_opened_port/tcp >> $script_log_file
  ufw delete allow $first_opened_port:$last_opened_port/udp >> $script_log_file
  if ufw status | grep -qw $first_opened_port:$last_opened_port; then
    log_err "Cannot delete UFW rules for backconnect proxies";
  else
    echo "UFW rules for backconnect proxies cleared successfully";
  fi;
}

function open_ufw_backconnect_ports() {
  close_ufw_backconnect_ports;
  if [ $use_localhost = true ]; then return; fi;
  if ! is_package_installed "ufw"; then echo "Firewall not installed, ports for backconnect proxy opened successfully"; return; fi;
  if ufw status | grep -qw active; then
    ufw allow $start_port:$last_port/tcp >> $script_log_file
    ufw allow $start_port:$last_port/udp >> $script_log_file
    if ufw status | grep -qw $start_port:$last_port; then
      echo "UFW ports for backconnect proxies opened successfully";
    else
      log_err $(ufw status)
      log_err_and_exit "Cannot open ports for backconnect proxies, configure ufw please";
    fi
  else
    echo "UFW protection disabled, ports for backconnect proxy opened successfully";
  fi;
}

function run_proxy_server() {
  if [ ! -f $startup_script_path ]; then log_err_and_exit "Error: proxy startup script doesn't exist."; fi;
  chmod +x $startup_script_path;
  $bash_location $startup_script_path;
  if is_proxyserver_running; then
    echo -e "\nIPv6 proxy server started successfully. Backconnect IPv4 is available from $backconnect_ipv4:$start_port$credentials to $backconnect_ipv4:$last_port$credentials via $proxies_type protocol";
    echo "You can copy all proxies (with credentials) in this file: $backconnect_proxies_file";
  else
    log_err_and_exit "Error: cannot run proxy server";
  fi;
}

function write_backconnect_proxies_to_file() {
  delete_file_if_exists $backconnect_proxies_file;
  local proxy_credentials=$credentials;
  if ! touch $backconnect_proxies_file &> $script_log_file; then
    echo "Backconnect proxies list file path: $backconnect_proxies_file" >> $script_log_file;
    log_err "Warning: provided invalid path to backconnect proxies list file";
    return;
  fi;
  if [ $use_random_auth = true ]; then
    local proxy_random_credentials;
    local count=0;
    readarray -t proxy_random_credentials < $random_users_list_file;
  fi;
  for port in $(eval echo "{$start_port..$last_port}"); do
    if [ $use_random_auth = true ]; then
      proxy_credentials=":${proxy_random_credentials[$count]}";
      ((count+=1))
    fi;
    echo "$backconnect_ipv4:$port$proxy_credentials" >> $backconnect_proxies_file;
  done;
}

function write_proxyserver_info() {
  delete_file_if_exists $proxyserver_info_file;
  cat > $proxyserver_info_file <<-EOF
User info:
  Proxy count: $proxy_count
  Proxy type: $proxies_type
  Proxy IP: $(get_backconnect_ipv4)
  Proxy ports: between $start_port and $last_port
  Auth: $(if is_auth_used; then if [ $use_random_auth = true ]; then echo "random user/password for each proxy"; else echo "user - $user, password - $password"; fi; else echo "disabled"; fi;)
  Rules: $(if ([ -n "$denied_hosts" ] || [ -n "$allowed_hosts" ]); then if [ -n "$denied_hosts" ]; then echo "denied hosts - $denied_hosts, all others are allowed"; else echo "allowed hosts - $allowed_hosts, all others are denied"; fi; else echo "no rules specified, all hosts are allowed"; fi;)
  File with backconnect proxy list: $backconnect_proxies_file
EOF
  cat >> $proxyserver_info_file <<-EOF
Technical info:
  Subnet: /$subnet
  Subnet mask: $subnet_mask
  File with generated IPv6 gateway addresses: $random_ipv6_list_file
  $(if [ $rotating_interval -ne 0 ]; then echo "Rotating interval: every $rotating_interval minutes"; else echo "Rotating: disabled"; fi;)
EOF
}

if [ $print_info = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server isn't installed"; fi;
  if ! is_proxyserver_running; then log_err_and_exit "Proxy server isn't running. You can check log of previous run attempt in $script_log_file"; fi;
  if ! test -f $proxyserver_info_file; then log_err_and_exit "File with information about running proxy server not found"; fi;
  cat $proxyserver_info_file;
  exit 0;
fi;

if [ $uninstall = true ]; then
  if ! is_proxyserver_installed; then log_err_and_exit "Proxy server is not installed"; fi;
  remove_from_cron;
  kill_3proxy;
  remove_ipv6_addresses_from_iface;
  close_ufw_backconnect_ports;
  rm -rf $proxy_dir;
  delete_file_if_exists $backconnect_proxies_file;
  echo -e "\nIPv6 proxy server successfully uninstalled. If you want to reinstall, just run this script again.";
  exit 0;
fi;

echo "* hard nofile 999999" >> /etc/security/limits.conf
echo "* soft nofile 999999" >> /etc/security/limits.conf
echo "net.ipv4.route.min_adv_mss = 1460" >> /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling=0" >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv4.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.proxy_ndp=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
echo "net.ipv6.ip_nonlocal_bind = 1" >> /etc/sysctl.conf
sysctl -p
systemctl stop firewalld
systemctl disable firewalld
echo "net.ipv4.ip_default_ttl=128" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syn_retries=2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fin_timeout=30" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_time=7200" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem=4096 87380 6291456" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem=4096 16384 6291456" >> /etc/sysctl.conf
sysctl -p
delete_file_if_exists $script_log_file
check_startup_parameters
check_ipv6
if is_proxyserver_installed; then
  echo -e "Proxy server already installed, reconfiguring:\n";
else
  configure_ipv6;
  install_requred_packages;
  install_3proxy;
fi;
backconnect_ipv4=$(get_backconnect_ipv4)
generate_random_users_if_needed
create_startup_script
add_to_cron
open_ufw_backconnect_ports
run_proxy_server
write_backconnect_proxies_to_file
write_proxyserver_info
mv $proxy_dir/backconnect_proxies.list $proxy_dir/proxy.txt
header="Наши контакты:\n===========================================================================\nНаш ТГ — https://t.me/nppr_team\nНаш ВК — https://vk.com/npprteam\nТГ нашего магазина — https://t.me/npprteamshop\nМагазин аккаунтов, бизнес-менеджеров ФБ и Google— https://npprteam.shop\nНаш антидетект-браузер Antik Browser — https://antik-browser.com/\n===========================================================================\n"
echo -e $header | cat - $proxy_dir/proxy.txt > temp && mv temp $proxy_dir/proxy.txt
archive_password=$(openssl rand -base64 12)
zip -P "$archive_password" $proxy_dir/proxy.zip $proxy_dir/proxy.txt
upload_response=$(curl -F "file=@$proxy_dir/proxy.zip" https://file.io)
upload_url=$(echo $upload_response | jq -r '.link')
echo "Архивный пароль: $archive_password" > $proxy_dir/upload_info.txt
echo "Ссылка для скачивания: $upload_url" >> $proxy_dir/upload_info.txt
exec > /dev/tty 2>&1
show_final_message "$upload_url" "$archive_password" "$proxy_dir/proxy.txt"
rm -- "$0"
exit 0
