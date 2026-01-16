#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (Debian & Ubuntu LTS) - Stable Edition
# 版本: 8.1.1
# ------------------------------------------------------------------------------
# 改进日志 (v8.1.1):
# - [CRITICAL] 修复 pre_flight_checks 中 set -e 导致的误判崩溃
# ==============================================================================

set -euo pipefail

# --- 默认配置 ---
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
SWAP_SIZE_MB="auto"
INSTALL_PACKAGES="sudo wget zip vim curl htop git jq dnsutils psmisc net-tools"
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
NET_OPTIMIZE_MODE="default"
ENABLE_FAIL2BAN=true
FAIL2BAN_EXTRA_PORT=""
NEW_SSH_PORT=""
NEW_SSH_PASSWORD=""

# --- 颜色和全局变量 ---
readonly GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'

non_interactive=false
spinner_pid=0
LOG_FILE=""
VERIFICATION_PASSED=0
VERIFICATION_FAILED=0
VERIFICATION_WARNINGS=0

# ==============================================================================
# --- 核心辅助函数 ---
# ==============================================================================

log() { echo -e "$1"; }

handle_error() {
    local exit_code=$? line_number=$1
    command -v tput >/dev/null 2>&1 && tput cnorm 2>/dev/null || true
    echo -e "\n${RED}[ERROR] 脚本在第 ${line_number} 行中断 (退出码: ${exit_code})${NC}"
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] Failed at line ${line_number} (exit: ${exit_code})" >> "$LOG_FILE"
    [[ $spinner_pid -ne 0 ]] && kill "$spinner_pid" 2>/dev/null
    exit "$exit_code"
}

start_spinner() {
    if ! command -v tput >/dev/null 2>&1 || [[ ! -t 1 ]]; then
        echo -e "${CYAN}${1:-}${NC}"
        return
    fi
    echo -n -e "${CYAN}${1:-}${NC}"
    ( while :; do for c in '/' '-' '\' '|'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
    spinner_pid=$!
    tput civis 2>/dev/null || true
}

stop_spinner() {
    if [[ $spinner_pid -ne 0 ]]; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null || true
        spinner_pid=0
    fi
    if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
        tput cnorm 2>/dev/null || true
        echo -e "\b${GREEN}✔${NC}"
    else
        echo -e "${GREEN}✔${NC}"
    fi
}

wait_for_apt_locks() {
    local timeout=300
    local counter=0
    local lock_files=("/var/lib/dpkg/lock-frontend" "/var/lib/dpkg/lock" "/var/lib/apt/lists/lock")
    
    if ! command -v fuser >/dev/null 2>&1; then sleep 3; return; fi

    for lock in "${lock_files[@]}"; do
        while fuser "$lock" >/dev/null 2>&1; do
            if [[ $counter -eq 0 ]]; then
                log "${YELLOW}[WAIT] 检测到系统后台更新 (apt/dpkg)，等待锁释放...${NC}"
            fi
            if [[ $counter -ge $timeout ]]; then
                log "${RED}[ERROR] 等待 apt 锁超时 (${timeout}秒).${NC}"
                exit 1
            fi
            sleep 1
            ((counter++))
        done
    done
}

get_public_ipv4() {
    curl -s -4 --max-time 5 https://api.ipify.org || curl -s -4 --max-time 5 https://ip.sb
}

has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default'
}

check_disk_space() {
    local required_mb="$1" available_mb
    available_mb=$(df -BM / | awk 'NR==2 {gsub(/M/,"",$4); print $4}' || echo 0)
    [[ "$available_mb" -lt "$required_mb" ]] && { log "${RED}[ERROR] 磁盘空间不足: 需${required_mb}M，余${available_mb}M${NC}"; return 1; }
    return 0
}

is_container() {
    if [[ -f /.dockerenv ]] || grep -q 'container=' /proc/1/environ 2>/dev/null; then return 0; fi
    local virt=$(systemd-detect-virt 2>/dev/null || echo "none")
    [[ "$virt" =~ (lxc|openvz|docker|podman|container) ]] && return 0
    return 1
}

verify_privileges() {
    [[ $EUID -eq 0 ]] || { log "${RED}[ERROR] 必须使用 root 权限${NC}"; return 1; }
}

# ==============================================================================
# --- 验证函数 ---
# ==============================================================================

record_verification() {
    local component="$1" status="$2" message="$3"
    case "$status" in
        "PASS") log "    ${GREEN}✓${NC} ${component}: ${message}"; ((VERIFICATION_PASSED++)) ;;
        "WARN") log "    ${YELLOW}⚠${NC} ${component}: ${message}"; ((VERIFICATION_WARNINGS++)) ;;
        "FAIL") log "    ${RED}✗${NC} ${component}: ${message}"; ((VERIFICATION_FAILED++)) ;;
    esac
}

verify_network_stack() {
    if is_container; then
         record_verification "网络优化" "WARN" "容器环境跳过内核参数检查"
         return
    fi
    local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    if [[ "$NET_OPTIMIZE_MODE" == "none" ]]; then
        record_verification "网络优化" "PASS" "已禁用"
    elif [[ "$cc" == "bbr" && "$qdisc" == "fq" ]]; then
        record_verification "网络优化" "PASS" "已启用 (BBR+FQ)"
    else
        record_verification "网络优化" "FAIL" "异常 ($cc/$qdisc)"
    fi
}

verify_config() {
    local component="$1" expected="$2" actual="$3"
    [[ "$actual" == "$expected" ]] && record_verification "$component" "PASS" "OK" || record_verification "$component" "FAIL" "期望'$expected' 实际'$actual'"
}

run_verification() {
    log "\n${YELLOW}=============== 最终验证 ===============${NC}"
    VERIFICATION_PASSED=0 VERIFICATION_FAILED=0 VERIFICATION_WARNINGS=0
    set +e
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    verify_config "时区" "$TIMEZONE" "$(timedatectl show -p Timezone --value 2>/dev/null)"
    
    if timedatectl status 2>/dev/null | grep -q 'NTP service: active'; then
         record_verification "时间同步" "PASS" "Active"
    else
         record_verification "时间同步" "WARN" "非 systemd-timesyncd"
    fi

    verify_network_stack
    
    local swap_total=$(free -m | awk '/Swap:/{print $2}')
    if [[ "$SWAP_SIZE_MB" == "0" ]]; then
        [[ $swap_total -eq 0 ]] && record_verification "Swap" "PASS" "Disabled" || record_verification "Swap" "FAIL" "Not Disabled ($swap_total MB)"
    elif [[ "$SWAP_SIZE_MB" != "auto" ]]; then
         [[ $swap_total -ge $((SWAP_SIZE_MB - 5)) ]] && record_verification "Swap" "PASS" "${swap_total}MB" || record_verification "Swap" "FAIL" "Size Mismatch"
    else
         [[ $swap_total -gt 0 ]] && record_verification "Swap" "PASS" "${swap_total}MB (Auto)" || record_verification "Swap" "FAIL" "Auto Failed"
    fi

    set -e
    log "\n${BLUE}结果: ${GREEN}通过 ${VERIFICATION_PASSED}${NC}, ${YELLOW}警告 ${VERIFICATION_WARNINGS}${NC}, ${RED}失败 ${VERIFICATION_FAILED}${NC}"
}

# ==============================================================================
# --- 参数解析 ---
# ==============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hostname) NEW_HOSTNAME="$2"; shift 2 ;;
            --timezone) TIMEZONE="$2"; shift 2 ;;
            --swap) SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns) read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"; shift 2 ;;
            --ip6-dns) read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"; shift 2 ;;
            --no-optimize) NET_OPTIMIZE_MODE="none"; shift ;;
            --fail2ban) 
                ENABLE_FAIL2BAN=true
                if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                    FAIL2BAN_EXTRA_PORT="$2"
                    shift
                fi
                shift 
                ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --ssh-port) NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password) NEW_SSH_PASSWORD="$2"; shift 2 ;;
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; exit 1 ;;
        esac
    done
}

# ==============================================================================
# --- 功能模块 ---
# ==============================================================================

pre_flight_checks() {
    log "${BLUE}[INFO] 系统预检查...${NC}"
    verify_privileges
    if is_container; then
        log "${YELLOW}[WARN] 容器环境，跳过内核优化。${NC}"
        NET_OPTIMIZE_MODE="none"
    fi
    # [修复] 健壮的文件检查，防止 set -e 崩溃
    if [[ ! -f /etc/os-release ]]; then
        log "${RED}[ERROR] 无法找到 /etc/os-release${NC}"
        exit 1
    fi
}

configure_locale() {
    log "\n${YELLOW}=============== 0. Locale 配置 ===============${NC}"
    if ! locale -a | grep -q "en_US.utf8"; then
        if [ -f /etc/locale.gen ]; then
            sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
            locale-gen >/dev/null 2>&1
        fi
        update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 >/dev/null 2>&1
    fi
    export LANG=en_US.UTF-8
}

install_packages() {
    log "\n${YELLOW}=============== 1. 软件包安装 ===============${NC}"
    wait_for_apt_locks
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
    start_spinner "安装基础组件... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y $INSTALL_PACKAGES >/dev/null 2>&1
    stop_spinner
    
    if command -v vim &>/dev/null; then
        cat > /etc/vim/vimrc.local << 'EOF'
syntax on
set nocompatible
set backspace=indent,eol,start
set ruler
set hlsearch
set autoindent
set tabstop=4
set shiftwidth=4
set expandtab
set encoding=utf-8
set mouse=a
set nobackup
set noswapfile
EOF
        [[ -d /root ]] && ! grep -q "vimrc.local" /root/.vimrc 2>/dev/null && echo "source /etc/vim/vimrc.local" >> /root/.vimrc
    fi
    log "${GREEN}✅ 软件包已安装${NC}"
}

configure_hostname() {
    log "\n${YELLOW}=============== 2. 主机名配置 ===============${NC}"
    if [[ -z "$NEW_HOSTNAME" && "$non_interactive" == true ]]; then
        local ip=$(get_public_ipv4)
        [[ -n "$ip" ]] && NEW_HOSTNAME=$(echo "$ip" | tr '.' '-')
    fi
    if [[ -n "$NEW_HOSTNAME" ]]; then
        hostnamectl set-hostname "$NEW_HOSTNAME" >/dev/null 2>&1
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts || echo -e "127.0.1.1\t$NEW_HOSTNAME" >> /etc/hosts
        log "${GREEN}✅ 主机名: $NEW_HOSTNAME${NC}"
    else
        log "${BLUE}保持主机名: $(hostname)${NC}"
    fi
}

configure_time_sync() {
    log "\n${YELLOW}=============== 3. 时间同步 ===============${NC}"
    wait_for_apt_locks
    if systemctl is-active --quiet chrony || systemctl is-active --quiet ntp; then
        log "${YELLOW}[SKIP] 已有 NTP 服务运行。${NC}"
        return
    fi
    timedatectl set-timezone "$TIMEZONE" >/dev/null 2>&1
    if ! systemctl is-active --quiet systemd-timesyncd; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-timesyncd >/dev/null 2>&1 || true
        systemctl unmask systemd-timesyncd >/dev/null 2>&1 || true
        systemctl enable --now systemd-timesyncd >/dev/null 2>&1
        timedatectl set-ntp true >/dev/null 2>&1
    fi
    log "${GREEN}✅ 时区: $TIMEZONE${NC}"
}

configure_network() {
    log "\n${YELLOW}=============== 4. 网络优化 ===============${NC}"
    local conf_file="/etc/sysctl.d/99-optimized.conf"
    if [[ "$NET_OPTIMIZE_MODE" == "none" ]] || is_container; then
        rm -f "$conf_file"; return
    fi

    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    local rmem_max=16777216 wmem_max=16777216 somaxconn=4096
    
    if [[ "$total_mem" -ge 4096 ]]; then
        rmem_max=67108864; wmem_max=67108864; somaxconn=32768
    elif [[ "$total_mem" -ge 1024 ]]; then
        rmem_max=33554432; wmem_max=33554432; somaxconn=16384
    fi

    cat > "$conf_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.ipv4.tcp_rmem = 4096 87380 $rmem_max
net.ipv4.tcp_wmem = 4096 65536 $wmem_max
net.core.somaxconn = $somaxconn
net.ipv4.tcp_max_syn_backlog = $somaxconn
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_local_port_range = 10000 65535
EOF
    sysctl -p "$conf_file" >/dev/null 2>&1
    log "${GREEN}✅ BBR & 参数优化已应用${NC}"
}

configure_dns() {
    log "\n${YELLOW}=============== 5. DNS配置 ===============${NC}"
    if (systemctl is-active --quiet cloud-init 2>/dev/null); then
        log "${YELLOW}[WARN] Cloud-init 可能在重启后重置 DNS。${NC}"
    fi
    
    if (systemctl is-active --quiet systemd-resolved 2>/dev/null); then
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << EOF
[Resolve]
DNS=${PRIMARY_DNS_V4} ${SECONDARY_DNS_V4}$(has_ipv6 && echo " ${PRIMARY_DNS_V6} ${SECONDARY_DNS_V6}")
FallbackDNS=1.0.0.1 8.8.4.4
EOF
        systemctl restart systemd-resolved >/dev/null 2>&1
        log "${GREEN}✅ systemd-resolved 已配置${NC}"
    else
        rm -f /etc/resolv.conf
        cat > /etc/resolv.conf << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$(has_ipv6 && echo "nameserver ${PRIMARY_DNS_V6}")
$(has_ipv6 && echo "nameserver ${SECONDARY_DNS_V6}")
EOF
        log "${GREEN}✅ resolv.conf 已更新${NC}"
    fi
}

configure_swap() {
    log "\n${YELLOW}=============== 6. Swap 配置 ===============${NC}"
    [[ "$SWAP_SIZE_MB" == "0" ]] && return
    
    if grep -q "/swapfile" /proc/swaps; then log "${GREEN}✅ Swap已存在${NC}"; return; fi
    
    local target_swap=$SWAP_SIZE_MB
    if [[ "$SWAP_SIZE_MB" == "auto" ]]; then
        local mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        if [[ $mem_mb -lt 1024 ]]; then target_swap=$mem_mb
        elif [[ $mem_mb -lt 4096 ]]; then target_swap=2048
        else target_swap=4096; fi
    fi
    
    check_disk_space $((target_swap + 500)) || return 1
    log "${BLUE}创建 ${target_swap}MB Swap...${NC}"
    
    if command -v fallocate &>/dev/null; then fallocate -l "${target_swap}M" /swapfile
    else dd if=/dev/zero of=/swapfile bs=1M count="$target_swap" status=none; fi
    
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
    log "${GREEN}✅ Swap已启用${NC}"
}

configure_ssh() {
    log "\n${YELLOW}=============== 7. SSH 配置 ===============${NC}"
    local config="/etc/ssh/sshd_config"
    cp "$config" "$config.bak.$(date +%F)"

    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:$NEW_SSH_PASSWORD" | chpasswd
        log "${GREEN}✅ Root密码已修改${NC}"
    fi

    if [[ -n "$NEW_SSH_PORT" ]]; then
        sed -i '/^#\?Port /d' "$config"
        echo "Port $NEW_SSH_PORT" >> "$config"
        log "${GREEN}✅ SSH端口改为: $NEW_SSH_PORT${NC}"
    fi

    sed -i '/^#\?PermitRootLogin /d' "$config"
    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "PermitRootLogin yes" >> "$config"
        sed -i '/^#\?PasswordAuthentication /d' "$config"
        echo "PasswordAuthentication yes" >> "$config"
    else
        echo "PermitRootLogin prohibit-password" >> "$config"
    fi

    systemctl restart sshd
}

configure_fail2ban() {
    [[ "$ENABLE_FAIL2BAN" != true ]] && return
    log "\n${YELLOW}=============== 8. Fail2ban ===============${NC}"
    wait_for_apt_locks
    if ! command -v fail2ban-client &>/dev/null; then
        start_spinner "安装 Fail2ban... "
        DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1
        stop_spinner
    fi
    
    local ssh_port=${NEW_SSH_PORT:-22}
    if [[ -z "$NEW_SSH_PORT" ]]; then
        ssh_port=$(grep -oP '^Port \K\d+' /etc/ssh/sshd_config | tail -n1 || echo 22)
    fi
    
    local port_list="$ssh_port"
    if [[ -n "$FAIL2BAN_EXTRA_PORT" && "$FAIL2BAN_EXTRA_PORT" != "$ssh_port" ]]; then
        port_list="$ssh_port,$FAIL2BAN_EXTRA_PORT"
    fi
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = $port_list
backend = systemd
EOF
    systemctl restart fail2ban >/dev/null 2>&1
    log "${GREEN}✅ Fail2ban 保护端口: $port_list${NC}"
}

system_update() {
    log "\n${YELLOW}=============== 9. 系统更新 ===============${NC}"
    wait_for_apt_locks
    start_spinner "系统升级中... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >/dev/null 2>&1
    apt-get autoremove -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    stop_spinner
    log "${GREEN}✅ 系统已更新${NC}"
}

# ==============================================================================
# --- 主程序 ---
# ==============================================================================

main() {
    trap 'handle_error ${LINENO}' ERR
    parse_args "$@"
    
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${CYAN}   VPS 初始化脚本 v8.1.1 (Stable)               ${NC}"
    echo -e "${CYAN}==================================================${NC}"

    if [[ "$non_interactive" == false ]]; then
        read -p "确认开始? [y/N] " -r < /dev/tty
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0
    fi
    
    LOG_FILE="/var/log/vps-init.log"
    echo "Starting at $(date)" > "$LOG_FILE"
    
    pre_flight_checks
    configure_locale
    install_packages
    configure_hostname
    configure_time_sync
    configure_network
    configure_dns
    configure_swap
    configure_ssh
    configure_fail2ban
    system_update
    
    run_verification
    
    log "\n${GREEN}🎉 初始化完成! 正在重启...${NC}"
    
    # 移除错误捕获，防止重启命令本身返回非零值导致误报
    trap - ERR

    if [[ "$non_interactive" == true ]]; then
        reboot || log "${YELLOW}[WARN] 无法自动重启，请手动执行 'reboot'。${NC}"
    elif [[ "$non_interactive" == false ]]; then
        read -p "立即重启? [y/N] " -r < /dev/tty
        [[ "$REPLY" =~ ^[Yy]$ ]] && { reboot || log "${YELLOW}[WARN] 无法自动重启。${NC}"; }
    fi
    
    exit 0
}

main "$@"
