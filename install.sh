#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: 7.9.18
# - [重构] 拆分 BBR 参数档位、显示、写入与验证逻辑
# - [输出] 最终验证显示 BBR 关键运行时参数
# - [界面] 统一部分警告输出样式
# ==============================================================================
set -euo pipefail

# --- 默认配置 ---
SCRIPT_VERSION="7.9.18"
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
SWAP_SIZE_MB="auto"
INSTALL_PACKAGES="sudo wget zip vim curl"
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
BBR_MODE="default"
ENABLE_FAIL2BAN=true
FAIL2BAN_EXTRA_PORT=""
# --- SSH 相关配置 ---
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

log() {
    echo -e "$1"
}

result_warn() {
    log "${YELLOW}  ⚠ $1${NC}"
}

section_header() {
    local number="$1" title="$2"
    log "\n${YELLOW}╭──────────────────────────────────────────────╮${NC}"
    log "${YELLOW}│  ${number}. ${title}${NC}"
    log "${YELLOW}╰──────────────────────────────────────────────╯${NC}"
}

step_info() {
    log "${BLUE}  ▸ $1${NC}"
}

result_ok() {
    log "${GREEN}  ✔ $1${NC}"
}


handle_error() {
    local exit_code=$? line_number=$1
    # [FIX] 增加 2>/dev/null || true 确保 tput 失败时不会再次触发错误
    command -v tput >/dev/null 2>&1 && tput cnorm 2>/dev/null || true
    local error_message="\n${RED}[ERROR] 脚本在第 ${line_number} 行失败 (退出码: ${exit_code})${NC}"
    echo -e "$error_message"
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] Script failed at line ${line_number} (exit code: ${exit_code})" >> "$LOG_FILE"
    [[ $spinner_pid -ne 0 ]] && kill "$spinner_pid" 2>/dev/null
    exit "$exit_code"
}

start_spinner() {
    # 如果 tput 不可用或非 TTY，则不显示 spinner
    if ! command -v tput >/dev/null 2>&1 || [[ ! -t 1 ]]; then
        echo -e "${CYAN}${1:-}${NC}"
        return
    fi
    echo -n -e "${CYAN}${1:-}${NC}"
    ( while :; do for c in '/' '-' '\' '|'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
    spinner_pid=$!
    # [FIX] 增加 2>/dev/null || true 防止 'tput civis' 失败时终止脚本
    tput civis 2>/dev/null || true
}

stop_spinner() {
    if [[ $spinner_pid -ne 0 ]]; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null || true
        spinner_pid=0
    fi
    # [FIX] 增加 2>/dev/null || true
    if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
        tput cnorm 2>/dev/null || true
        echo -e "\b${GREEN}✔${NC}"
    else
        echo -e "${GREEN}✔${NC}"
    fi
}

show_progress() {
    local current=$1 total=$2 width=40
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    printf "\r["
    printf "%*s" $filled | tr ' ' '='
    printf "%*s" $empty | tr ' ' '-'
    printf "] %d%%" $percent
}

get_public_ipv4() {
    local ip url octet valid
    for url in "https://api.ipify.org" "https://ip.sb"; do
        if command -v curl >/dev/null 2>&1; then
            ip=$(curl -fsS4 --max-time 5 "$url" 2>/dev/null) || continue
        elif command -v wget >/dev/null 2>&1; then
            ip=$(wget -qO- -4 --timeout=5 "$url" 2>/dev/null) || continue
        else
            return 1
        fi
        ip=${ip//[[:space:]]/}
        valid=true
        if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            IFS=. read -ra octets <<< "$ip"
            for octet in "${octets[@]}"; do
                [[ "$octet" -le 255 ]] || valid=false
            done
            [[ "$valid" == true ]] && { echo "$ip"; return 0; }
        fi
    done
    return 1
}

has_ipv6() {
    if ip -6 route show default 2>/dev/null | grep -q 'default' || ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'; then
        return 0
    fi
    if command -v ping &>/dev/null; then
        ping -6 -c 1 -W 3 dns.google >/dev/null 2>&1 && return 0
    fi
    if command -v curl &>/dev/null; then
        curl -6 -s --head --max-time 5 "https://[2606:4700:4700::1111]/" >/dev/null 2>&1 && return 0
    fi
    return 1
}

check_disk_space() {
    local required_mb="$1" available_mb
    available_mb=$(df -BM / | awk 'NR==2 {gsub(/M/,"",$4); print $4}' || echo 0)
    [[ "$available_mb" -eq 0 ]] && { log "${RED}[ERROR] 无法获取可用磁盘空间信息。${NC}"; return 1; }
    if [[ "$available_mb" -lt "$required_mb" ]]; then
        log "${RED}[ERROR] 磁盘空间不足: 需要${required_mb}MB，可用${available_mb}MB${NC}"
        return 1
    fi
}

is_container() {
    case "$(systemd-detect-virt --container 2>/dev/null)" in
        docker|lxc|openvz|containerd|podman) return 0 ;;
    esac
    [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] ||
    grep -q 'container=lxc\|container=docker' /proc/1/environ 2>/dev/null
}

compare_version() {
    printf '%s\n' "$@" | sort -V | head -n1
}

is_kernel_version_ge() {
    local required="$1" current
    current=$(uname -r | grep -oP '^\d+\.\d+' || echo "0.0")
    [[ "$(compare_version "$current" "$required")" = "$required" ]]
}

verify_privileges() {
    local checks=0
    [[ $EUID -eq 0 ]] && checks=$((checks + 1))
    [[ -w /etc/passwd ]] && checks=$((checks + 1))
    [[ $EUID -eq 0 ]] || { groups | grep -qE '\b(sudo|wheel|admin)\b' && checks=$((checks + 1)); }
    if [[ $checks -lt 2 ]]; then
        log "${RED}[ERROR] 权限不足，需要root权限或完整sudo权限${NC}"
        return 1
    fi
    return 0
}

record_verification() {
    local component="$1" status="$2" message="$3"
    case "$status" in
        "PASS") log "    ${GREEN}✓${NC} ${component}: ${message}"; VERIFICATION_PASSED=$((VERIFICATION_PASSED + 1)) ;;
        "WARN") log "    ${YELLOW}⚠${NC} ${component}: ${message}"; VERIFICATION_WARNINGS=$((VERIFICATION_WARNINGS + 1)) ;;
        "FAIL") log "    ${RED}✗${NC} ${component}: ${message}"; VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1)) ;;
    esac
}

verify_config() {
    local component="$1" expected="$2" actual="$3"
    if [[ "$actual" = "$expected" ]]; then
        record_verification "$component" "PASS" "已设置为 '${actual}'"
    else
        record_verification "$component" "FAIL" "期望 '${expected}'，实际 '${actual}'"
    fi
}

verify_bbr() {
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    if [[ "$BBR_MODE" = "none" ]]; then
        [[ "$current_cc" != "bbr" ]] && record_verification "BBR" "PASS" "已禁用" || record_verification "BBR" "WARN" "可能需要重启生效 (当前: ${current_cc})"
    elif [[ "$current_cc" = "bbr" && "$current_qdisc" = "fq" ]]; then
        record_verification "BBR" "PASS" "已启用 (${BBR_MODE}模式)"
    else
        record_verification "BBR" "FAIL" "配置异常: ${current_cc}/${current_qdisc}"
    fi
}

verify_swap() {
    local current_swap_mb=$(awk '/SwapTotal/ {print int($2/1024 + 0.5)}' /proc/meminfo)
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        [[ $current_swap_mb -eq 0 ]] && record_verification "Swap" "PASS" "已禁用" || record_verification "Swap" "FAIL" "期望禁用但仍有${current_swap_mb}MB"
    else
        [[ $current_swap_mb -gt 0 ]] && record_verification "Swap" "PASS" "${current_swap_mb}MB" || record_verification "Swap" "FAIL" "未配置"
    fi
}

verify_dns() {
    local status="FAIL" message="" dns_servers=""
    
    if (systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]); then
        status="WARN"
        message="云环境可能覆盖; "
    fi
    
    if (systemctl is-active --quiet systemd-resolved 2>/dev/null); then
        local conf_file="/etc/systemd/resolved.conf.d/99-custom-dns.conf"
        if [[ -f "$conf_file" ]]; then
            dns_servers=$(grep -E "^\s*DNS=" "$conf_file" | sed -e 's/DNS=//' -e 's/^\s*//' -e 's/\s*$//')
        fi
        message+="systemd-resolved: "
    else
        local conf_file="/etc/resolv.conf"
        if [[ -f "$conf_file" ]]; then
            dns_servers=$(grep -E "^\s*nameserver" "$conf_file" | awk '{print $2}' | paste -sd ' ' -)
        fi
        message+="resolv.conf: "
    fi
    
    if [[ -n "$dns_servers" ]]; then
        [[ "$status" != "WARN" ]] && status="PASS"
        message+="${dns_servers}"
    else
        status="FAIL"
        message+="配置缺失"
    fi
    
    record_verification "DNS" "$status" "$message"
}

verify_time_sync() {
    if (timedatectl status 2>/dev/null | grep -q 'NTP service: active'); then
        record_verification "时间同步" "PASS" "systemd-timesyncd (NTP) 已激活"
    elif (systemctl is-active --quiet systemd-timesyncd 2>/dev/null); then
        record_verification "时间同步" "PASS" "systemd-timesyncd 服务运行中"
    # [FIX] chrony/ntp 是警告，因为用户不想用它们
    elif (systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null); then
        record_verification "时间同步" "WARN" "正在使用第三方NTP (chrony/ntp)"
    else
        record_verification "时间同步" "FAIL" "NTP服务未运行"
    fi
}

run_verification() {
    log "\n${YELLOW}=============== 配置验证 ===============${NC}"
    VERIFICATION_PASSED=0 VERIFICATION_FAILED=0 VERIFICATION_WARNINGS=0
    # 验证时临时关闭 set -e
    set +e
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    verify_config "时区" "$TIMEZONE" "$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    verify_time_sync
    verify_bbr
    [[ "$BBR_MODE" = "optimized" ]] && show_bbr_runtime_details
    verify_swap
    verify_dns
    local installed=0 total=0
    for pkg in $INSTALL_PACKAGES; do
        total=$((total + 1))
        dpkg -l "$pkg" >/dev/null 2>&1 && installed=$((installed + 1))
    done
    [[ $installed -eq $total ]] && record_verification "软件包" "PASS" "全部已安装 ($installed/$total)" || record_verification "软件包" "FAIL" "部分缺失 ($installed/$total)"
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local current_port=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config | tail -n1)
        [[ -z "$current_port" ]] && current_port="22"
        verify_config "SSH端口" "$NEW_SSH_PORT" "$current_port"
    fi
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then
        if (systemctl is-active --quiet fail2ban 2>/dev/null); then
            record_verification "Fail2ban" "PASS" "运行正常"
        else
            record_verification "Fail2ban" "FAIL" "服务异常"
        fi
    fi
    # 恢复 set -e
    set -e
    log "\n${BLUE}验证结果: ${GREEN}通过 ${VERIFICATION_PASSED}${NC}, ${YELLOW}警告 ${VERIFICATION_WARNINGS}${NC}, ${RED}失败 ${VERIFICATION_FAILED}${NC}"
}

usage() {
    cat << EOF
${YELLOW}用法: $0 [选项]${NC}
${BLUE}核心选项:${NC}
  --hostname <name>      设置主机名
  --timezone <tz>        设置时区
  --swap <size_mb>       设置Swap大小，'auto'/'0'
  --ip-dns <'主 备'>      设置IPv4 DNS
  --ip6-dns <'主 备'>     设置IPv6 DNS
${BLUE}BBR选项:${NC}
  --bbr                  启用默认BBR (默认)
  --bbr-optimized        启用优化BBR (高配置)
  --no-bbr               禁用BBR
${BLUE}安全选项:${NC}
  --fail2ban [port]      启用Fail2ban
  --no-fail2ban          禁用Fail2ban
  --ssh-port <port>      设置SSH端口
  --ssh-password <pass> 设置root密码
${BLUE}其他:${NC}
  -h, --help             显示帮助
  --non-interactive      非交互模式
${GREEN}示例: $0 --bbr-optimized --ssh-port 2222${NC}
EOF
    exit 0
}

parse_args() {
    require_value() {
        [[ $# -ge 2 && -n "${2:-}" && "$2" != -* ]] || {
            echo -e "${RED}选项 $1 需要一个参数${NC}" >&2
            exit 2
        }
    }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage ;;
            --hostname) require_value "$@"; NEW_HOSTNAME="$2"; shift 2 ;;
            --timezone)
                require_value "$@"
                if command -v timedatectl >/dev/null 2>&1 && ! timedatectl list-timezones 2>/dev/null | grep -Fxq "$2"; then
                    echo -e "${RED}无效时区: $2${NC}" >&2
                    exit 2
                fi
                TIMEZONE="$2"; shift 2 ;;
            --swap)
                require_value "$@"
                [[ "$2" = "auto" || "$2" =~ ^[0-9]+$ ]] || { echo -e "${RED}--swap 必须是 auto、0 或正整数 MB${NC}" >&2; exit 2; }
                SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns)
                require_value "$@"; read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"
                [[ -n "$PRIMARY_DNS_V4" && -n "$SECONDARY_DNS_V4" ]] || { echo -e "${RED}--ip-dns 需要两个 DNS 地址${NC}" >&2; exit 2; }
                shift 2 ;;
            --ip6-dns)
                require_value "$@"; read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"
                [[ -n "$PRIMARY_DNS_V6" && -n "$SECONDARY_DNS_V6" ]] || { echo -e "${RED}--ip6-dns 需要两个 DNS 地址${NC}" >&2; exit 2; }
                shift 2 ;;
            --bbr) BBR_MODE="default"; shift ;;
            --bbr-optimized) BBR_MODE="optimized"; shift ;;
            --no-bbr) BBR_MODE="none"; shift ;;
            --fail2ban)
                ENABLE_FAIL2BAN=true
                if [[ -n "${2:-}" && ! "$2" =~ ^- ]]; then
                    [[ "$2" =~ ^[0-9]+$ && "$2" -ge 1 && "$2" -le 65535 ]] || { echo -e "${RED}Fail2ban 端口必须是 1-65535 的端口${NC}" >&2; exit 2; }
                    FAIL2BAN_EXTRA_PORT="$2"
                    shift
                fi
                shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --ssh-port)
                require_value "$@"
                [[ "$2" =~ ^[0-9]+$ && "$2" -ge 1 && "$2" -le 65535 ]] || { echo -e "${RED}--ssh-port 必须是 1-65535 的端口${NC}" >&2; exit 2; }
                NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password) require_value "$@"; NEW_SSH_PASSWORD="$2"; shift 2 ;;
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

pre_flight_checks() {
    log "${BLUE}[INFO] 系统预检查...${NC}"
    verify_privileges || exit 1
    if is_container; then
        log "${YELLOW}[WARN] 容器环境，某些功能可能受限${NC}"
        [[ "$non_interactive" = false ]] && { read -p "继续? [y/N] " -r < /dev/tty; [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0; }
    fi
    [[ ! -f /etc/os-release ]] && { log "${RED}错误: 系统信息缺失${NC}"; exit 1; }
    source /etc/os-release
    local supported=false
    [[ "$ID" = "debian" && "$VERSION_ID" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "$ID" = "ubuntu" && "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]] && supported=true
    if [[ "$supported" = "false" ]]; then
        log "${YELLOW}[WARN] 系统: ${PRETTY_NAME} (建议使用Debian 10-13或Ubuntu 20.04-24.04)${NC}"
        [[ "$non_interactive" = false ]] && { read -p "继续? [y/N] " -r < /dev/tty; [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0; }
    fi
    log "${GREEN}✅ 系统: ${PRETTY_NAME}${NC}"
}

install_packages() {
    section_header "1" "软件包安装"
    step_info "更新软件包列表"
    start_spinner "更新软件包列表... "
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG_FILE" 2>&1
    stop_spinner
    step_info "安装基础软件包：${INSTALL_PACKAGES}"
    start_spinner "安装基础软件包... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y $INSTALL_PACKAGES >> "$LOG_FILE" 2>&1
    stop_spinner
    if command -v vim &>/dev/null; then
        cat > /etc/vim/vimrc.local << 'EOF'
syntax on
set nocompatible
set backspace=indent,eol,start
set ruler
set showcmd
set hlsearch
set incsearch
set autoindent
set tabstop=4
set shiftwidth=4
set expandtab
set encoding=utf-8
set mouse=a
set nobackup
set noswapfile
EOF
        [[ -d /root ]] && ! grep -q "source /etc/vim/vimrc.local" /root/.vimrc 2>/dev/null && echo "source /etc/vim/vimrc.local" >> /root/.vimrc
    fi
    result_ok "基础软件包安装完成：${INSTALL_PACKAGES}"
}

configure_hostname() {
    section_header "2" "主机名配置"
    local current_hostname=$(hostname)
    log "${BLUE}  当前主机名：${current_hostname}${NC}"
    local final_hostname="$current_hostname"
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOG_FILE" 2>&1
            final_hostname="$NEW_HOSTNAME"
            log "${GREEN}✅ 主机名设为: ${NEW_HOSTNAME}${NC}"
        else
            log "${RED}[ERROR] 主机名格式错误${NC}"
            NEW_HOSTNAME=""
        fi
    
    # [FIX] 修复非交互模式下的逻辑漏洞
    elif [[ "$non_interactive" = true ]]; then
        local auto_ip
        auto_ip=$(get_public_ipv4) # 先获取
        
        # [FIX] 检查 auto_ip 是否为空
        if [[ -n "$auto_ip" ]]; then 
            final_hostname=$(echo "$auto_ip" | tr '.' '-')
            hostnamectl set-hostname "$final_hostname" >> "$LOG_FILE" 2>&1
            NEW_HOSTNAME="$final_hostname"
            log "${GREEN}✅ 自动设置主机名: ${final_hostname}${NC}"
        else
            log "${YELLOW}[WARN] 无法自动获取公网IP，跳过自动设置主机名。${NC}"
        fi
    elif [[ "$non_interactive" = false ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            read -p "输入新主机名: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name" >> "$LOG_FILE" 2>&1
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"
            fi
        fi
    fi
    if [[ "$final_hostname" != "$current_hostname" ]]; then
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t${final_hostname}/" /etc/hosts
        else
            echo -e "127.0.1.1\t${final_hostname}" >> /etc/hosts
        fi
    fi
}

configure_timezone() {
    section_header "3" "时区配置"
    step_info "设置时区：${TIMEZONE}"
    timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1
    result_ok "时区已设置：${TIMEZONE}"
}

# [修改 v7.9.14] 严格按照 "仅 systemd-timesyncd" 逻辑
configure_time_sync() {
    section_header "4" "时间同步配置"
    
    # 1. 检查 'chrony' 或 'ntp' (如果已安装, 尊重用户)
    if (systemctl is-active --quiet chrony 2>/dev/null || \
       systemctl is-active --quiet ntp 2>/dev/null || \
       systemctl is-active --quiet ntpd 2>/dev/null); then
        log "${YELLOW}[WARN] 检测到已有的NTP服务 (chrony/ntp) 正在运行，跳过。${NC}"
        log "${YELLOW}       (脚本被配置为仅使用 systemd-timesyncd)${NC}"
        return
    fi

    if ! command -v timedatectl >/dev/null 2>&1; then
        log "${RED}[ERROR] 未找到 timedatectl 命令, 无法配置 systemd-timesyncd。${NC}"
        return
    fi

    local timesyncd_enabled=false
    
    # 2. 尝试启用 (如果服务已存在)
    if systemctl cat systemd-timesyncd >/dev/null 2>&1; then
        start_spinner "启用 systemd-timesyncd (NTP)... "
        systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        
        if timedatectl set-ntp true >> "$LOG_FILE" 2>&1; then
            timesyncd_enabled=true
        else
            systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        fi
        stop_spinner
    fi
    
    # 3. 检查是否成功，如果不成功 (或服务不存在)，则尝试安装
    if [ "$timesyncd_enabled" = false ] && ! (systemctl is-active --quiet systemd-timesyncd 2>/dev/null); then
        log "${YELLOW}[WARN] systemd-timesyncd 未运行或不存在，尝试安装...${NC}"
        start_spinner "安装 systemd-timesyncd... "
        DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-timesyncd >> "$LOG_FILE" 2>&1
        stop_spinner

        # 4. 安装后再次尝试启用
        start_spinner "再次尝试启用 systemd-timesyncd... "
        systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        if timedatectl set-ntp true >> "$LOG_FILE" 2>&1; then
             : # 成功
        else
            systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        fi
        stop_spinner
    fi
    
    if timedatectl status 2>/dev/null | grep -q 'NTP service: active' || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        log "${GREEN}✅ 时间同步配置完成${NC}"
    else
        log "${RED}[ERROR] 时间同步配置未生效${NC}"
        return 1
    fi
}

bbr_profile() {
    local mem_mb="$1"
    if [[ "$mem_mb" -ge 4096 ]]; then
        BBR_MEMORY_TIER="4GB+"
        BBR_RMEM_WMEM=67108864
        BBR_SOMAXCONN=65535
    elif [[ "$mem_mb" -ge 1024 ]]; then
        BBR_MEMORY_TIER="1GB-4GB"
        BBR_RMEM_WMEM=33554432
        BBR_SOMAXCONN=32768
    else
        BBR_MEMORY_TIER="<1GB"
        BBR_RMEM_WMEM=16777216
        BBR_SOMAXCONN=16384
    fi
}

show_bbr_plan() {
    log "${BLUE}  内存档位：${BBR_MEMORY_TIER} | 缓冲区：${BBR_RMEM_WMEM} bytes | 连接队列：${BBR_SOMAXCONN}${NC}"
    log "${CYAN}  将写入的 BBR 参数：${NC}"
    log "    net.core.default_qdisc              = fq"
    log "    net.ipv4.tcp_congestion_control      = bbr"
    log "    net.core.rmem_max / wmem_max         = ${BBR_RMEM_WMEM}"
    log "    net.ipv4.tcp_rmem                    = 4096 87380 ${BBR_RMEM_WMEM}"
    log "    net.ipv4.tcp_wmem                    = 4096 65536 ${BBR_RMEM_WMEM}"
    log "    net.core.somaxconn / tcp_syn_backlog = ${BBR_SOMAXCONN}"
    log "    net.core.netdev_max_backlog          = ${BBR_SOMAXCONN}"
    log "    tcp_fin_timeout / tw_reuse           = 30 / 1"
    log "    tcp_slow_start_after_idle            = 0"
    log "    ip_local_port_range                  = 10000 65535"
    log "    tcp_keepalive_time / intvl / probes  = 600 / 15 / 5"
    log "    tcp_notsent_lowat / mtu_probing      = 16384 / 1"
}

write_optimized_bbr_config() {
    local config_file="$1"
    cat > "$config_file" << EOF
# --- BBR 核心 ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 缓冲区优化 (配合 TCP 读写) ---
net.core.rmem_max = ${BBR_RMEM_WMEM}
net.core.wmem_max = ${BBR_RMEM_WMEM}
net.ipv4.tcp_rmem = 4096 87380 ${BBR_RMEM_WMEM}
net.ipv4.tcp_wmem = 4096 65536 ${BBR_RMEM_WMEM}

# --- 连接队列与积压 ---
net.core.somaxconn = ${BBR_SOMAXCONN}
net.ipv4.tcp_max_syn_backlog = ${BBR_SOMAXCONN}
net.core.netdev_max_backlog = ${BBR_SOMAXCONN}

# --- 连接复用与超时 (关键优化) ---
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 10000 65535

# --- 保活探测 ---
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# --- 其他 ---
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
EOF
}

verify_bbr_runtime() {
    local config_file="$1" current_cc current_qdisc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "")
    if [[ "$current_cc" != "bbr" || "$current_qdisc" != "fq" ]]; then
        log "${RED}[ERROR] BBR 核心参数未生效: ${current_cc}/${current_qdisc}${NC}"
        return 1
    fi
    result_ok "BBR 核心参数已生效：${current_cc} / ${current_qdisc}"
    log "${BLUE}  配置文件：${config_file}${NC}"
}

show_bbr_runtime_details() {
    local key value
    log "${CYAN}  BBR 关键运行时参数：${NC}"
    for key in \
        net.ipv4.tcp_congestion_control \
        net.core.default_qdisc \
        net.ipv4.tcp_tw_reuse \
        net.ipv4.tcp_fin_timeout \
        net.ipv4.tcp_keepalive_time \
        net.ipv4.tcp_keepalive_intvl \
        net.ipv4.tcp_keepalive_probes \
        net.ipv4.tcp_mtu_probing; do
        value=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        log "    ${key} = ${value}"
    done
}

configure_bbr() {
    section_header "5" "BBR 配置（优化版）"
    local config_file="/etc/sysctl.d/99-bbr.conf"
    
    if [[ "$BBR_MODE" = "none" ]]; then
        log "${BLUE}[INFO] BBR 已禁用，将切换拥塞控制为 cubic${NC}"
        cat > "$config_file" << 'EOF'
net.ipv4.tcp_congestion_control = cubic
EOF
        sysctl -w net.ipv4.tcp_congestion_control=cubic >> "$LOG_FILE" 2>&1 || true
        sysctl -p "$config_file" >> "$LOG_FILE" 2>&1 || true
        return
    fi
    
    if ! is_kernel_version_ge "4.9"; then
        log "${RED}[ERROR] 内核版本过低 ($(uname -r))，需要4.9+${NC}"
        return 1
    fi
    
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    log "${BLUE}检测到内存: ${mem_mb}MB${NC}"
    
    case "$BBR_MODE" in
        "optimized")
            log "${BLUE}配置优化BBR (高性能参数)...${NC}"
            
            if [[ $mem_mb -lt 1024 ]]; then
                log "${YELLOW}[WARN] 内存较低，建议使用默认BBR模式${NC}"
            fi
            
            bbr_profile "$mem_mb"
            show_bbr_plan
            write_optimized_bbr_config "$config_file"
            ;;
        *)
            log "${BLUE}配置标准 BBR：仅启用 bbr + fq${NC}"
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
            ;;
    esac
    
    if ! sysctl -p "$config_file" >> "$LOG_FILE" 2>&1; then
        result_warn "部分 BBR 参数不受当前内核支持，将继续验证核心参数"
    fi
    verify_bbr_runtime "$config_file"
}

configure_swap() {
    section_header "6" "Swap 配置"
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        log "${BLUE}  Swap：禁用${NC}"
        local swap_file="/swapfile" active_swap
        while IFS= read -r active_swap; do
            [[ -n "$active_swap" ]] || continue
            if ! swapoff "$active_swap" >> "$LOG_FILE" 2>&1; then
                log "${RED}[ERROR] 无法关闭现有 Swap：${active_swap}，保留原配置。${NC}"
                return 1
            fi
        done < <(swapon --show=NAME --noheadings 2>/dev/null)
        rm -f "$swap_file"
        sed -i -E '\|^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+[^[:space:]]+[[:space:]]+swap([[:space:]]|$)|d' /etc/fstab
        if [[ -n "$(swapon --show=NAME --noheadings 2>/dev/null)" || -e "$swap_file" ]]; then
            log "${RED}[ERROR] Swap 未能完全禁用。${NC}"
            return 1
        fi
        log "${GREEN}  ✔ Swap 已禁用并移除${NC}"
        return 0
    fi
    local swap_mb
    if [[ "$SWAP_SIZE_MB" = "auto" ]]; then
        local mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        if [[ $mem_mb -lt 1024 ]]; then swap_mb=$mem_mb
        elif [[ $mem_mb -lt 4096 ]]; then swap_mb=2048
        else swap_mb=4096; fi
        log "${BLUE}  自动计算目标 Swap：${swap_mb}MB${NC}"
    else
        swap_mb="$SWAP_SIZE_MB"
        log "${BLUE}  指定目标 Swap：${swap_mb}MB${NC}"
    fi
    check_disk_space $((swap_mb + 100)) || return 1
    local swap_file="/swapfile"
    # 使用唯一临时路径，避免上次中断遗留的 active swap 阻塞本次运行。
    local new_swap="${swap_file}.new.$$"
    # 清理所有旧版本或中断运行遗留的临时 Swap（包括 active 状态）。
    for stale_swap in "${swap_file}.new"*; do
        [[ -e "$stale_swap" ]] || continue
        [[ "$stale_swap" = "$new_swap" ]] && continue
        swapoff "$stale_swap" 2>/dev/null || true
        rm -f "$stale_swap"
        if [[ -e "$stale_swap" ]]; then
            log "${RED}[ERROR] 无法清理遗留的临时 Swap文件: ${stale_swap}${NC}"
            return 1
        fi
    done
    if [[ -f "$swap_file" ]]; then
        local current_size_mb=$(($(stat -c %s "$swap_file" 2>/dev/null || echo 0) / 1024 / 1024))
        if [[ "$current_size_mb" -eq "$swap_mb" ]]; then
            log "${GREEN}  ✔ Swap 文件已存在：${current_size_mb}MB${NC}"
            return
        fi
    fi
    log "${BLUE}创建${swap_mb}MB Swap文件...${NC}"
    # 创建阶段失败时也清理临时文件，避免下次运行留下脏状态。
    if command -v fallocate &>/dev/null; then
        start_spinner "快速创建Swap... "
        if ! fallocate -l "${swap_mb}M" "$new_swap" >> "$LOG_FILE" 2>&1; then
            stop_spinner
            rm -f "$new_swap"
            log "${RED}[ERROR] Swap文件创建失败。${NC}"
            return 1
        fi
        stop_spinner
    else
        log "${BLUE}使用dd创建，请稍候...${NC}"
        if ! dd if=/dev/zero of="$new_swap" bs=1M count="$swap_mb" status=progress 2>&1 | while IFS= read -r line; do
            if [[ "$line" =~ ([0-9]+)\ bytes.*copied ]]; then
                local copied_bytes=${BASH_REMATCH[1]}
                local copied_mb=$((copied_bytes / 1024 / 1024))
                show_progress $copied_mb $swap_mb
            fi
        done
        then
            rm -f "$new_swap"
            log "${RED}[ERROR] Swap文件创建失败。${NC}"
            return 1
        fi
        echo ""
    fi
    chmod 600 "$new_swap"
    if ! mkswap "$new_swap" >> "$LOG_FILE" 2>&1; then
        rm -f "$new_swap"
        log "${RED}[ERROR] Swap格式化失败。${NC}"
        return 1
    fi
    if [[ -f "$swap_file" ]]; then
        if ! swapoff "$swap_file" 2>/dev/null; then
            rm -f "$new_swap"
            log "${RED}[ERROR] 无法关闭现有 Swap，保留原配置。${NC}"
            return 1
        fi
    fi
    # 不能移动仍处于 active 状态的 swap 文件；先关闭旧文件，再替换路径。
    if ! mv -f "$new_swap" "$swap_file"; then
        log "${RED}[ERROR] Swap文件替换失败，未启用新配置。${NC}"
        return 1
    fi
    if ! swapon "$swap_file" >> "$LOG_FILE" 2>&1; then
        log "${RED}[ERROR] 新 Swap 启用失败。${NC}"
        return 1
    fi
    grep -Eq '^[[:space:]]*/swapfile[[:space:]]+' /etc/fstab || echo "$swap_file none swap sw 0 0" >> /etc/fstab
    log "${GREEN}  ✔ Swap 已配置：${swap_mb}MB${NC}"
}

configure_dns() {
    section_header "7" "DNS 配置"
    local ipv6_enabled=false
    has_ipv6 && ipv6_enabled=true
    if (systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]); then
        result_warn "云环境可能覆盖 DNS 配置"
    fi
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d
        local resolved_file="/etc/systemd/resolved.conf.d/99-custom-dns.conf"
        local resolved_tmp="${resolved_file}.vps-setup.$$"
        cat > "$resolved_tmp" << EOF
[Resolve]
DNS=${PRIMARY_DNS_V4} ${SECONDARY_DNS_V4}$( [[ "$ipv6_enabled" == true ]] && echo " ${PRIMARY_DNS_V6} ${SECONDARY_DNS_V6}" )
FallbackDNS=1.0.0.1 8.8.4.4
EOF
        mv -f "$resolved_tmp" "$resolved_file"
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 || log "${YELLOW}[WARN] systemd-resolved 重启失败${NC}"
    else
        log "${BLUE}配置resolv.conf...${NC}"
        if [[ -L /etc/resolv.conf ]]; then
            log "${RED}[ERROR] /etc/resolv.conf 是符号链接，为避免破坏系统 DNS 管理，已停止修改。${NC}"
            return 1
        fi
        cp -a /etc/resolv.conf "/etc/resolv.conf.backup.$(date +%Y%m%d-%H%M%S)" 2>>"$LOG_FILE" || {
            log "${RED}[ERROR] 无法备份 /etc/resolv.conf，已停止修改。${NC}"
            return 1
        }
        chattr -i /etc/resolv.conf 2>/dev/null || true
        local resolv_tmp="/etc/resolv.conf.vps-setup.$$"
        cat > "$resolv_tmp" << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$( [[ "$ipv6_enabled" == true ]] && printf 'nameserver %s\nnameserver %s\n' "$PRIMARY_DNS_V6" "$SECONDARY_DNS_V6" )
EOF
        mv -f "$resolv_tmp" /etc/resolv.conf
    fi
    result_ok "DNS 配置完成：IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$([ "$ipv6_enabled" = true ] && echo "，IPv6 已启用")"
}

configure_ssh() {
    section_header "8" "SSH 配置"

    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]] && ! dpkg -l openssh-server >/dev/null 2>&1; then
        start_spinner "安装 openssh-server... "
        DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
        stop_spinner
    fi
    
    [[ -z "$NEW_SSH_PORT" ]] && [[ "$non_interactive" = false ]] && { read -p "SSH端口 (留空跳过): " -r NEW_SSH_PORT < /dev/tty; }
    
    if [[ -z "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = false ]]; then
        read -s -p "root密码 (输入时不可见, 留空跳过): " NEW_SSH_PASSWORD < /dev/tty
        echo
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}[SECURITY WARNING] 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi

    local ssh_changed=false ssh_backup=""
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if [[ ! -f /etc/ssh/sshd_config ]] || ! command -v sshd >/dev/null 2>&1; then
            log "${RED}[ERROR] 未找到 SSH 配置或 sshd，无法修改 SSH。${NC}"
            return 1
        fi
    fi
    if [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ && "$NEW_SSH_PORT" -gt 0 && "$NEW_SSH_PORT" -lt 65536 ]]; then
        local current_ssh_port
        current_ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}')
        if [[ " $current_ssh_port " != *" ${NEW_SSH_PORT} "* ]] && ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
            log "${RED}[ERROR] SSH端口 ${NEW_SSH_PORT} 已被其他服务占用，未修改 SSH 配置。${NC}"
            return 1
        fi
        ssh_backup="/etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S).$$"
        cp -a /etc/ssh/sshd_config "$ssh_backup"
        sed -i '/^[#\s]*Port\s\+/d' /etc/ssh/sshd_config
        echo "Port ${NEW_SSH_PORT}" >> /etc/ssh/sshd_config
        ssh_changed=true
        log "${GREEN}✅ SSH端口设为: ${NEW_SSH_PORT}${NC}"
    fi
    
    if [[ "$ssh_changed" = true ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
            if ! systemctl restart sshd >> "$LOG_FILE" 2>&1; then
                log "${RED}[ERROR] SSH 服务重启失败，正在恢复配置。${NC}"
                cp -a "$ssh_backup" /etc/ssh/sshd_config
                systemctl restart sshd >> "$LOG_FILE" 2>&1 || true
                return 1
            fi
            sleep 1
            if ! ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
                log "${RED}[ERROR] SSH 未监听新端口，正在恢复配置。${NC}"
                cp -a "$ssh_backup" /etc/ssh/sshd_config
                systemctl restart sshd >> "$LOG_FILE" 2>&1 || true
                return 1
            fi
            log "${YELLOW}[WARN] SSH端口已更改，请用新端口重连！${NC}"
        else
            log "${RED}[ERROR] SSH配置错误，已恢复备份${NC}"
            cp -a "$ssh_backup" /etc/ssh/sshd_config
            systemctl restart sshd >> "$LOG_FILE" 2>&1 || true
            return 1
        fi
    fi

    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:${NEW_SSH_PASSWORD}" | chpasswd >> "$LOG_FILE" 2>&1
        log "${GREEN}✅ root密码已设置${NC}"
    fi
}

configure_fail2ban() {
    section_header "9" "Fail2ban 配置"
    
    local ports=("22")
    [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] && ports+=("$NEW_SSH_PORT")
    [[ -n "$FAIL2BAN_EXTRA_PORT" && "$FAIL2BAN_EXTRA_PORT" =~ ^[0-9]+$ ]] && ports+=("$FAIL2BAN_EXTRA_PORT")
    
    if [[ "$non_interactive" = true && -z "$NEW_SSH_PORT" && -f /etc/ssh/sshd_config ]]; then
        local detected_port=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config | tail -n1)
        [[ -n "$detected_port" ]] && ports+=("$detected_port")
    fi
    
    local port_list=$(printf "%s\n" "${ports[@]}" | sort -un | tr '\n' ',' | sed 's/,$//')
    
    start_spinner "安装Fail2ban... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >> "$LOG_FILE" 2>&1
    stop_spinner
    
    local jail_file="/etc/fail2ban/jail.local" jail_tmp="/etc/fail2ban/jail.local.vps-setup.$$"
    local jail_backup=""
    [[ -f "$jail_file" ]] && jail_backup="${jail_file}.backup.$(date +%Y%m%d-%H%M%S).$$" && cp -a "$jail_file" "$jail_backup"
    cat > "$jail_tmp" << EOF
[DEFAULT]
# 永久封禁：输错 SSH 密码达到 maxretry 后，来源 IP 不会自动解封。
bantime = -1
findtime = 300
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8

[sshd]
enabled = true
port = ${port_list}
maxretry = 3
EOF
    mv -f "$jail_tmp" "$jail_file"
    if ! fail2ban-client -t >> "$LOG_FILE" 2>&1; then
        log "${RED}[ERROR] Fail2ban 配置校验失败${NC}"
        if [[ -n "$jail_backup" ]]; then
            cp -a "$jail_backup" "$jail_file"
        else
            rm -f "$jail_file"
        fi
        return 1
    fi
    
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl restart fail2ban >> "$LOG_FILE" 2>&1
    
    if (systemctl is-active --quiet fail2ban); then
        result_ok "Fail2ban 已启动，保护端口：${port_list}"
    else
        log "${RED}[ERROR] Fail2ban启动失败${NC}"
        return 1
    fi
}

system_update() {
    section_header "10" "系统更新与清理"
    start_spinner "系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
    stop_spinner
    start_spinner "清理缓存... "
    apt-get autoremove --purge -y >> "$LOG_FILE" 2>&1
    apt-get clean >> "$LOG_FILE" 2>&1
    stop_spinner
    result_ok "系统更新与清理完成"
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================
main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要root权限${NC}"; exit 1; }
    
    parse_args "$@"

    section_header "配置摘要" "VPS 初始化配置"
    log "${CYAN}  当前配置摘要：${NC}"
    log "    主机名：${NEW_HOSTNAME:-保持当前/交互}"
    log "    时区：${TIMEZONE}"
    log "    BBR：${BBR_MODE}"
    log "    Swap：${SWAP_SIZE_MB}"
    log "    DNS：${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}"
    log "    Fail2ban：${ENABLE_FAIL2BAN}"
    [[ -n "$NEW_SSH_PORT" ]] && log "    SSH 端口：${NEW_SSH_PORT}"

    if [[ "$non_interactive" = false ]]; then
        read -p "开始配置? [Y/n] " -r < /dev/tty
        [[ "$REPLY" =~ ^[Nn]$ ]] && exit 0
    fi
    
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    echo "VPS Init Log - $(date)" > "$LOG_FILE"
    
    log "\n${BLUE}开始执行配置...${NC}"
    SECONDS=0
    
    pre_flight_checks
    install_packages
    configure_hostname
    configure_timezone
    configure_time_sync
    configure_bbr
    configure_swap
    configure_dns
    
    configure_ssh
    [[ "$ENABLE_FAIL2BAN" = true ]] && configure_fail2ban
    system_update
    
    run_verification
    
    log "\n${YELLOW}==================== 完成 ====================${NC}"
    log "${GREEN}🎉 VPS初始化完成！${NC}"
    log "执行时间: ${SECONDS}秒"
    log "日志文件: ${LOG_FILE}"
    
    if [[ -n "$NEW_SSH_PORT" ]]; then
        log "\n${RED}⚠️  SSH端口已改为 ${NEW_SSH_PORT}，请用新端口重连！${NC}"
    fi
    
    if is_container; then
        log "\n${BLUE}容器环境，配置已生效${NC}"
    else
        log "\n${BLUE}建议重启以确保所有配置生效${NC}"
        if [[ "$non_interactive" = false ]]; then
            read -p "立即重启? [Y/n] " -r < /dev/tty
            [[ ! "$REPLY" =~ ^[Nn]$ ]] && { log "${BLUE}重启中...${NC}"; sleep 2; reboot; }
        fi
    fi
    
    [[ $VERIFICATION_FAILED -eq 0 ]] && exit 0 || exit 1
}

main "$@"
