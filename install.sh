#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: 7.9.5
# ------------------------------------------------------------------------------
# 改进日志:
# - [调整] BBR逻辑变更：默认启BBR，--bbr-optimized 启用优化BBR
# - [增强] DNS验证结果现在会显示具体的IPv4和IPv6 DNS地址
# - [安全] 加固命令行密码处理，交互模式下隐藏输入并对非交互模式告警
# - [健壮] SSH端口配置实现幂等性，防止重复配置
# - [健壮] Fail2ban端口列表自动去重
# - [修复] 增强IPv6网络检测的可靠性
# ==============================================================================
set -euo pipefail

# --- 默认配置 ---
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

# ==============================================================================
# --- 核心辅助函数 ---
# ==============================================================================

log() {
    echo -e "$1"
}

handle_error() {
    local exit_code=$? line_number=$1
    tput cnorm
    local error_message="\n${RED}[ERROR] 脚本在第 ${line_number} 行失败 (退出码: ${exit_code})${NC}"
    echo -e "$error_message"
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] Script failed at line ${line_number} (exit code: ${exit_code})" >> "$LOG_FILE"
    [[ $spinner_pid -ne 0 ]] && kill "$spinner_pid" 2>/dev/null
    exit "$exit_code"
}

start_spinner() {
    if [[ ! -t 1 ]]; then return; fi
    echo -n -e "${CYAN}${1:-}${NC}"
    ( while :; do for c in '/' '-' '\' '|'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
    spinner_pid=$!
    tput civis
}

stop_spinner() {
    if [[ $spinner_pid -ne 0 ]]; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null || true
        spinner_pid=0
    fi
    if [[ ! -t 1 ]]; then return; fi
    tput cnorm
    echo -e "\b${GREEN}✔${NC}"
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
    local ip
    for cmd in "curl -s -4 --max-time 5" "wget -qO- -4 --timeout=5"; do
        for url in "https://api.ipify.org" "https://ip.sb"; do
            ip=$($cmd "$url" 2>/dev/null) && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && echo "$ip" && return
        done
    done
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
    [[ $EUID -eq 0 ]] && ((checks++))
    [[ -w /etc/passwd ]] && ((checks++))
    [[ $EUID -eq 0 ]] || groups | grep -qE '\b(sudo|wheel|admin)\b' && ((checks++))
    if [[ $checks -lt 2 ]]; then
        log "${RED}[ERROR] 权限不足，需要root权限或完整sudo权限${NC}"
        return 1
    fi
    return 0
}

# ==============================================================================
# --- 改进的验证函数 ---
# ==============================================================================

record_verification() {
    local component="$1" status="$2" message="$3"
    case "$status" in
        "PASS") log "    ${GREEN}✓${NC} ${component}: ${message}"; ((VERIFICATION_PASSED++)) ;;
        "WARN") log "    ${YELLOW}⚠${NC} ${component}: ${message}"; ((VERIFICATION_WARNINGS++)) ;;
        "FAIL") log "    ${RED}✗${NC} ${component}: ${message}"; ((VERIFICATION_FAILED++)) ;;
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

# --- [已修改] 增强的DNS验证函数 ---
verify_dns() {
    local status="FAIL" message="" dns_servers=""
    
    if systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]; then
        status="WARN"
        message="云环境可能覆盖; "
    fi
    
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
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

run_verification() {
    log "\n${YELLOW}=============== 配置验证 ===============${NC}"
    VERIFICATION_PASSED=0 VERIFICATION_FAILED=0 VERIFICATION_WARNINGS=0
    set +e
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    verify_config "时区" "$TIMEZONE" "$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    verify_bbr
    verify_swap
    verify_dns
    local installed=0 total=0
    for pkg in $INSTALL_PACKAGES; do ((total++)); dpkg -l "$pkg" >/dev/null 2>&1 && ((installed++)); done
    [[ $installed -eq $total ]] && record_verification "软件包" "PASS" "全部已安装 ($installed/$total)" || record_verification "软件包" "FAIL" "部分缺失 ($installed/$total)"
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local current_port=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config | tail -n1)
        [[ -z "$current_port" ]] && current_port="22"
        verify_config "SSH端口" "$NEW_SSH_PORT" "$current_port"
    fi
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            record_verification "Fail2ban" "PASS" "运行正常"
        else
            record_verification "Fail2ban" "FAIL" "服务异常"
        fi
    fi
    set -e
    log "\n${BLUE}验证结果: ${GREEN}通过 ${VERIFICATION_PASSED}${NC}, ${YELLOW}警告 ${VERIFICATION_WARNINGS}${NC}, ${RED}失败 ${VERIFICATION_FAILED}${NC}"
}

# ==============================================================================
# --- 参数解析 ---
# ==============================================================================

usage() {
    cat << EOF
${YELLOW}用法: $0 [选项]${NC}
${BLUE}核心选项:${NC}
  --hostname <name>     设置主机名
  --timezone <tz>       设置时区
  --swap <size_mb>      设置Swap大小，'auto'/'0'
  --ip-dns <'主 备'>     设置IPv4 DNS
  --ip6-dns <'主 备'>    设置IPv6 DNS
${BLUE}BBR选项:${NC}
  --bbr                启用默认BBR (默认)
  --bbr-optimized       启用优化BBR (高配置)
  --no-bbr              禁用BBR
${BLUE}安全选项:${NC}
  --fail2ban [port]     启用Fail2ban
  --no-fail2ban         禁用Fail2ban
  --ssh-port <port>     设置SSH端口
  --ssh-password <pass> 设置root密码
${BLUE}其他:${NC}
  -h, --help            显示帮助
  --non-interactive     非交互模式
${GREEN}示例: $0 --bbr-optimized --ssh-port 2222${NC}
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage ;;
            --hostname) NEW_HOSTNAME="$2"; shift 2 ;;
            --timezone) TIMEZONE="$2"; shift 2 ;;
            --swap) SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns) read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"; shift 2 ;;
            --ip6-dns) read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"; shift 2 ;;
            --bbr) BBR_MODE="default"; shift ;;
            --bbr-optimized) BBR_MODE="optimized"; shift ;;
            --no-bbr) BBR_MODE="none"; shift ;;
            --fail2ban) ENABLE_FAIL2BAN=true; [[ -n "${2:-}" && ! "$2" =~ ^- ]] && { FAIL2BAN_EXTRA_PORT="$2"; shift; }; shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --ssh-port) NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password) NEW_SSH_PASSWORD="$2"; shift 2 ;;
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

# ==============================================================================
# --- 功能函数 ---
# ==============================================================================

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
    log "\n${YELLOW}=============== 1. 软件包安装 ===============${NC}"
    start_spinner "更新软件包列表... "
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG_FILE" 2>&1
    stop_spinner
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
    log "${GREEN}✅ 软件包安装完成${NC}"
}

configure_hostname() {
    log "\n${YELLOW}=============== 2. 主机名配置 ===============${NC}"
    local current_hostname=$(hostname)
    log "${BLUE}当前主机名: ${current_hostname}${NC}"
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
    elif [[ "$non_interactive" = true ]]; then
        local auto_ip
        if auto_ip=$(get_public_ipv4); then
            final_hostname=$(echo "$auto_ip" | tr '.' '-')
            hostnamectl set-hostname "$final_hostname" >> "$LOG_FILE" 2>&1
            NEW_HOSTNAME="$final_hostname"
            log "${GREEN}✅ 自动设置主机名: ${final_hostname}${NC}"
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
    log "\n${YELLOW}=============== 3. 时区配置 ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1
    log "${GREEN}✅ 时区: ${TIMEZONE}${NC}"
}

configure_bbr() {
    log "\n${YELLOW}=============== 4. BBR配置 ===============${NC}"
    local config_file="/etc/sysctl.d/99-bbr.conf"
    if [[ "$BBR_MODE" = "none" ]]; then
        log "${BLUE}[INFO] 跳过BBR配置${NC}"
        rm -f "$config_file"
        sysctl -p >> "$LOG_FILE" 2>&1 || true
        return
  D fi
    if ! is_kernel_version_ge "4.9"; then
        log "${RED}[ERROR] 内核版本过低 ($(uname -r))，需要4.9+${NC}"
        return 1
    fi
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    log "${BLUE}检测到内存: ${mem_mb}MB${NC}"
    case "$BBR_MODE" in
        "optimized")
            log "${BLUE}配置优化BBR...${NC}"
            if [[ $mem_mb -lt 1024 ]]; then
                log "${YELLOW}[WARN] 内存较低，建议使用默认BBR模式${NC}"
            fi
            local rmem_wmem=$((mem_mb > 2048 ? 67108864 : mem_mb > 1024 ? 33554432 : 16777216))
            local somaxconn=$((mem_mb > 2048 ? 32768 : mem_mb > 1024 ? 16384 : 8192))
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = ${rmem_wmem}
net.core.wmem_max = ${rmem_wmem}
net.core.somaxconn = ${somaxconn}
net.ipv4.tcp_max_syn_backlog = ${somaxconn}
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
EOF
            ;;
        *)
            log "${BLUE}配置标准BBR...${NC}"
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
            ;;
    esac
    sysctl -p "$config_file" >> "$LOG_FILE" 2>&1
    log "${GREEN}✅ BBR配置完成${NC}"
}

configure_swap() {
    log "\n${YELLOW}=============== 5. Swap配置 ===============${NC}"
    [[ "$SWAP_SIZE_MB" = "0" ]] && { log "${BLUE}Swap已禁用${NC}"; return; }
    local swap_mb
    if [[ "$SWAP_SIZE_MB" = "auto" ]]; then
        local mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        if [[ $mem_mb -lt 1024 ]]; then swap_mb=$mem_mb
        elif [[ $mem_mb -lt 4096 ]]; then swap_mb=2048
        else swap_mb=4096; fi
        log "${BLUE}自动设置Swap: ${swap_mb}MB${NC}"
    else
        swap_mb="$SWAP_SIZE_MB"
    fi
    check_disk_space $((swap_mb + 100)) || return 1
    local swap_file="/swapfile"
    if [[ -f "$swap_file" ]]; then
        local current_size_mb=$(($(stat -c %s "$swap_file" 2>/dev/null || echo 0) / 1024 / 1024))
        if [[ "$current_size_mb" -eq "$swap_mb" ]]; then
            log "${GREEN}✅ Swap文件已存在 (${current_size_mb}MB)${NC}"
            return
        fi
        swapoff "$swap_file" 2>/dev/null || true
        rm -f "$swap_file"
    fi
    log "${BLUE}创建${swap_mb}MB Swap文件...${NC}"
    if command -v fallocate &>/dev/null; then
        start_spinner "快速创建Swap... "
        fallocate -l "${swap_mb}M" "$swap_file" >> "$LOG_FILE" 2>&1
        stop_spinner
    else
        log "${BLUE}使用dd创建，请稍候...${NC}"
        dd if=/dev/zero of="$swap_file" bs=1M count="$swap_mb" status=progress 2>&1 | while IFS= read -r line; do
            if [[ "$line" =~ ([0-9]+)\ bytes.*copied ]]; then
                local copied_bytes=${BASH_REMATCH[1]}
                local copied_mb=$((copied_bytes / 1024 / 1024))
                show_progress $copied_mb $swap_mb
            fi
        done
        echo ""
D fi
    chmod 600 "$swap_file"
    mkswap "$swap_file" >> "$LOG_FILE" 2>&1
    swapon "$swap_file" >> "$LOG_FILE" 2>&1
    grep -q "$swap_file" /etc/fstab || echo "$swap_file none swap sw 0 0" >> /etc/fstab
    log "${GREEN}✅ ${swap_mb}MB Swap已配置${NC}"
}

configure_dns() {
    log "\n${YELLOW}=============== 6. DNS配置 ===============${NC}"
    if systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]; then
        log "${YELLOW}[WARN] 云环境检测，DNS可能被覆盖${NC}"
    fi
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log "${BLUE}配置systemd-resolved...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << EOF
[Resolve]
DNS=${PRIMARY_DNS_V4} ${SECONDARY_DNS_V4}$(has_ipv6 && echo " ${PRIMARY_DNS_V6} ${SECONDARY_DNS_V6}")
FallbackDNS=1.0.0.1 8.8.4.4
EOF
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1
    else
        log "${BLUE}配置resolv.conf...${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        cat > /etc/resolv.conf << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$(has_ipv6 && echo "nameserver ${PRIMARY_DNS_V6}")
$(has_ipv6 && echo "nameserver ${SECONDARY_DNS_V6}")
EOF
    fi
    log "${GREEN}✅ DNS配置完成${NC}"
}

configure_ssh() {
    log "\n${YELLOW}=============== 7. SSH配置 ===============${NC}"
    
    [[ -z "$NEW_SSH_PORT" ]] && [[ "$non_interactive" = false ]] && { read -p "SSH端口 (留空跳过): " -r NEW_SSH_PORT < /dev/tty; }
    
    if [[ -z "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = false ]]; then
        read -s -p "root密码 (输入时不可见, 留空跳过): " NEW_SSH_PASSWORD < /dev/tty
        echo
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}[SECURITY WARNING] 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi

    local ssh_changed=false
    if [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ && "$NEW_SSH_PORT" -gt 0 && "$NEW_SSH_PORT" -lt 65536 ]]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d)"
        sed -i '/^[#\s]*Port\s\+/d' /etc/ssh/sshd_config
        echo "Port ${NEW_SSH_PORT}" >> /etc/ssh/sshd_config
        ssh_changed=true
        log "${GREEN}✅ SSH端口设为: ${NEW_SSH_PORT}${NC}"
    fi
    
    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:${NEW_SSH_PASSWORD}" | chpasswd >> "$LOG_FILE" 2>&1
        log "${GREEN}✅ root密码已设置${NC}"
    fi
    
    if [[ "$ssh_changed" = true ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
D         systemctl restart sshd >> "$LOG_FILE" 2>&1
            log "${YELLOW}[WARN] SSH端口已更改，请用新端口重连！${NC}"
        else
            log "${RED}[ERROR] SSH配置错误，已恢复备份${NC}"
            cp "/etc/ssh/sshd_config.backup.$(date +%Y%m%d)" /etc/ssh/sshd_config
            systemctl restart sshd >> "$LOG_FILE" 2>&1
        fi
    fi
}

configure_fail2ban() {
    log "\n${YELLOW}=============== 8. Fail2ban配置 ===============${NC}"
    
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
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
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
    
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    systemctl start fail2ban >> "$LOG_FILE" 2>&1
    
    if systemctl is-active --quiet fail2ban; then
        log "${GREEN}✅ Fail2ban已启动，保护端口: ${port_list}${NC}"
    else
        log "${RED}[ERROR] Fail2ban启动失败${NC}"
    fi
}

system_update() {
    log "\n${YELLOW}=============== 9. 系统更新 ===============${NC}"
    start_spinner "系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
    stop_spinner
    start_spinner "清理缓存... "
    apt-get autoremove --purge -y >> "$LOG_FILE" 2>&1
    apt-get clean >> "$LOG_FILE" 2>&1
    stop_spinner
    log "${GREEN}✅ 系统更新完成${NC}"
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================
main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要root权限${NC}"; exit 1; }
    
    parse_args "$@"

    {
        echo -e "${CYAN}==================== VPS初始化 ====================${NC}"
        echo -e "主机名: ${NEW_HOSTNAME:-自动/交互}"
        echo -e "时区: ${TIMEZONE}"
        echo -e "Swap: ${SWAP_SIZE_MB}"
        echo -e "BBR: ${BBR_MODE}"
D     echo -e "DNS: ${PRIMARY_DNS_V4}, ${SECONDARY_DNS_V4}"
        echo -e "Fail2ban: ${ENABLE_FAIL2BAN}"
        [[ -n "$NEW_SSH_PORT" ]] && echo -e "SSH端口: ${NEW_SSH_PORT}"
        echo -e "${CYAN}===================================================${NC}"
    } >&2

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
    configure_bbr
    configure_swap
    configure_dns
    
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if ! dpkg -l openssh-server >/dev/null 2>&1; then
            start_spinner "安装openssh-server... "
            DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
            stop_spinner
        fi
    fi
    
    configure_ssh
    [[ "$ENABLE_FAIL2BAN" = true ]] && configure_fail2ban
D system_update
    
    run_verification
    
    log "\n${YELLOW}==================== 完成 ====================${NC}"
    log "${GREEN}🎉 VPS初始化完成！${NC}"
    log "执行时间: ${SECONDS}秒"
    log "日志文件: ${LOG_FILE}"
    
    if [[ -n "$NEW_SSH_PORT" ]]; then
        log "\n${RED}⚠️  SSH端口已改为 ${NEW_SSH_PORT}，请用新端口重连！${NC}"
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
