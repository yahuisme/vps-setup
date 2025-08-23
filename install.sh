#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本
# 版本: 6.2-final
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
ENABLE_FAIL2BAN=true #
FAIL2BAN_EXTRA_PORT=""

# --- 颜色和全局变量 ---
readonly GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'

non_interactive=false
spinner_pid=0
LOG_FILE=""
VERIFICATION_PASSED=0
VERIFICATION_FAILED=0

# ==============================================================================
# --- 核心辅助函数 ---
# ==============================================================================

# 错误处理
handle_error() {
    local exit_code=$? line_number=$1
    tput cnorm
    echo -e "\n${RED}[ERROR] 脚本在第 $line_number 行失败 (退出码: $exit_code)${NC}"
    [[ -n "$LOG_FILE" ]] && echo -e "${RED}完整日志: ${LOG_FILE}${NC}"
    [[ $spinner_pid -ne 0 ]] && kill $spinner_pid 2>/dev/null
    exit $exit_code
}

# Spinner 控制
start_spinner() {
    [[ ! -t 1 || "$non_interactive" = true ]] && return
    echo -n -e "${CYAN}${1:-}${NC}"
    ( while :; do for c in '/' '-' '\' '|'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
    spinner_pid=$!
    tput civis
}

stop_spinner() {
    [[ $spinner_pid -ne 0 ]] && { kill $spinner_pid 2>/dev/null; wait $spinner_pid 2>/dev/null || true; spinner_pid=0; }
    tput cnorm
    echo -e "\b${GREEN}✔${NC}"
}

# 系统信息获取
get_public_ipv4() {
    local ip
    for cmd in "curl -s -4 --max-time 5" "wget -qO- -4 --timeout=5"; do
        for url in "https://api.ipify.org" "https://ip.sb"; do
            ip=$($cmd $url 2>/dev/null) && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && echo "$ip" && return
        done
    done
}

has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' || ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'
}

check_disk_space() {
    local required_mb=$1 available_mb
    available_mb=$(df / | awk 'NR==2 {print int($4/1024)}')
    [[ $available_mb -lt $required_mb ]] && { echo -e "${RED}[ERROR] 磁盘空间不足: 需要${required_mb}MB，可用${available_mb}MB${NC}"; return 1; }
}

# ==============================================================================
# --- 验证函数 ---
# ==============================================================================

record_verification() {
    local component="$1" status="$2" message="$3"
    if [[ "$status" = "PASS" ]]; then
        echo -e "    ${GREEN}✓${NC} $component: $message"
        ((VERIFICATION_PASSED++))
    elif [[ "$status" = "WARN" ]]; then
        echo -e "    ${YELLOW}⚠️${NC} $component: $message"
    else
        echo -e "    ${RED}✗${NC} $component: $message"
        ((VERIFICATION_FAILED++))
    fi
}

verify_config() {
    local component="$1" expected="$2" actual="$3" extra="${4:-}"
    if [[ "$actual" = "$expected" ]]; then
        record_verification "$component" "PASS" "已设置为 '$actual' $extra"
    else
        record_verification "$component" "FAIL" "期望 '$expected'，实际 '$actual'"
    fi
}

run_verification() {
    echo -e "\n${YELLOW}=============== 配置验证 ===============${NC}"
    echo -e "${BLUE}[INFO] 正在验证所有配置...${NC}\n"
    
    VERIFICATION_PASSED=0
    VERIFICATION_FAILED=0
    set +e
    
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    
    verify_config "时区" "$TIMEZONE" "$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    if [[ "$BBR_MODE" = "none" ]]; then
        record_verification "BBR" "PASS" "已禁用 (当前: $current_cc)"
    elif [[ "$current_cc" = "bbr" && "$current_qdisc" = "fq" ]]; then
        local mode_desc="标准模式"
        [[ "$BBR_MODE" = "optimized" && -f /etc/sysctl.d/99-bbr.conf && $(grep -c "^net\." /etc/sysctl.d/99-bbr.conf 2>/dev/null) -gt 5 ]] && mode_desc="动态优化模式"
        record_verification "BBR" "PASS" "$mode_desc 已启用"
    else
        record_verification "BBR" "FAIL" "BBR配置异常: $current_cc/$current_qdisc"
    fi
    
    local current_swap_mb=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        [[ $current_swap_mb -eq 0 ]] && record_verification "Swap" "PASS" "已禁用" || record_verification "Swap" "FAIL" "期望禁用，实际${current_swap_mb}MB"
    else
        [[ $current_swap_mb -gt 0 ]] && record_verification "Swap" "PASS" "${current_swap_mb}MB" || record_verification "Swap" "FAIL" "Swap未配置"
    fi
    
    local dns_warning_msg="配置未生效 (云服务器常见现象，因其自动化服务会覆盖此配置)"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        [[ -f /etc/systemd/resolved.conf.d/99-custom-dns.conf && "$(cat /etc/systemd/resolved.conf.d/99-custom-dns.conf 2>/dev/null)" =~ $PRIMARY_DNS_V4 ]] && record_verification "DNS" "PASS" "systemd-resolved已配置" || record_verification "DNS" "WARN" "systemd-resolved ${dns_warning_msg}"
    else
        [[ -f /etc/resolv.conf && "$(cat /etc/resolv.conf 2>/dev/null)" =~ $PRIMARY_DNS_V4 ]] && record_verification "DNS" "PASS" "resolv.conf已配置" || record_verification "DNS" "WARN" "resolv.conf ${dns_warning_msg}"
    fi
    
    local installed=0 total=0
    for pkg in $INSTALL_PACKAGES; do ((total++)); dpkg -l "$pkg" >/dev/null 2>&1 && ((installed++)); done
    [[ $installed -eq $total ]] && record_verification "软件包" "PASS" "全部已安装 ($installed/$total)" || record_verification "软件包" "FAIL" "部分未安装 ($installed/$total)"
    
    [[ "$ENABLE_FAIL2BAN" = true ]] && {
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            record_verification "Fail2ban" "PASS" "运行正常，保护端口: $(grep -oP 'port\s*=\s*\K[0-9,]+' /etc/fail2ban/jail.local 2>/dev/null || echo "N/A")"
        else
            record_verification "Fail2ban" "FAIL" "服务异常"
        fi
    }
    
    set -e
    
    echo -e "\n${BLUE}[INFO] 验证完成: ${GREEN}通过 $VERIFICATION_PASSED${NC}, ${RED}失败 $VERIFICATION_FAILED${NC}"
    [[ $VERIFICATION_FAILED -eq 0 ]] && echo -e "${GREEN}✅ 所有配置验证通过！${NC}" || echo -e "${YELLOW}⚠️ 有 $VERIFICATION_FAILED 项需要检查${NC}"
}

# ==============================================================================
# --- 参数解析 ---
# ==============================================================================

usage() {
    cat << EOF
${YELLOW}用法: $0 [选项]...${NC}
${BLUE}核心选项:${NC}
  --hostname <name>     设置新的主机名
  --timezone <tz>       设置时区 (默认: 自动检测)
  --swap <size_mb>      设置 Swap 大小，'auto'/'0'
  --ip-dns <'主 备'>    设置 IPv4 DNS
  --ip6-dns <'主 备'>   设置 IPv6 DNS
${BLUE}BBR 选项:${NC}
  --bbr-optimized       启用动态优化 BBR
  --no-bbr              禁用 BBR
${BLUE}安全选项:${NC}
  --fail2ban [port]     (默认启用) 指定额外SSH保护端口
  --no-fail2ban         禁用 Fail2ban
${BLUE}其他:${NC}
  -h, --help            显示帮助
  --non-interactive     非交互模式
${GREEN}示例: bash $0 --no-fail2ban --swap 0${NC}
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help) usage ;;
            --hostname) NEW_HOSTNAME="$2"; shift 2 ;;
            --timezone) TIMEZONE="$2"; shift 2 ;;
            --swap) SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns) read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"; shift 2 ;;
            --ip6-dns) read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"; shift 2 ;;
            --bbr-optimized) BBR_MODE="optimized"; shift ;;
            --no-bbr) BBR_MODE="none"; shift ;;
            --fail2ban)
                ENABLE_FAIL2BAN=true
                [[ -n "${2:-}" && ! "$2" =~ ^- ]] && { FAIL2BAN_EXTRA_PORT="$2"; shift; }
                shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;; # <-- 新增
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

# ==============================================================================
# --- 功能函数 (按执行顺序排列) ---
# ==============================================================================

pre_flight_checks() {
    echo -e "${BLUE}[INFO] 系统预检查...${NC}"
    [[ ! -f /etc/os-release ]] && { echo "错误: /etc/os-release 未找到"; exit 1; }
    source /etc/os-release
    
    local supported=false
    [[ "$ID" = "debian" && "$VERSION_ID" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "$ID" = "ubuntu" && "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]] && supported=true
    
    if [[ "$supported" = "false" ]]; then
        echo -e "${YELLOW}[WARN] 当前系统: $PRETTY_NAME (建议使用 Debian 10-13 或 Ubuntu 20.04-24.04)${NC}"
        if [[ "$non_interactive" = "false" ]]; then
            read -p "继续? [y/N] " -r < /dev/tty
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
        fi
    fi
    echo -e "${GREEN}✅ 系统: $PRETTY_NAME${NC}"
}

install_packages() {
    echo -e "\n${YELLOW}=============== 1. 软件包安装 ===============${NC}"
    
    start_spinner "更新软件包列表... "
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || { stop_spinner; echo -e "${RED}更新失败${NC}"; return 1; }
    stop_spinner
    
    start_spinner "安装基础软件包... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y $INSTALL_PACKAGES >/dev/null 2>&1 || { stop_spinner; echo -e "${YELLOW}部分安装失败${NC}"; }
    stop_spinner
    
    if command -v vim &>/dev/null; then
        echo -e "${BLUE}配置 Vim...${NC}"
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
        [[ -d /root ]] && echo "source /etc/vim/vimrc.local" >> /root/.vimrc 2>/dev/null || true
    fi
    echo -e "${GREEN}✅ 软件包安装与配置完成${NC}"
}

configure_hostname() {
    echo -e "\n${YELLOW}=============== 2. 主机名配置 ===============${NC}"
    local current_hostname=$(hostname)
    echo -e "${BLUE}当前主机名: $current_hostname${NC}"
    local final_hostname="$current_hostname"
    
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME"
            final_hostname="$NEW_HOSTNAME"
            echo -e "${BLUE}[INFO] 主机名设为: $NEW_HOSTNAME${NC}"
        else
            echo -e "${RED}[ERROR] 主机名格式不正确，保持不变${NC}"
            NEW_HOSTNAME=""
        fi
    elif [[ "$non_interactive" = "true" && -n "$(get_public_ipv4)" ]]; then
        final_hostname="$(get_public_ipv4 | tr '.' '-')"
        hostnamectl set-hostname "$final_hostname"
        NEW_HOSTNAME="$final_hostname"
        echo -e "${GREEN}自动设置主机名: $final_hostname${NC}"
    elif [[ "$non_interactive" = "false" ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "输入新主机名: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name"
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"
            fi
        fi
    fi
    
    if [[ "$final_hostname" != "$current_hostname" ]]; then
        sed -i "/^127\.0\.1\.1/d" /etc/hosts
        echo -e "127.0.1.1\t$final_hostname" >> /etc/hosts
    fi
    echo -e "${GREEN}✅ 主机名: $(hostname)${NC}"
}

configure_timezone() {
    echo -e "\n${YELLOW}=============== 3. 时区配置 ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null && echo -e "${GREEN}✅ 时区: $TIMEZONE${NC}"
}

configure_bbr() {
    echo -e "\n${YELLOW}=============== 4. BBR配置 ===============${NC}"
    
    local config_file="/etc/sysctl.d/99-bbr.conf"
    
    if [[ "$BBR_MODE" = "none" ]]; then
        echo -e "${BLUE}[INFO] 根据参数跳过 BBR 配置${NC}"
        rm -f "$config_file"
        return
    fi
    
    if [[ "$BBR_MODE" = "optimized" ]]; then
        local kernel_major=$(uname -r | cut -d. -f1)
        local kernel_minor=$(uname -r | cut -d. -f2)
        if (( kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 9) )); then
            echo -e "${BLUE}[INFO] 配置动态优化 BBR...${NC}"
            local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
            local somaxconn=$(( mem_mb > 2048 ? 65535 : (mem_mb > 1024 ? 49152 : 32768) ))
            local rmem_wmem_max=$(( mem_mb > 2048 ? 67108864 : (mem_mb > 1024 ? 33554432 : (mem_mb > 512 ? 16777216 : 8388608)) ))
            
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = $rmem_wmem_max
net.core.wmem_max = $rmem_wmem_max
net.core.somaxconn = $somaxconn
net.ipv4.tcp_max_syn_backlog = $somaxconn
net.ipv4.tcp_fin_timeout = 15
EOF
            sysctl --system >/dev/null 2>&1
            echo -e "${GREEN}✅ 动态优化 BBR 已启用${NC}"
            return
        else
             echo -e "${RED}内核版本过低，使用标准BBR${NC}"
        fi
    fi
    
    echo -e "${BLUE}[INFO] 配置标准 BBR...${NC}"
    echo -e "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" > "$config_file"
    sysctl -p "$config_file" >/dev/null 2>&1
    echo -e "${GREEN}✅ 标准 BBR 已启用${NC}"
}

configure_swap() {
    echo -e "\n${YELLOW}=============== 5. Swap配置 ===============${NC}"
    
    [[ "$SWAP_SIZE_MB" = "0" ]] && { echo -e "${BLUE}Swap已禁用${NC}"; return; }
    [[ $(swapon --show) ]] && { echo -e "${BLUE}Swap已存在，跳过${NC}"; return; }
    
    local swap_mb
    if [[ "$SWAP_SIZE_MB" = "auto" ]]; then
        local mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        swap_mb=$((mem_mb < 2048 ? mem_mb : 2048))
        echo -e "${BLUE}自动设置 Swap: ${swap_mb}MB${NC}"
    else
        swap_mb=$SWAP_SIZE_MB
    fi
    
    check_disk_space $((swap_mb + 100)) || return 1
    
    echo -e "${BLUE}正在创建 ${swap_mb}MB Swap...${NC}"
    fallocate -l "${swap_mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$swap_mb" status=none
    chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
    grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
    echo -e "${GREEN}✅ ${swap_mb}MB Swap 已配置${NC}"
}

configure_dns() {
    echo -e "\n${YELLOW}=============== 6. DNS配置 ===============${NC}"
    
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${BLUE}配置 systemd-resolved...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        {
            echo "[Resolve]"
            echo "DNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4"
            has_ipv6 && echo "FallbackDNS=$PRIMARY_DNS_V6 $SECONDARY_DNS_V6"
        } > /etc/systemd/resolved.conf.d/99-custom-dns.conf
        systemctl restart systemd-resolved
    else
        echo -e "${BLUE}配置 /etc/resolv.conf...${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "nameserver $PRIMARY_DNS_V4"
            echo "nameserver $SECONDARY_DNS_V4"
            has_ipv6 && { echo "nameserver $PRIMARY_DNS_V6"; echo "nameserver $SECONDARY_DNS_V6"; }
        } > /etc/resolv.conf
    fi
    echo -e "${GREEN}✅ DNS 配置完成${NC}"
}

configure_fail2ban() {
    echo -e "\n${YELLOW}=============== 7. Fail2ban配置 ===============${NC}"
    
    local port_list="22"
    if [[ -n "$FAIL2BAN_EXTRA_PORT" && "$FAIL2BAN_EXTRA_PORT" =~ ^[0-9]+$ && "$FAIL2BAN_EXTRA_PORT" != "22" ]]; then
        port_list="22,$FAIL2BAN_EXTRA_PORT"
    fi
    
    start_spinner "安装 Fail2ban... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1 || { stop_spinner; echo -e "${RED}安装失败${NC}"; return 1; }
    stop_spinner
    
    echo -e "${BLUE}配置保护端口: $port_list${NC}"
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = -1
findtime = 300
maxretry = 3
[sshd]
enabled = true
port = $port_list
backend = systemd
ignoreip = 127.0.0.1/8
EOF
    systemctl enable --now fail2ban >/dev/null 2>&1
    echo -e "${GREEN}✅ Fail2ban 已配置并启动${NC}"
}

system_update() {
    echo -e "\n${YELLOW}=============== 8. 系统更新与清理 ===============${NC}"
    
    start_spinner "系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >/dev/null 2>&1
    stop_spinner
    
    start_spinner "清理缓存... "
    DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    stop_spinner
    
    echo -e "${GREEN}✅ 系统更新与清理完成${NC}"
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================

main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要 root 权限${NC}"; exit 1; }
    
    parse_args "$@"

    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}               VPS 初始化配置预览${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    
    local hostname_display
    if [[ -n "$NEW_HOSTNAME" ]]; then hostname_display="$NEW_HOSTNAME"
    elif [[ "$non_interactive" = true ]]; then hostname_display="自动设置 (基于公网IP)"
    else hostname_display="交互式设置"; fi
    
    echo -e "  主机名:      $hostname_display"
    echo -e "  时区:        $TIMEZONE"
    echo -e "  Swap:        $SWAP_SIZE_MB"
    echo -e "  BBR模式:     $BBR_MODE"
    echo -e "  DNS(v4):     $PRIMARY_DNS_V4, $SECONDARY_DNS_V4"
    has_ipv6 && echo -e "  DNS(v6):     $PRIMARY_DNS_V6, $SECONDARY_DNS_V6"
    
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then
        local ports="22${FAIL2BAN_EXTRA_PORT:+,${FAIL2BAN_EXTRA_PORT}}"
        echo -e "  Fail2ban:    ${GREEN}启用 (端口: $ports)${NC}"
    else
        echo -e "  Fail2ban:    ${RED}禁用${NC}"
    fi
    echo -e "${CYAN}=====================================================${NC}"
    
    if [[ "$non_interactive" = false ]]; then
        read -p "确认配置并开始? [Y/n] " -r < /dev/tty
        [[ $REPLY =~ ^[Nn]$ ]] && { echo "已取消"; exit 0; }
    fi
    
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    echo -e "${BLUE}[INFO] 开始执行配置... (日志: $LOG_FILE)${NC}"
    SECONDS=0
    
    pre_flight_checks
    install_packages
    configure_hostname
    configure_timezone
    configure_bbr
    configure_swap
    configure_dns
    [[ "$ENABLE_FAIL2BAN" = true ]] && configure_fail2ban
    system_update
    
    run_verification
    
    echo -e "\n${YELLOW}==================== 配置完成 ====================${NC}"
    echo -e "${GREEN}🎉 VPS初始化配置完成！${NC}"
    echo -e "  执行时间: ${SECONDS}秒"
    echo -e "  日志文件: ${LOG_FILE}"
    
    echo -e "\n${BLUE}[INFO] 建议重启以确保所有设置生效。${NC}"
    read -p "立即重启? [Y/n] " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}[INFO] 重启中...${NC}"
        reboot
    else
        echo -e "${GREEN}请稍后手动重启：${YELLOW}sudo reboot${NC}"
    fi
}

main "$@"
