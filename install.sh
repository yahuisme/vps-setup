#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本
# 版本: 5.9
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
ENABLE_FAIL2BAN=false
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
# --- 验证函数（简化版） ---
# ==============================================================================

record_verification() {
    local component="$1" status="$2" message="$3"
    if [[ "$status" = "PASS" ]]; then
        echo -e "    ${GREEN}✓${NC} $component: $message"
        ((VERIFICATION_PASSED++))
    elif [[ "$status" = "WARN" ]]; then
        echo -e "    ${YELLOW}⚠️${NC} $component: $message"
        # 警告不计入失败统计
    else
        echo -e "    ${RED}✗${NC} $component: $message"
        ((VERIFICATION_FAILED++))
    fi
}

# 统一验证函数，减少重复代码
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
    set +e  # 临时禁用错误退出
    
    # 验证主机名（只在用户指定了新主机名时验证）
    [[ -n "$NEW_HOSTNAME" ]] && {
        local current_hostname=$(hostname)
        verify_config "主机名" "$NEW_HOSTNAME" "$current_hostname"
    }
    
    # 验证时区
    local current_timezone=$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')
    verify_config "时区" "$TIMEZONE" "$current_timezone"
    
    # 验证BBR
    local current_cc current_qdisc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    
    if [[ "$BBR_MODE" = "none" ]]; then
        record_verification "BBR" "PASS" "已禁用 (当前: $current_cc)"
    elif [[ "$current_cc" = "bbr" && "$current_qdisc" = "fq" ]]; then
        local mode_desc="标准模式"
        [[ "$BBR_MODE" = "optimized" && -f /etc/sysctl.d/99-bbr.conf ]] && {
            local config_lines=$(grep -c "^net\." /etc/sysctl.d/99-bbr.conf 2>/dev/null || echo "0")
            [[ $config_lines -gt 5 ]] && mode_desc="动态优化模式 ($config_lines 配置项)"
        }
        record_verification "BBR" "PASS" "$mode_desc 已启用"
    else
        record_verification "BBR" "FAIL" "BBR配置异常: $current_cc/$current_qdisc"
    fi
    
    # 验证Swap
    local current_swap_mb=$(awk '/SwapTotal/ {print int($2/1024)}' /proc/meminfo)
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        [[ $current_swap_mb -eq 0 ]] && record_verification "Swap" "PASS" "已禁用" || record_verification "Swap" "FAIL" "期望禁用，实际${current_swap_mb}MB"
    else
        [[ $current_swap_mb -gt 0 ]] && record_verification "Swap" "PASS" "${current_swap_mb}MB" || record_verification "Swap" "FAIL" "Swap未配置"
    fi
    
    # 验证DNS (改进检查逻辑)
    local dns_warning_msg="配置未生效 (这在云服务器上很常见，因其自动化管理服务会覆盖此配置)"
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if [[ -f /etc/systemd/resolved.conf.d/99-custom-dns.conf ]]; then
            local dns_config=$(cat /etc/systemd/resolved.conf.d/99-custom-dns.conf 2>/dev/null)
            if [[ "$dns_config" =~ $PRIMARY_DNS_V4 ]]; then
                record_verification "DNS" "PASS" "systemd-resolved已配置"
            else
                record_verification "DNS" "WARN" "systemd-resolved ${dns_warning_msg}"
            fi
        else
            record_verification "DNS" "FAIL" "systemd-resolved配置文件未找到"
        fi
    else
        if [[ -f /etc/resolv.conf ]]; then
            local resolv_content=$(cat /etc/resolv.conf 2>/dev/null)
            if [[ "$resolv_content" =~ $PRIMARY_DNS_V4 ]]; then
                record_verification "DNS" "PASS" "resolv.conf已配置"
            else
                record_verification "DNS" "WARN" "resolv.conf ${dns_warning_msg}"
            fi
        else
            record_verification "DNS" "FAIL" "DNS配置文件不存在"
        fi
    fi
    
    # 验证软件包安装
    local installed=0 total=0
    for pkg in $INSTALL_PACKAGES; do
        ((total++))
        dpkg -l "$pkg" >/dev/null 2>&1 && ((installed++))
    done
    [[ $installed -eq $total ]] && record_verification "软件包" "PASS" "全部已安装 ($installed/$total)" || record_verification "软件包" "FAIL" "部分未安装 ($installed/$total)"
    
    # 验证Fail2ban
    [[ "$ENABLE_FAIL2BAN" = true ]] && {
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local ports=$(grep -oP 'port\s*=\s*\K[0-9,]+' /etc/fail2ban/jail.local 2>/dev/null || echo "N/A")
            record_verification "Fail2ban" "PASS" "运行正常，保护端口: $ports"
        else
            record_verification "Fail2ban" "FAIL" "服务异常"
        fi
    }
    
    set -e
    
    echo -e "\n${BLUE}[INFO] 验证完成: ${GREEN}通过 $VERIFICATION_PASSED${NC}, ${RED}失败 $VERIFICATION_FAILED${NC}"
    [[ $VERIFICATION_FAILED -eq 0 ]] && echo -e "${GREEN}✅ 所有配置验证通过！${NC}" || echo -e "${YELLOW}⚠️ 有 $VERIFICATION_FAILED 项需要检查${NC}"
}

# ==============================================================================
# --- 参数解析 (简化版) ---
# ==============================================================================

usage() {
    cat << EOF
${YELLOW}用法: $0 [选项]...${NC}

${BLUE}核心选项:${NC}
  --hostname <name>     设置新的主机名
  --timezone <tz>       设置时区 (默认: 自动检测)
  --swap <size_mb>      设置 Swap 大小，'auto'/'0'
  --ip-dns <'主 备'>    设置 IPv4 DNS (用引号)
  --ip6-dns <'主 备'>   设置 IPv6 DNS (用引号)

${BLUE}BBR 选项:${NC}
  (默认)                启用标准 BBR
  --bbr-optimized       启用动态优化 BBR
  --no-bbr              禁用 BBR

${BLUE}安全选项:${NC}
  --fail2ban [port]     启用 Fail2ban，可选额外SSH端口

${BLUE}其他:${NC}
  -h, --help            显示帮助
  --non-interactive     非交互模式

${GREEN}示例:${NC}
  bash $0 --bbr-optimized --fail2ban 2222
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
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

# ==============================================================================
# --- 功能函数 (优化版) ---
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

configure_hostname() {
    echo -e "\n${YELLOW}=============== 1. 主机名配置 ===============${NC}"
    local current_hostname=$(hostname)
    echo -e "${BLUE}当前主机名: $current_hostname${NC}"
    local final_hostname="$current_hostname"
    local hostname_changed=false
    
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME"
            final_hostname="$NEW_HOSTNAME"
            hostname_changed=true
            echo -e "${BLUE}[INFO] 主机名设为: $NEW_HOSTNAME${NC}"
        else
            echo -e "${RED}[ERROR] 主机名格式不正确，保持不变${NC}"
            NEW_HOSTNAME=""  # 清除无效的主机名设置
        fi
    elif [[ "$non_interactive" = "true" ]]; then
        local public_ip=$(get_public_ipv4)
        if [[ -n "$public_ip" ]]; then
            final_hostname="${public_ip//./-}"
            hostnamectl set-hostname "$final_hostname"
            NEW_HOSTNAME="$final_hostname"  # 记录自动设置的主机名
            hostname_changed=true
            echo -e "${GREEN}自动设置主机名: $final_hostname${NC}"
        fi
    elif [[ "$non_interactive" = "false" ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "输入新主机名: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name"
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"  # 记录交互设置的主机名
                hostname_changed=true
            fi
        fi
    fi
    
    # 更新 /etc/hosts (只在主机名变更时)
    if [[ "$hostname_changed" = true ]]; then
        if ! grep -q "^127\.0\.1\.1.*$final_hostname" /etc/hosts; then
            if grep -q "^127\.0\.1\.1" /etc/hosts; then
                sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$final_hostname/" /etc/hosts
            else
                echo -e "127.0.1.1\t$final_hostname" >> /etc/hosts
            fi
        fi
    fi
    echo -e "${GREEN}✅ 主机名: $(hostname)${NC}"
}

configure_timezone() {
    echo -e "\n${YELLOW}=============== 2. 时区配置 ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null && echo -e "${GREEN}✅ 时区: $TIMEZONE${NC}"
}

configure_bbr() {
    echo -e "\n${YELLOW}=============== 3. BBR配置 ===============${NC}"
    
    case "$BBR_MODE" in
        "none")
            echo -e "${BLUE}[INFO] 根据参数跳过 BBR 配置${NC}"
            rm -f /etc/sysctl.d/99-bbr.conf
            return 0
            ;;
        "optimized")
            echo -e "${BLUE}[INFO] 配置动态优化 BBR...${NC}"
            local kernel_version=$(uname -r)
            local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
            local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
            
            if (( kernel_major < 4 || (kernel_major == 4 && kernel_minor < 9) )); then
                echo -e "${RED}内核版本过低 ($kernel_version)，使用标准BBR${NC}"
                BBR_MODE="default"
            else
                # 动态配置基于内存大小
                local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
                local cpu_cores=$(nproc)
                echo -e "${BLUE}系统: ${mem_mb}MB RAM, ${cpu_cores} CPU cores${NC}"
                
                # 根据内存分级配置
                if [[ $mem_mb -le 512 ]]; then
                    local rmem_max="8388608" wmem_max="8388608" somaxconn="32768"
                elif [[ $mem_mb -le 1024 ]]; then
                    local rmem_max="16777216" wmem_max="16777216" somaxconn="49152"
                elif [[ $mem_mb -le 2048 ]]; then
                    local rmem_max="33554432" wmem_max="33554432" somaxconn="65535"
                else
                    local rmem_max="67108864" wmem_max="67108864" somaxconn="65535"
                fi
                
                cat > /etc/sysctl.d/99-bbr.conf << EOF
# Auto-generated BBR optimized config on $(date)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = $((somaxconn/2))
net.ipv4.tcp_max_syn_backlog = $somaxconn
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = $((mem_mb * 1024))
vm.swappiness = 10
EOF
                sysctl --system >/dev/null 2>&1
                echo -e "${GREEN}✅ 动态优化 BBR 已启用${NC}"
                return 0
            fi
            ;;
    esac
    
    # 默认/标准BBR配置
    echo -e "${BLUE}[INFO] 配置标准 BBR...${NC}"
    cat > /etc/sysctl.d/99-bbr.conf << EOF
# Standard BBR configuration
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
    echo -e "${GREEN}✅ 标准 BBR 已启用${NC}"
}

configure_swap() {
    echo -e "\n${YELLOW}=============== 4. Swap配置 ===============${NC}"
    
    # 如果禁用swap或已存在swap则跳过
    [[ "$SWAP_SIZE_MB" = "0" ]] && { echo -e "${BLUE}Swap已禁用${NC}"; return 0; }
    [[ $(awk '/SwapTotal/ {print $2}' /proc/meminfo) -gt 0 ]] && { echo -e "${BLUE}Swap已存在，跳过${NC}"; return 0; }
    
    # 计算swap大小
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
    [[ -f /swapfile ]] && { swapoff /swapfile 2>/dev/null || true; rm -f /swapfile; }
    
    if fallocate -l "${swap_mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$swap_mb" status=none 2>/dev/null; then
        chmod 600 /swapfile
        mkswap /swapfile >/dev/null
        swapon /swapfile
        grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}✅ ${swap_mb}MB Swap 已配置${NC}"
    else
        echo -e "${RED}Swap 创建失败${NC}"
        return 1
    fi
}

configure_dns() {
    echo -e "\n${YELLOW}=============== 5. DNS配置 ===============${NC}"
    
    local has_ipv6_support=$(has_ipv6 && echo true || echo false)
    [[ "$has_ipv6_support" = "true" ]] && echo -e "${BLUE}检测到IPv6支持${NC}" || echo -e "${YELLOW}仅IPv4支持${NC}"
    
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${BLUE}配置 systemd-resolved...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        {
            echo "[Resolve]"
            echo "DNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4"
            [[ "$has_ipv6_support" = "true" ]] && echo "FallbackDNS=$PRIMARY_DNS_V6 $SECONDARY_DNS_V6" || echo "FallbackDNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4"
        } > /etc/systemd/resolved.conf.d/99-custom-dns.conf
        systemctl restart systemd-resolved
        resolvectl flush-caches 2>/dev/null || true
        echo -e "${GREEN}✅ DNS 配置完成 (systemd-resolved)${NC}"
    else
        echo -e "${BLUE}配置 /etc/resolv.conf...${NC}"
        [[ -f /etc/resolv.conf ]] && cp /etc/resolv.conf /etc/resolv.conf.backup."$(date +%s)"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "nameserver $PRIMARY_DNS_V4"
            echo "nameserver $SECONDARY_DNS_V4"
            [[ "$has_ipv6_support" = "true" ]] && {
                echo "nameserver $PRIMARY_DNS_V6"
                echo "nameserver $SECONDARY_DNS_V6"
            }
        } > /etc/resolv.conf
        echo -e "${GREEN}✅ DNS 配置完成${NC}"
    fi
}

install_packages() {
    echo -e "\n${YELLOW}=============== 6. 软件包安装 ===============${NC}"
    
    start_spinner "更新软件包列表... "
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || { stop_spinner; echo -e "${RED}更新失败${NC}"; return 1; }
    stop_spinner
    
    start_spinner "安装软件包... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y $INSTALL_PACKAGES >/dev/null 2>&1 || { stop_spinner; echo -e "${YELLOW}部分安装失败${NC}"; }
    stop_spinner
    
    # 配置Vim
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
        echo -e "${GREEN}✅ Vim 配置完成${NC}"
    fi
    
    echo -e "${GREEN}✅ 软件包安装完成${NC}"
}

configure_fail2ban() {
    echo -e "\n${YELLOW}=============== 7. Fail2ban配置 ===============${NC}"
    
    local port_list="22"
    if [[ -n "$FAIL2BAN_EXTRA_PORT" ]]; then
        if [[ "$FAIL2BAN_EXTRA_PORT" =~ ^[0-9]+$ && "$FAIL2BAN_EXTRA_PORT" -ge 1 && "$FAIL2BAN_EXTRA_PORT" -le 65535 ]]; then
            if [[ "$FAIL2BAN_EXTRA_PORT" != "22" ]]; then
                 port_list="22,$FAIL2BAN_EXTRA_PORT"
            fi
        else
            echo -e "${RED}无效端口号: $FAIL2BAN_EXTRA_PORT${NC}"
            return 1
        fi
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
banaction = iptables-allports
action = %(action_mwl)s

[sshd]
enabled = true
port = $port_list
backend = systemd
ignoreip = 127.0.0.1/8
EOF
    
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    echo -e "${GREEN}✅ Fail2ban 已配置并启动${NC}"
}

system_update() {
    echo -e "\n${YELLOW}=============== 8. 系统更新 ===============${NC}"
    
    start_spinner "系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >/dev/null 2>&1 || echo -e "${YELLOW}升级有警告${NC}"
    stop_spinner
    
    start_spinner "清理缓存... "
    DEBIAN_FRONTEND=noninteractive apt-get autoremove --purge -y >/dev/null 2>&1
    apt-get clean >/dev/null 2>&1
    stop_spinner
    
    echo -e "${GREEN}✅ 系统更新完成${NC}"
}

final_summary() {
    echo -e "\n${YELLOW}==================== 配置完成 ====================${NC}"
    echo -e "${GREEN}🎉 VPS初始化配置完成！${NC}\n"
    
    echo "当前配置状态："
    echo "  主机名: $(hostname)"
    echo "  时区:   $(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    echo "  BBR:    $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'N/A') ($BBR_MODE模式)"
    echo "  Swap:   $(free -h | awk '/Swap/ {print $2}' || echo '0B')"
    
    [[ "$ENABLE_FAIL2BAN" = true ]] && systemctl is-active --quiet fail2ban && {
        local ports=$(grep -oP 'port\s*=\s*\K[0-9,]+' /etc/fail2ban/jail.local 2>/dev/null || echo "N/A")
        echo -e "  Fail2ban: ${GREEN}已启用 (保护端口: $ports)${NC}"
    }
    
    echo -e "\n执行时间: ${SECONDS}秒"
    echo -e "日志文件: ${LOG_FILE}"
    
    [[ $VERIFICATION_FAILED -eq 0 ]] && echo -e "${GREEN}✅ 所有验证通过！${NC}" || echo -e "${YELLOW}⚠️ $VERIFICATION_FAILED 项需要检查${NC}"
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================

main() {
    trap 'handle_error ${LINENO}' ERR
    
    # 权限检查
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要 root 权限${NC}"; exit 1; }
    
    parse_args "$@"
    
    # 配置预览
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}               VPS 初始化配置预览${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    
    # 主机名显示逻辑
    local hostname_display
    if [[ -n "$NEW_HOSTNAME" ]]; then
        hostname_display="$NEW_HOSTNAME"
    elif [[ "$non_interactive" = "true" ]]; then
        hostname_display="自动设置 (基于公网IP)"
    else
        hostname_display="交互式设置"
    fi
    
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
    
    # 确认继续
    if [[ "$non_interactive" = "false" ]]; then
        read -p "确认配置并开始? [Y/n] " -r < /dev/tty
        [[ $REPLY =~ ^[Nn]$ ]] && { echo "已取消"; exit 0; }
    fi
    
    
    # 设置日志
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    touch "$LOG_FILE" && chmod 600 "$LOG_FILE"
    exec > >(tee -a "$LOG_FILE") 2>&1
    
    echo -e "${BLUE}[INFO] 开始执行配置... (日志: $LOG_FILE)${NC}"
    [[ "$non_interactive" = "true" ]] && echo -e "${BLUE}[INFO] 非交互模式${NC}"
    
    # 开始计时
    SECONDS=0
    
    # 执行配置步骤
    pre_flight_checks
    install_packages
    configure_hostname
    configure_timezone
    configure_bbr
    configure_swap
    configure_dns
    [[ "$ENABLE_FAIL2BAN" = true ]] && configure_fail2ban
    system_update
    
    # 验证配置
    run_verification
    
    # 显示摘要
    final_summary
    
    # 重启确认
    echo -e "\n${BLUE}[INFO] 配置完成！建议重启以确保所有设置生效。${NC}"
    
    if [[ "$non_interactive" = "true" ]]; then
        echo -e "${CYAN}[非交互模式] 脚本配置已完成。${NC}"
    fi

    read -p "立即重启? [Y/n] " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}[INFO] 重启中...${NC}"
        reboot
    else
        echo -e "${GREEN}配置完成！请稍后手动重启：${NC}"
        echo -e "${YELLOW}  sudo reboot${NC}"
    fi
}

main "$@"
