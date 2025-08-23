#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本
# 版本: 5.1-final (Cleaned)
# 描述: 集成参数化配置、动态BBR优化、Fail2ban防护、智能Swap、日志记录。
# ==============================================================================
set -e
set -o pipefail

# --- 默认配置 ---
# 自动检测时区，如果失败则回退到 UTC
if command -v timedatectl &> /dev/null; then
    DETECTED_TIMEZONE=$(timedatectl show --property=Timezone --value)
    TIMEZONE=${DETECTED_TIMEZONE:-"UTC"}
else
    TIMEZONE="UTC"
fi

SWAP_SIZE_MB="auto"
INSTALL_PACKAGES="sudo wget zip vim curl"
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
BBR_MODE="default" # 可选值: default, optimized, none
ENABLE_FAIL2BAN=false
FAIL2BAN_EXTRA_PORT=""

# --- 颜色定义 (设为只读) ---
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# --- 全局变量 ---
non_interactive=false
spinner_pid=0
LOG_FILE=""

# ==============================================================================
# --- 命令行参数解析 ---
# ==============================================================================
usage() {
    echo -e "${YELLOW}用法: $0 [选项]...${NC}"
    echo "  全功能初始化脚本，用于 Debian 和 Ubuntu LTS 系统。"
    echo -e "  默认主机名将基于公网IP生成，时区将自动检测，Swap将智能分配。"
    echo
    echo -e "${BLUE}核心选项:${NC}"
    echo "  --hostname <name>        设置新的主机名 (例如: 'my-server')"
    echo "  --timezone <tz>          设置时区 (例如: 'Asia/Shanghai', 'UTC')"
    echo "  --swap <size_mb>         设置 Swap 大小 (MB)，'auto' 或 '0' (禁用)"
    echo "  --ip-dns <'p s'>         设置 IPv4 DNS (主/备，用引号和空格隔开)"
    echo "  --ip6-dns <'p s'>        设置 IPv6 DNS (主/备，用引号和空格隔开)"
    echo
    echo -e "${BLUE}BBR 模式选项 (三选一):${NC}"
    echo "  (默认)                   启用标准 BBR + FQ"
    echo "  --bbr-optimized          启用动态优化的 BBR (推荐)"
    echo "  --no-bbr                  禁用 BBR 配置"
    echo
    echo -e "${BLUE}安全选项:${NC}"
    echo "  --fail2ban [port]        安装并配置 Fail2ban。可选提供一个额外要保护的SSH端口。"
    echo
    echo -e "${BLUE}其他选项:${NC}"
    echo "  -h, --help               显示此帮助信息"
    echo "  --non-interactive        以非交互模式运行，自动应答并重启"
    echo
    echo -e "${GREEN}示例:${NC}"
    echo "  # 全功能优化 (主机名、Swap、时区自动配置)，并用fail2ban保护22和2222端口"
    echo "  bash $0 --bbr-optimized --fail2ban 2222"
    exit 0
}

# 使用 getopt 进行更健壮的参数解析
parse_args() {
    local temp
    temp=$(getopt -o 'h' -l 'hostname:,timezone:,swap:,ip-dns:,ip6-dns:,bbr-optimized,no-bbr,fail2ban::,non-interactive,help' -n "$0" -- "$@")
    if [ $? -ne 0 ]; then echo -e "${RED}参数解析错误...${NC}"; usage; fi
    eval set -- "$temp"
    unset temp

    while true; do
        case "$1" in
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
                case "$2" in
                    "") shift 2 ;;
                    *)  FAIL2BAN_EXTRA_PORT=$2; shift 2 ;;
                esac
                ;;
            --non-interactive) non_interactive=true; shift ;;
            --) shift; break ;;
            *) echo -e "${RED}内部错误！${NC}"; exit 1 ;;
        esac
    done
}


# --- 辅助函数 ---
handle_error() {
    local exit_code=$?
    local line_number=$1
    # 恢复光标
    tput cnorm
    echo -e "\n${RED}[ERROR] 脚本在第 $line_number 行执行失败 (退出码: $exit_code)${NC}"
    if [ -n "$LOG_FILE" ]; then
        echo -e "${RED}[ERROR] 完整日志请查看: ${LOG_FILE}${NC}"
    fi
    # 如果 spinner 正在运行，则杀死它
    if [[ $spinner_pid -ne 0 ]]; then kill $spinner_pid 2>/dev/null; fi
    exit $exit_code
}

start_spinner() {
    if [ "$non_interactive" = true ]; then return; fi
    local msg="${1:-}"
    echo -n -e "${CYAN}${msg}${NC}"
    local -r chars="/-\|"
    (
        while :; do
            for (( i=0; i<${#chars}; i++ )); do
                echo -n -e "\b${chars:$i:1}"
                sleep 0.1
            done
        done
    ) &
    spinner_pid=$!
    # 隐藏光标
    tput civis
}

stop_spinner() {
    if [[ $spinner_pid -ne 0 ]]; then
        kill $spinner_pid &>/dev/null
        wait $spinner_pid &>/dev/null
        spinner_pid=0
    fi
    # 恢复光标
    tput cnorm
    echo -e "\b${GREEN}✔${NC}"
}

# 健壮的公网 IPv4 获取函数
get_public_ipv4() {
    local ip=""
    # 依次尝试多个服务和工具来获取公网IPv4地址
    # curl -s: 静默模式; -4: 强制IPv4; --max-time 5: 超时5秒
    # wget -qO-: 静默模式输出到标准输出; -4: 强制IPv4; --timeout=5: 超时5秒
    if command -v curl &>/dev/null; then
        ip=$(curl -s -4 --max-time 5 https://api.ipify.org) || \
        ip=$(curl -s -4 --max-time 5 https://ip.sb)
    fi

    if [[ -z "$ip" ]] && command -v wget &>/dev/null; then
        ip=$(wget -qO- -4 --timeout=5 https://api.ipify.org) || \
        ip=$(wget -qO- -4 --timeout=5 https://ip.sb)
    fi

    # 验证返回的是否为合法的IPv4地址
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
    else
        # 如果所有尝试都失败或返回内容不合法，则返回空
        echo ""
    fi
}

has_ipv6() { ip -6 route show default 2>/dev/null | grep -q 'default' || ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'; }

check_disk_space() {
    local required_mb=$1
    local available_mb
    available_mb=$(df / | awk 'NR==2 {print int($4/1024)}')
    if [ "$available_mb" -lt "$required_mb" ]; then
        echo -e "${RED}[ERROR] 磁盘空间不足，需要 ${required_mb}MB，可用 ${available_mb}MB${NC}"; return 1;
    fi
    return 0
}

# --- 功能函数区 ---

pre_flight_checks() {
    echo -e "${BLUE}[INFO] 正在执行系统预检查...${NC}"
    local supported=false
    if [ "$ID" = "debian" ] && [[ "$VERSION_ID" =~ ^(10|11|12|13)$ ]]; then supported=true;
    elif [ "$ID" = "ubuntu" ] && [[ "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]]; then supported=true; fi
    if [ "$supported" = "false" ]; then
        echo -e "${YELLOW}[WARN] 此脚本为 Debian 10-13 或 Ubuntu 20.04-24.04 LTS 设计，当前系统为 $PRETTY_NAME。${NC}"
        if [ "$non_interactive" = "true" ]; then echo -e "${YELLOW}[WARN] 在非交互模式下将强制继续。${NC}";
        else
            read -p "是否强制继续? [y/N] " -r < /dev/tty
            [[ ! $REPLY =~ ^[Yy]$ ]] && echo "操作已取消。" && exit 0
        fi
    fi
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 预检查完成。系统: $PRETTY_NAME"
}

configure_hostname() {
    echo -e "\n${YELLOW}=============== 1. 配置主机名 ===============${NC}"
    local CURRENT_HOSTNAME
    CURRENT_HOSTNAME=$(hostname)
    echo "当前主机名: $CURRENT_HOSTNAME"
    local FINAL_HOSTNAME="$CURRENT_HOSTNAME"

    if [ -n "$NEW_HOSTNAME" ]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$ ]]; then
            echo -e "${BLUE}[INFO] 通过参数设置新主机名为: $NEW_HOSTNAME${NC}"
            hostnamectl set-hostname "$NEW_HOSTNAME"
            FINAL_HOSTNAME="$NEW_HOSTNAME"
        else
            echo -e "${RED}[ERROR] 主机名 '$NEW_HOSTNAME' 格式不正确，保持不变。${NC}"
        fi
    else
        local IP_BASED_HOSTNAME=""
        local PUBLIC_IPV4=""
        echo -e "${BLUE}[INFO] 未指定主机名，尝试从公网 IPv4 生成建议...${NC}"
        
        PUBLIC_IPV4=$(get_public_ipv4)

        if [ -n "$PUBLIC_IPV4" ]; then
            IP_BASED_HOSTNAME="${PUBLIC_IPV4//./-}"
            echo -e "${GREEN}[INFO] 成功获取公网 IP: ${PUBLIC_IPV4}，建议的主机名为: ${IP_BASED_HOSTNAME}${NC}"
        else
            echo -e "${YELLOW}[WARN] 无法自动获取公网 IPv4 地址。${NC}"
        fi

        if [ "$non_interactive" = "true" ]; then
            if [ -n "$IP_BASED_HOSTNAME" ]; then
                echo -e "${BLUE}[INFO] 在非交互模式下，自动应用建议的主机名。${NC}"
                hostnamectl set-hostname "$IP_BASED_HOSTNAME"
                FINAL_HOSTNAME="$IP_BASED_HOSTNAME"
            else
                echo -e "${BLUE}[INFO] 非交互模式下无法获取IP，主机名保持不变。${NC}"
            fi
        else
            read -p "是否需要修改主机名? [Y/n] " -r < /dev/tty
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                local prompt_default="${IP_BASED_HOSTNAME:-$CURRENT_HOSTNAME}"
                read -p "请输入新的主机名 [默认为: ${prompt_default}]: " INTERACTIVE_HOSTNAME < /dev/tty
                local TARGET_HOSTNAME="${INTERACTIVE_HOSTNAME:-$prompt_default}"
                
                if [ -n "$TARGET_HOSTNAME" ] && [[ "$TARGET_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$ ]]; then
                    hostnamectl set-hostname "$TARGET_HOSTNAME"
                    FINAL_HOSTNAME="$TARGET_HOSTNAME"
                else
                    echo -e "${YELLOW}[WARN] 主机名格式不正确或为空，保持不变。${NC}"
                fi
            fi
        fi
    fi

    if ! grep -q -E "^127\.0\.1\.1\s+${FINAL_HOSTNAME}$" /etc/hosts; then
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$FINAL_HOSTNAME/g" /etc/hosts
        else
            echo -e "127.0.1.1\t$FINAL_HOSTNAME" >> /etc/hosts
        fi
    fi
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 主机名已更新为: $(hostname)"
}

configure_timezone() {
    echo -e "\n${YELLOW}=============== 2. 配置时区 ===============${NC}"
    echo -e "${BLUE}[INFO] 目标时区: ${TIMEZONE} (未指定时则为自动检测值)${NC}"
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null && echo -e "${GREEN}[SUCCESS]${NC} ✅ 时区已设置为 $TIMEZONE"
}

configure_default_bbr() {
    echo -e "\n${YELLOW}=============== 3. 配置 BBR (标准模式) ===============${NC}"
    cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
# Generated by VPS Init Script (Default BBR)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 标准 BBR 已启用"
}

configure_optimized_bbr() {
    echo -e "\n${YELLOW}=============== 3. 配置 BBR (动态优化模式) ===============${NC}"
    local KERNEL_VERSION KERNEL_MAJOR KERNEL_MINOR
    KERNEL_VERSION=$(uname -r); KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1); KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    if (( KERNEL_MAJOR < 4 )) || (( KERNEL_MAJOR == 4 && KERNEL_MINOR < 9 )); then
        echo -e "${RED}❌ 错误: 内核版本 $KERNEL_VERSION 不支持BBR (需要 4.9+), 跳过优化。${NC}"; return 1;
    fi
    if [[ ! $(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null) =~ "bbr" ]]; then
        echo -e "${YELLOW}⚠️  警告: BBR模块未加载，尝试加载...${NC}"
        modprobe tcp_bbr 2>/dev/null || echo -e "${RED}❌ 无法加载BBR模块${NC}"
    fi

    local TOTAL_MEM CPU_CORES
    TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
    CPU_CORES=$(nproc)
    echo -e "${BLUE}[INFO] 系统信息: ${TOTAL_MEM}MB 内存, ${CPU_CORES} 核 CPU${NC}"

    local RMEM_MAX WMEM_MAX TCP_RMEM TCP_WMEM SOMAXCONN NETDEV_BACKLOG FILE_MAX CONNTRACK_MAX VM_TIER
    if [ $TOTAL_MEM -le 512 ]; then
        RMEM_MAX="8388608"; WMEM_MAX="8388608"; TCP_RMEM="4096 65536 8388608"; TCP_WMEM="4096 65536 8388608"
        SOMAXCONN="32768"; NETDEV_BACKLOG="16384"; FILE_MAX="262144"; CONNTRACK_MAX="131072"; VM_TIER="经典级(≤512MB)"
    elif [ $TOTAL_MEM -le 1024 ]; then
        RMEM_MAX="16777216"; WMEM_MAX="16777216"; TCP_RMEM="4096 65536 16777216"; TCP_WMEM="4096 65536 16777216"
        SOMAXCONN="49152"; NETDEV_BACKLOG="24576"; FILE_MAX="524288"; CONNTRACK_MAX="262144"; VM_TIER="轻量级(512MB-1GB)"
    elif [ $TOTAL_MEM -le 2048 ]; then
        RMEM_MAX="33554432"; WMEM_MAX="33554432"; TCP_RMEM="4096 87380 33554432"; TCP_WMEM="4096 65536 33554432"
        SOMAXCONN="65535"; NETDEV_BACKLOG="32768"; FILE_MAX="1048576"; CONNTRACK_MAX="524288"; VM_TIER="标准级(1GB-2GB)"
    else
        RMEM_MAX="67108864"; WMEM_MAX="67108864"; TCP_RMEM="4096 131072 67108864"; TCP_WMEM="4096 87380 67108864"
        SOMAXCONN="65535"; NETDEV_BACKLOG="65535"; FILE_MAX="2097152"; CONNTRACK_MAX="1048576"; VM_TIER="高性能级(>2GB)"
    fi
    echo -e "${BLUE}[INFO] 已匹配优化配置: ${VM_TIER}${NC}"
    
    local CONF_FILE="/etc/sysctl.d/99-bbr.conf"
    
    if [ -f "$CONF_FILE" ]; then
        cp "$CONF_FILE" "$CONF_FILE.bak_$(date +%F_%H-%M-%S)"
        echo -e "${BLUE}[INFO] 已备份现有 BBR 配置。${NC}"
    fi

    cat > "$CONF_FILE" << EOF
# Auto-generated by VPS Init Script on $(date)
# Optimized for ${TOTAL_MEM}MB RAM (${VM_TIER})
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = $RMEM_MAX
net.core.wmem_max = $WMEM_MAX
net.ipv4.tcp_rmem = $TCP_RMEM
net.ipv4.tcp_wmem = $TCP_WMEM
net.core.somaxconn = $SOMAXCONN
net.core.netdev_max_backlog = $NETDEV_BACKLOG
net.ipv4.tcp_max_syn_backlog = $SOMAXCONN
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 180000
fs.file-max = $FILE_MAX
fs.nr_open = $FILE_MAX
net.ipv4.tcp_slow_start_after_idle = 0
vm.swappiness = 10
EOF
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        echo "net.netfilter.nf_conntrack_max = $CONNTRACK_MAX" >> "$CONF_FILE"
    fi
    
    sysctl --system >/dev/null 2>&1
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 动态 BBR 优化已应用。当前拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
}

configure_swap() {
    echo -e "\n${YELLOW}=============== 4. 配置 Swap ===============${NC}"
    local swap_size_num
    if [[ "$SWAP_SIZE_MB" =~ ^[0-9]+$ ]]; then swap_size_num=$SWAP_SIZE_MB; else swap_size_num=-1; fi
    if [ "$swap_size_num" -eq 0 ]; then echo -e "${BLUE}[INFO] Swap配置为0，跳过。${NC}"; return 0; fi
    if [ "$(awk '/SwapTotal/ {print $2}' /proc/meminfo)" -gt 0 ]; then echo -e "${BLUE}[INFO] 已存在Swap，跳过。${NC}"; return 0; fi

    local swap_to_create_mb mem_total_mb
    if [ "$SWAP_SIZE_MB" = "auto" ]; then
        mem_total_mb=$(($(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024))
        if [ "$mem_total_mb" -lt 2048 ]; then swap_to_create_mb=$mem_total_mb; else swap_to_create_mb=2048; fi
        echo -e "${BLUE}[INFO] 自动计算Swap大小为 ${swap_to_create_mb}MB...${NC}"
    else 
        swap_to_create_mb=$SWAP_SIZE_MB
    fi

    if ! check_disk_space "$((swap_to_create_mb + 100))"; then return 1; fi
    echo -e "${BLUE}[INFO] 正在配置 ${swap_to_create_mb}MB Swap...${NC}"
    if [ -f /swapfile ]; then swapoff /swapfile 2>/dev/null || true; rm -f /swapfile; fi

    if fallocate -l "${swap_to_create_mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$swap_to_create_mb" status=none 2>/dev/null; then
        chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
        grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}[SUCCESS]${NC} ✅ ${swap_to_create_mb}MB Swap 配置完成"
    else echo -e "${RED}[ERROR] Swap 文件创建失败${NC}"; return 1; fi
}

configure_dns() {
    echo -e "\n${YELLOW}=============== 5. 配置公共 DNS ===============${NC}"
    local has_ipv6_support=false
    if has_ipv6; then
        echo -e "${BLUE}[INFO] 检测到IPv6连接，将同时配置IPv6 DNS。${NC}"
        has_ipv6_support=true
    else
        echo -e "${YELLOW}[WARN] 未检测到IPv6连接，仅配置IPv4 DNS。${NC}"
    fi

    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${BLUE}[INFO] 检测到 systemd-resolved 服务，正在写入配置...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        local dns_content="[Resolve]\nDNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4\n"
        if [ "$has_ipv6_support" = "true" ]; then
            dns_content+="FallbackDNS=$PRIMARY_DNS_V6 $SECONDARY_DNS_V6\n"
        else
            dns_content+="FallbackDNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4\n"
        fi
        echo -e "$dns_content" > /etc/systemd/resolved.conf.d/99-custom-dns.conf
        systemctl restart systemd-resolved
        resolvectl flush-caches 2>/dev/null || true
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成 (systemd-resolved)。"
        return 0
    fi
    
    echo -e "${YELLOW}[WARN] 未检测到特定DNS管理器。将直接覆盖 /etc/resolv.conf。${NC}"
    if [ -f /etc/resolv.conf ]; then
        cp /etc/resolv.conf /etc/resolv.conf.backup."$(date +%s)"
        echo -e "${BLUE}[INFO] 已备份原 /etc/resolv.conf 文件${NC}"
    fi
    chattr -i /etc/resolv.conf 2>/dev/null || true
    {
        echo "nameserver $PRIMARY_DNS_V4"
        echo "nameserver $SECONDARY_DNS_V4"
        [ "$has_ipv6_support" = "true" ] && {
            echo "nameserver $PRIMARY_DNS_V6"
            echo "nameserver $SECONDARY_DNS_V6"
        }
    } > /etc/resolv.conf
    echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成 (直接覆盖)。"
}

install_tools_and_vim() {
    echo -e "\n${YELLOW}=============== 6. 安装常用工具和配置Vim ===============${NC}"
    start_spinner "更新软件包列表... "
    apt-get update -qq || { stop_spinner; echo -e "${RED}[ERROR] 软件包列表更新失败。${NC}"; return 1; }
    stop_spinner

    start_spinner "正在安装: $INSTALL_PACKAGES... "
    apt-get install -y $INSTALL_PACKAGES || { stop_spinner; echo -e "${YELLOW}[WARN] 部分软件包安装失败。${NC}"; }
    stop_spinner

    if command -v vim &> /dev/null; then
        echo -e "${BLUE}[INFO] 配置Vim基础特性...${NC}"
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
        if [ -d /root ] && ! grep -q "source /etc/vim/vimrc.local" /root/.vimrc 2>/dev/null; then
            echo "source /etc/vim/vimrc.local" >> /root/.vimrc
        fi
        echo -e "${GREEN}[SUCCESS]${NC} ✅ Vim配置完成。"
    fi
}

install_and_configure_fail2ban() {
    echo -e "\n${YELLOW}=============== 7. 配置 Fail2ban 安全防护 ===============${NC}"
    local PORT_LIST="22"
    if [ -n "$FAIL2BAN_EXTRA_PORT" ]; then
        if ! [[ "$FAIL2BAN_EXTRA_PORT" =~ ^[0-9]+$ && "$FAIL2BAN_EXTRA_PORT" -ge 1 && "$FAIL2BAN_EXTRA_PORT" -le 65535 ]]; then
            echo -e "${RED}[ERROR] 无效的Fail2ban端口号 '$FAIL2BAN_EXTRA_PORT'，跳过配置。${NC}"
            return 1
        fi
        if [ "$FAIL2BAN_EXTRA_PORT" != "22" ]; then PORT_LIST="22,${FAIL2BAN_EXTRA_PORT}"; fi
    fi

    start_spinner "正在安装 Fail2ban... "
    apt-get install -y fail2ban || { stop_spinner; echo -e "${RED}[ERROR] Fail2ban 安装失败。${NC}"; return 1; }
    stop_spinner
    
    echo -e "${BLUE}[INFO] 正在创建配置文件 /etc/fail2ban/jail.local...${NC}"
    echo -e "${BLUE}[INFO] 将保护的SSH端口: ${PORT_LIST}${NC}"
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = -1
findtime = 300
maxretry = 3
banaction = iptables-allports
action = %(action_mwl)s

[sshd]
enabled = true
port = ${PORT_LIST}
backend = systemd
ignoreip = 127.0.0.1/8
EOF
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban
    echo -e "${GREEN}[SUCCESS]${NC} ✅ Fail2ban 已配置并启动。"
}

update_and_cleanup() {
    echo -e "\n${YELLOW}=============== 8. 系统更新和清理 ===============${NC}"
    start_spinner "执行系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" || \
        echo -e "${YELLOW}[WARN] 系统升级过程出现错误，但继续执行。${NC}"
    stop_spinner

    start_spinner "移除无用依赖并清理缓存... "
    apt-get autoremove --purge -y >/dev/null 2>&1
    apt-get clean
    stop_spinner
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 系统更新和清理完成。"
}

final_summary() {
    echo -e "\n${YELLOW}===================== 配置完成 =====================${NC}"
    echo -e "${GREEN}[SUCCESS]${NC} 🎉 系统初始化配置完成！\n"
    echo "配置摘要："
    echo "  - 主机名: $(hostname)"
    echo "  - 时区: $(timedatectl show --property=Timezone --value 2>/dev/null || echo '未设置')"
    local bbr_status
    bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    echo "  - BBR模式: ${BBR_MODE} (当前: ${bbr_status:-'未知'})"
    echo "  - Swap大小: $(free -h | awk '/Swap/ {print $2}' || echo '未配置')"
    if $ENABLE_FAIL2BAN && systemctl is-active --quiet fail2ban; then
        local f2b_ports
        f2b_ports=$(grep -oP 'port\s*=\s*\K[0-9,]+' /etc/fail2ban/jail.local || echo "未知")
        echo -e "  - Fail2ban: ${GREEN}已启用 (保护端口: ${f2b_ports})${NC}"
    else
        echo "  - Fail2ban: 未配置"
    fi
    echo -e "\n总执行时间: ${SECONDS} 秒"
    echo -e "完整日志已保存至: ${LOG_FILE}"
}

# --- 主函数 ---
main() {
    trap 'handle_error ${LINENO}' ERR
    if [[ $EUID -ne 0 ]]; then echo -e "${RED}[ERROR] 此脚本需要 root 权限运行。${NC}" >&2; exit 1; fi

    parse_args "$@"

    echo -e "${CYAN}=======================================================${NC}"
    echo -e "${CYAN}                 VPS 初始化配置预览                  ${NC}"
    echo -e "${CYAN}=======================================================${NC}"
    echo -e "  ${YELLOW}主机名:${NC}         ${NEW_HOSTNAME:-'自动 (基于公网IP)'}"
    echo -e "  ${YELLOW}时区:${NC}           ${TIMEZONE}"
    echo -e "  ${YELLOW}Swap大小:${NC}       ${SWAP_SIZE_MB}"
    echo -e "  ${YELLOW}BBR模式:${NC}        ${BBR_MODE}"
    echo -e "  ${YELLOW}DNS (IPv4):${NC}     ${PRIMARY_DNS_V4}, ${SECONDARY_DNS_V4}"
    if has_ipv6; then
        echo -e "  ${YELLOW}DNS (IPv6):${NC}     ${PRIMARY_DNS_V6}, ${SECONDARY_DNS_V6}"
    fi
    if [ "$ENABLE_FAIL2BAN" = true ]; then
        local f2b_ports="22${FAIL2BAN_EXTRA_PORT:+,${FAIL2BAN_EXTRA_PORT}}"
        echo -e "  ${YELLOW}Fail2ban:${NC}       ${GREEN}启用 (保护端口: ${f2b_ports})${NC}"
    else
        echo -e "  ${YELLOW}Fail2ban:${NC}       ${RED}禁用${NC}"
    fi
    echo -e "${CYAN}=======================================================${NC}"

    if [ "$non_interactive" = false ]; then
        read -p "确认以上配置并开始执行? [Y/n] " -r < /dev/tty
        [[ $REPLY =~ ^[Nn]$ ]] && { echo "操作已取消。"; exit 0; }
    fi

    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "${LOG_FILE}") 2>&1
    echo -e "${BLUE}[INFO] 脚本启动于 $(date)。日志将记录到: ${LOG_FILE}${NC}"
    if [ "$non_interactive" = "true" ]; then echo -e "${BLUE}[INFO] 已启用非交互模式。${NC}"; fi

    # ---- 正式执行 ----
    SECONDS=0
    [ -f /etc/os-release ] && source /etc/os-release || { echo "错误: /etc/os-release 未找到"; exit 1; }

    pre_flight_checks
    install_tools_and_vim # 提前安装curl等工具，为主机名检测提供支持
    configure_hostname
    configure_timezone
    
    if [ "$BBR_MODE" = "optimized" ]; then
        configure_optimized_bbr
    elif [ "$BBR_MODE" = "default" ]; then
        configure_default_bbr
    else
        echo -e "\n${YELLOW}=============== 3. 配置 BBR ===============${NC}"
        echo -e "${BLUE}[INFO] 根据参数 (--no-bbr)，跳过 BBR 配置。${NC}"
        rm -f /etc/sysctl.d/99-bbr.conf
    fi

    configure_swap
    configure_dns
    
    if [ "$ENABLE_FAIL2BAN" = true ]; then
        install_and_configure_fail2ban
    fi

    update_and_cleanup
    final_summary

    echo
    if [ "$non_interactive" = "true" ]; then
        echo -e "${BLUE}[INFO] 非交互模式：配置完成，正在自动重启系统...${NC}"
        reboot
    else
        read -p "是否立即重启系统以确保所有配置生效？ [Y/n] " -r < /dev/tty
        [[ ! $REPLY =~ ^[Nn]$ ]] && { echo -e "${BLUE}[INFO] 正在立即重启系统...${NC}"; reboot; } || \
            echo -e "${BLUE}[INFO] 配置完成，建议稍后手动重启 (sudo reboot)。${NC}"
    fi
}

main "$@"
