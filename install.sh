#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本
# 版本: 6.7-enhanced
# ==============================================================================
set -euo pipefail

# --- 默认配置 ---
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
SWAP_SIZE_MB="auto"
INSTALL_PACKAGES="sudo wget zip vim"
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
BBR_MODE="default"
ENABLE_FAIL2BAN=true
FAIL2BAN_EXTRA_PORT=""
LOG_RETENTION_DAYS=7
TOTAL_STEPS=8
CURRENT_STEP=0

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

# 显示进度
show_progress() {
    ((CURRENT_STEP++))
    echo -e "${BLUE}[INFO] 完成 $CURRENT_STEP/$TOTAL_STEPS 步骤${NC}"
}

# 系统信息获取
get_public_ipv4() {
    local ip
    for cmd in "curl -s -4 --max-time 5" "wget -qO- -4 --timeout=5"; do
        for url in "https://api.ipify.org" "https://ip.sb"; do
            ip=$($cmd $url 2>/dev/null) && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && echo "$ip" && return
        done
    done
    echo "vps-$(date +%s)" # Fallback 主机名
}

has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' || ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'
}

# DNS 连通性测试
test_dns() {
    local dns="$1"
    ping -c 1 "$dns" >/dev/null 2>&1 && return 0
    echo -e "${YELLOW}[WARN] DNS $dns 不可达${NC}"
    return 1
}

# 磁盘空间检查
check_disk_space() {
    local required_mb=$1
    local available_mb

    available_mb=$(df -BM / | awk 'NR==2 {gsub(/M/,"",$4); print $4}' || echo 0)

    if [[ "$available_mb" -eq 0 ]]; then
        echo -e "${RED}[ERROR] 无法获取可用磁盘空间信息。${NC}"
        return 1
    fi

    if [[ "$available_mb" -lt "$required_mb" ]]; then
        echo -e "${RED}[ERROR] 磁盘空间不足: 需要${required_mb}MB，可用${available_mb}MB${NC}"
        return 1
    fi
}

# 容器环境检测
is_container() {
    case "$(systemd-detect-virt --container 2>/dev/null)" in
        docker|lxc|openvz|containerd|podman) return 0 ;;
    esac
    [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] ||
    grep -q 'container=lxc\|container=docker' /proc/1/environ 2>/dev/null
}

# 内核版本比较
compare_version() {
    printf '%s\n' "$@" | sort -V | head -n1
}

is_kernel_version_ge() {
    local required="$1" current
    current=$(uname -r | grep -oP '^\d+\.\d+' || echo "0.0")
    [[ "$(compare_version "$current" "$required")" = "$required" ]]
}

# 清理旧日志文件
clean_old_logs() {
    echo -e "${BLUE}[INFO] 清理超过 ${LOG_RETENTION_DAYS} 天的日志文件...${NC}"
    if [[ -d /var/log ]]; then
        find /var/log -type f -name "vps-init-*.log" -mtime +"$LOG_RETENTION_DAYS" -delete 2>/dev/null
        echo -e "${GREEN}✅ 旧日志清理完成${NC}"
    else
        echo -e "${YELLOW}[WARN] /var/log 目录不存在，跳过清理${NC}"
    fi
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
    [[ -n "$NEW_HOSTNAME" && -f /etc/hosts ]] && {
        grep -q "$NEW_HOSTNAME" /etc/hosts && record_verification "/etc/hosts" "PASS" "包含主机名 $NEW_HOSTNAME" || record_verification "/etc/hosts" "FAIL" "未包含主机名 $NEW_HOSTNAME"
    }
    
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
        [[ $current_swap_mb -gt 0 && -f /swapfile && $(grep -q "/swapfile" /proc/swaps) ]] && record_verification "Swap" "PASS" "${current_swap_mb}MB 已启用" || record_verification "Swap" "FAIL" "Swap未配置或未启用"
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
  --ip-dns <'主 备'>   设置 IPv4 DNS
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
  --log-retention-days <days>  设置日志保留天数 (默认: 7)
${GREEN}示例:${NC}
  bash $0 --no-fail2ban --swap 0
  bash $0 --hostname myvps --ip-dns "1.1.1.1 8.8.8.8" --bbr-optimized --log-retention-days 14
EOF
    exit 0
}

validate_ports() {
    local ports="$1"
    IFS=',' read -ra port_array <<< "$ports"
    for port in "${port_array[@]}"; do
        if ! [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
            echo -e "${RED}[ERROR] 无效端口: $port${NC}"
            return 1
        fi
    done
    echo "$ports"
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
                [[ -n "${2:-}" && ! "$2" =~ ^- ]] && { FAIL2BAN_EXTRA_PORT=$(validate_ports "$2") || exit 1; shift; }
                shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --non-interactive) non_interactive=true; shift ;;
            --log-retention-days) 
                if [[ "$2" =~ ^[0-9]+$ && "$2" -ge 0 ]]; then
                    LOG_RETENTION_DAYS="$2"
                    shift 2
                else
                    echo -e "${RED}[ERROR] 无效日志保留天数: $2${NC}"
                    exit 1
                fi ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

# ==============================================================================
# --- 功能函数 (按执行顺序排列) ---
# ==============================================================================

pre_flight_checks() {
    echo -e "${BLUE}[INFO] 系统预检查...${NC}"
    
    if is_container; then
        echo -e "${YELLOW}[WARN] 检测到容器环境，某些功能可能受限${NC}"
        if [[ "$non_interactive" = false ]]; then
            read -p "继续执行? [y/N] " -r < /dev/tty
            [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
        fi
    fi
    
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
    
    if ! groups | grep -q sudo 2>/dev/null && [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] 需要 root 权限或 sudo 权限${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 系统: $PRETTY_NAME${NC}"
    show_progress
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
    show_progress
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
    elif [[ "$non_interactive" = "true" ]]; then
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
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$final_hostname/" /etc/hosts
        else
            echo -e "127.0.1.1\t$final_hostname" >> /etc/hosts
        fi
    fi
    echo -e "${GREEN}✅ 主机名: $(hostname)${NC}"
    show_progress
}

configure_timezone() {
    echo -e "\n${YELLOW}=============== 3. 时区配置 ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null && echo -e "${GREEN}✅ 时区: $TIMEZONE${NC}"
    show_progress
}

configure_bbr() {
    echo -e "\n${YELLOW}=============== 4. BBR配置 ===============${NC}"
    
    local config_file="/etc/sysctl.d/99-bbr.conf"
    
    if [[ "$BBR_MODE" = "none" ]]; then
        echo -e "${BLUE}[INFO] 根据参数跳过 BBR 配置${NC}"
        rm -f "$config_file"
        show_progress
        return
    fi
    
    if ! is_kernel_version_ge "4.9"; then
        echo -e "${RED}[ERROR] 内核版本过低 ($(uname -r))，BBR 需要 4.9+${NC}"
        show_progress
        return 1
    fi
    
    if ! lsmod | grep -q tcp_bbr; then
        modprobe tcp_bbr 2>/dev/null || echo -e "${YELLOW}[WARN] BBR 模块未加载${NC}"
    fi
    
    if [[ "$BBR_MODE" = "optimized" ]]; then
        if is_kernel_version_ge "4.9"; then
            echo -e "${BLUE}[INFO] 配置动态优化 BBR...${NC}"
            local mem_mb=$(free -m | awk '/^Memeração:{print $2}')
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
            show_progress
            return
        else
            echo -e "${RED}内核版本过低，使用标准BBR${NC}"
        fi
    fi
    
    echo -e "${BLUE}[INFO] 配置标准 BBR...${NC}"
    echo -e "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr" > "$config_file"
    sysctl -p "$config_file" >/dev/null 2>&1
    echo -e "${GREEN}✅ 标准 BBR 已启用${NC}"
    show_progress
}

configure_swap() {
    echo -e "\n${YELLOW}=============== 5. Swap配置 ===============${NC}"
    
    if is_container; then
        echo -e "${YELLOW}[WARN] 容器环境不支持 Swap 配置，跳过${NC}"
        show_progress
        return
    fi
    
    [[ "$SWAP_SIZE_MB" = "0" ]] && { echo -e "${BLUE}Swap已禁用${NC}"; show_progress; return; }
    
    local swap_mb
    if [[ "$SWAP_SIZE_MB" = "auto" ]]; then
        local mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        swap_mb=$((mem_mb < 2048 ? mem_mb : 2048))
        echo -e "${BLUE}自动设置 Swap: ${swap_mb}MB${NC}"
    else
        swap_mb=$SWAP_SIZE_MB
    fi
    
    check_disk_space $((swap_mb + 100)) || { show_progress; return 1; }
    
    local current_swap_file="/swapfile"
    
    if [[ -f "$current_swap_file" ]]; then
        local current_size_mb=$(du -m "$current_swap_file" | awk '{print $1}')
        if [[ "$current_size_mb" -ne "$swap_mb" ]]; then
            if grep -q "$current_swap_file" /proc/swaps 2>/dev/null; then
                swapoff "$current_swap_file" >/dev/null 2>&1 || { echo -e "${RED}[ERROR] 无法关闭现有 Swap 文件${NC}"; show_progress; return 1; }
            fi
            rm -f "$current_swap_file"
        else
            echo -e "${BLUE}检测到已存在大小合适的 Swap 文件，跳过创建。${NC}"
            show_progress
            return
        fi
    fi
    
    echo -e "${BLUE}正在创建 ${swap_mb}MB Swap...${NC}"
    
    start_spinner "创建 Swap 文件... "
    local success=false
    
    if command -v fallocate &>/dev/null; then
        fallocate -l "${swap_mb}M" "$current_swap_file" 2>/dev/null && success=true
    fi
    
    if [[ "$success" = false ]]; then
        dd if=/dev/zero of="$current_swap_file" bs=1M count="$swap_mb" status=none 2>/dev/null && success=true
    fi
    
    if [[ "$success" = false ]]; then
        stop_spinner
        echo -e "${RED}[ERROR] Swap 文件创建失败${NC}"
        show_progress
        return 1
    fi
    
    stop_spinner
    
    chmod 600 "$current_swap_file" && mkswap "$current_swap_file" >/dev/null && swapon "$current_swap_file"
    grep -q "$current_swap_file" /etc/fstab || echo "$current_swap_file none swap sw 0 0" >> /etc/fstab
    echo -e "${GREEN}✅ ${swap_mb}MB Swap 已配置${NC}"
    show_progress
}

configure_dns() {
    echo -e "\n${YELLOW}=============== 6. DNS配置 ===============${NC}"
    
    if systemctl is-active --quiet cloud-init 2>/dev/null; then
        echo -e "${YELLOW}[WARN] 检测到 cloud-init 服务正在运行。DNS 设置可能在重启后被覆盖。请考虑在您的云服务商控制面板中配置DNS。${NC}"
    fi

    if systemctl is-active --quiet NetworkManager 2>/dev/null; then
        echo -e "${YELLOW}[WARN] NetworkManager 正在运行，DNS 设置可能被覆盖${NC}"
    fi
    
    test_dns "$PRIMARY_DNS_V4" || PRIMARY_DNS_V4="8.8.8.8"
    test_dns "$SECONDARY_DNS_V4" || SECONDARY_DNS_V4="8.8.4.4"
    if has_ipv6; then
        test_dns "$PRIMARY_DNS_V6" || PRIMARY_DNS_V6=""
        test_dns "$SECONDARY_DNS_V6" || SECONDARY_DNS_V6=""
    fi
    
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        echo -e "${BLUE}配置 systemd-resolved...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        {
            echo "[Resolve]"
            echo "DNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4"
            has_ipv6 && [[ -n "$PRIMARY_DNS_V6" ]] && echo "FallbackDNS=$PRIMARY_DNS_V6 $SECONDARY_DNS_V6"
        } > /etc/systemd/resolved.conf.d/99-custom-dns.conf
        systemctl restart systemd-resolved
    else
        echo -e "${BLUE}配置 /etc/resolv.conf...${NC}"
        if [[ -L /etc/resolv.conf ]]; then
            echo -e "${YELLOW}[WARN] /etc/resolv.conf 是符号链接，配置可能不持久${NC}"
        fi
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "nameserver $PRIMARY_DNS_V4"
            echo "nameserver $SECONDARY_DNS_V4"
            has_ipv6 && [[ -n "$PRIMARY_DNS_V6" ]] && { echo "nameserver $PRIMARY_DNS_V6"; echo "nameserver $SECONDARY_DNS_V6"; }
        } > /etc/resolv.conf
    fi
    echo -e "${GREEN}✅ DNS 配置完成${NC}"
    show_progress
}

configure_fail2ban() {
    echo -e "\n${YELLOW}=============== 7. Fail2ban配置 ===============${NC}"
    
    local port_list="22"
    if [[ -n "$FAIL2BAN_EXTRA_PORT" ]]; then
        port_list=$(validate_ports "22,$FAIL2BAN_EXTRA_PORT") || { show_progress; return 1; }
    fi
    
    start_spinner "安装 Fail2ban... "
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1; then
        stop_spinner
        echo -e "${YELLOW}[WARN] Fail2ban 安装失败，继续执行其他步骤${NC}"
        show_progress
        return 0
    fi
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
    show_progress
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
    show_progress
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================

main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要 root 权限${NC}"; exit 1; }
    
    parse_args "$@"
    
    # 清理旧日志文件
    clean_old_logs
    
    echo -e "${CYAN}=====================================================${NC}"
    echo -e "${CYAN}             VPS 初始化配置预览${NC}"
    echo -e "${CYAN}=====================================================${NC}"
    
    local hostname_display
    if [[ -n "$NEW_HOSTNAME" ]]; then hostname_display="$NEW_HOSTNAME"
    elif [[ "$non_interactive" = true ]]; then hostname_display="自动设置 (基于公网IP)"
    else hostname_display="交互式设置"; fi
    
    echo -e "  主机名:          $hostname_display"
    echo -e "  时区:            $TIMEZONE"
    echo -e "  Swap:            $SWAP_SIZE_MB"
    echo -e "  BBR模式:         $BBR_MODE"
    echo -e "  DNS(v4):         $PRIMARY_DNS_V4, $SECONDARY_DNS_V4"
    has_ipv6 && echo -e "  DNS(v6):         $PRIMARY_DNS_V6, $SECONDARY_DNS_V6"
    echo -e "  日志保留天数:    $LOG_RETENTION_DAYS"
    
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then
        local ports="22${FAIL2BAN_EXTRA_PORT:+,${FAIL2BAN_EXTRA_PORT}}"
        echo -e "  Fail2ban:        ${GREEN}启用 (端口: $ports)${NC}"
    else
        echo -e "  Fail2ban:        ${RED}禁用${NC}"
    fi
    echo -e "${CYAN}=====================================================${NC}"
    
    if [[ "$non_interactive" = false ]]; then
        read -p "确认配置并开始? [Y/n] " -r < /dev/tty
        [[ $REPLY =~ ^[Nn]$ ]] && { echo "已取消"; exit 0; }
    fi
    
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S)-$$.log"
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
    
    if is_container; then
        echo -e "\n${BLUE}[INFO] 容器环境无需重启，配置已生效。${NC}"
    else
        echo -e "\n${BLUE}[INFO] 建议重启以确保所有设置生效。${NC}"
        read -p "立即重启? [Y/n] " -r < /dev/tty
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            echo -e "${BLUE}[INFO] 重启中...${NC}"
            reboot
        else
            echo -e "${GREEN}请稍后手动重启：${YELLOW}sudo reboot${NC}"
        fi
    fi
}

main "$@"
