#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本 (专业增强版)
# 版本: 2.18-pro
# 描述: 集成可配置性、非交互模式、智能Swap和日志记录功能。
# ==============================================================================
set -e

# ==============================================================================
# --- 用户配置区 (请在此处修改以自定义脚本行为) ---
# ==============================================================================
# 时区, 例如 "Asia/Shanghai", "Asia/Hong_Kong", "America/New_York", "America/Los_Angeles", "Europe/London", "UTC", "GMT"
TIMEZONE="Asia/Hong_Kong"

# Swap 大小 (MB)。设置为 0 表示不创建。
# 设置为 "auto"，脚本将智能分配 (内存<2G则设为等量, >=2G则设为2G)。
SWAP_SIZE_MB="1024" 

# 需要安装的常用工具包，用空格隔开
INSTALL_PACKAGES="sudo wget zip vim"

# 自定义 DNS 服务器 (主要/备用)
PRIMARY_DNS_V4="8.8.8.8"
SECONDARY_DNS_V4="1.1.1.1"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
# ==============================================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 全局变量 ---
non_interactive=false

# --- 错误处理 ---
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo
    echo -e "${RED}[ERROR] 脚本在第 $line_number 行执行失败 (退出码: $exit_code)${NC}"
    echo -e "${RED}[ERROR] 完整日志请查看: ${LOG_FILE:-"未生成日志文件"}${NC}"
    exit $exit_code
}

# --- IPv6 检测 ---
has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' || \
    ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'
}

# --- 系统预检 ---
pre_flight_checks() {
    echo -e "${BLUE}[INFO] 正在执行系统预检查...${NC}"
    
    local supported=false
    if [ "$ID" = "debian" ] && [[ "$VERSION_ID" =~ ^(10|11|12|13)$ ]]; then
        supported=true
    elif [ "$ID" = "ubuntu" ] && [[ "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
        supported=true
    fi

    if [ "$supported" = "false" ]; then
        echo -e "${YELLOW}[WARN] 此脚本为 Debian 10-13 或 Ubuntu 20.04-24.04 LTS 设计，当前系统为 $PRETTY_NAME。${NC}"
        if [ "$non_interactive" = "true" ]; then
             echo -e "${YELLOW}[WARN] 在非交互模式下将强制继续。${NC}"
        else
            read -p "是否强制继续? [y/N] " -r < /dev/tty
            [[ ! $REPLY =~ ^[Yy]$ ]] && echo "操作已取消。" && exit 0
        fi
    fi

    echo -e "${GREEN}[SUCCESS]${NC} ✅ 预检查完成。系统: $PRETTY_NAME"
}

# --- 配置主机名 ---
configure_hostname() {
    echo -e "\n${YELLOW}=============== 1. 配置主机名 ===============${NC}"
    local CURRENT_HOSTNAME
    CURRENT_HOSTNAME=$(hostname)
    echo "当前主机名: $CURRENT_HOSTNAME"
    local FINAL_HOSTNAME="$CURRENT_HOSTNAME"

    if [ "$non_interactive" = "true" ]; then
        echo -e "${BLUE}[INFO] 非交互模式，保持当前主机名。${NC}"
    else
        read -p "是否需要修改主机名？ [y/N] 默认 N: " -r < /dev/tty
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            read -p "请输入新的主机名: " NEW_HOSTNAME < /dev/tty
            if [ -n "$NEW_HOSTNAME" ] && [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$ ]]; then
                hostnamectl set-hostname "$NEW_HOSTNAME"
                FINAL_HOSTNAME="$NEW_HOSTNAME"
                echo -e "${GREEN}[SUCCESS]${NC} ✅ 主机名已更新为: $FINAL_HOSTNAME"
            else
                echo -e "${YELLOW}[WARN] 主机名格式不正确或为空，保持不变。${NC}"
            fi
        else
            echo -e "${BLUE}[INFO] 保持当前主机名。${NC}"
        fi
    fi
    
    # 幂等性更新 /etc/hosts
    if ! grep -q "127.0.1.1\s\+$FINAL_HOSTNAME" /etc/hosts; then
        if grep -q "127.0.1.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$FINAL_HOSTNAME/g" /etc/hosts
        else
            echo "127.0.1.1    $FINAL_HOSTNAME" >> /etc/hosts
        fi
    fi
}

# --- 配置时区和BBR ---
configure_timezone_and_bbr() {
    echo -e "\n${YELLOW}=============== 2. 配置时区和BBR ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" 2>/dev/null && \
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 时区已设置为 $TIMEZONE"

    cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
    echo -e "${GREEN}[SUCCESS]${NC} ✅ BBR 已启用"
}

# --- 配置Swap ---
configure_swap() {
    echo -e "\n${YELLOW}=============== 3. 配置 Swap ===============${NC}"
    if [ "$SWAP_SIZE_MB" -eq 0 ]; then
        echo -e "${BLUE}[INFO] Swap大小配置为0，跳过此步骤。${NC}"
        return 0
    fi

    if [ "$(awk '/SwapTotal/ {print $2}' /proc/meminfo)" -gt 0 ]; then
        echo -e "${BLUE}[INFO] 检测到已存在 Swap，跳过此步骤。${NC}"
        return 0
    fi

    local swap_to_create_mb
    if [ "$SWAP_SIZE_MB" = "auto" ]; then
        mem_total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
        mem_total_mb=$((mem_total_kb / 1024))
        if [ "$mem_total_mb" -lt 2048 ]; then
            swap_to_create_mb=$mem_total_mb
        else
            swap_to_create_mb=2048
        fi
        echo -e "${BLUE}[INFO] 自动计算Swap大小为 ${swap_to_create_mb}MB...${NC}"
    else
        swap_to_create_mb=$SWAP_SIZE_MB
    fi

    echo -e "${BLUE}[INFO] 正在配置 ${swap_to_create_mb}MB Swap...${NC}"
    [ -f /swapfile ] && swapoff /swapfile &>/dev/null || true && rm -f /swapfile

    if fallocate -l "${swap_to_create_mb}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$swap_to_create_mb" status=none 2>/dev/null; then
        chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
        grep -q "/swapfile" /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
        echo -e "${GREEN}[SUCCESS]${NC} ✅ ${swap_to_create_mb}MB Swap 配置完成"
    else
        echo -e "${RED}[ERROR] Swap 文件创建失败${NC}"
        return 1
    fi
}

# --- 配置DNS ---
configure_dns() {
    echo -e "\n${YELLOW}=============== 4. 配置公共 DNS ===============${NC}"

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
        if [ "$has_ipv6_support" = "true" ]; then
            cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << EOF
[Resolve]
DNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4
FallbackDNS=$PRIMARY_DNS_V6 $SECONDARY_DNS_V6
EOF
        else
            cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << EOF
[Resolve]
DNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4
FallbackDNS=$PRIMARY_DNS_V4 $SECONDARY_DNS_V4
EOF
        fi
        systemctl restart systemd-resolved
        resolvectl flush-caches 2>/dev/null || true
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成 (systemd-resolved)。"
    else
        echo -e "${BLUE}[INFO] 使用传统方式覆盖 /etc/resolv.conf...${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        {
            echo "nameserver $PRIMARY_DNS_V4"
            echo "nameserver $SECONDARY_DNS_V4"
            [ "$has_ipv6_support" = "true" ] && {
                echo "nameserver $PRIMARY_DNS_V6"
                echo "nameserver $SECONDARY_DNS_V6"
            }
        } > /etc/resolv.conf
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成 (传统方式)。"
    fi
}

# --- 安装工具和Vim ---
install_tools_and_vim() {
    echo -e "\n${YELLOW}=============== 5. 安装常用工具和配置Vim ===============${NC}"
    echo -e "${BLUE}[INFO] 更新软件包列表...${NC}"
    apt-get update -qq || { echo -e "${RED}[ERROR] 软件包列表更新失败。${NC}"; return 1; }

    echo -e "${BLUE}[INFO] 正在安装: $INSTALL_PACKAGES${NC}"
    apt-get install -y $INSTALL_PACKAGES || echo -e "${YELLOW}[WARN] 部分软件包安装失败，请稍后手动安装。${NC}"

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
        # 幂等性添加 source 语句
        if [ -d /root ] && ! grep -q "source /etc/vim/vimrc.local" /root/.vimrc 2>/dev/null; then
            echo "source /etc/vim/vimrc.local" >> /root/.vimrc
        fi
        echo -e "${GREEN}[SUCCESS]${NC} ✅ Vim配置完成。"
    fi
}

# --- 系统更新和清理 ---
update_and_cleanup() {
    echo -e "\n${YELLOW}=============== 6. 系统更新和清理 ===============${NC}"
    echo -e "${BLUE}[INFO] 执行系统升级...${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" || \
        echo -e "${YELLOW}[WARN] 系统升级过程出现错误，但继续执行。${NC}"
    echo -e "${BLUE}[INFO] 移除无用依赖并清理缓存...${NC}"
    apt-get autoremove --purge -y
    apt-get clean
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 系统更新和清理完成。"
}

# --- 最终摘要 ---
final_summary() {
    echo -e "\n${YELLOW}===================== 配置完成 =====================${NC}"
    echo -e "${GREEN}[SUCCESS]${NC} 🎉 系统初始化配置完成！\n"
    echo "配置摘要："
    echo "  - 主机名: $(hostname)"
    echo "  - 时区: $(timedatectl show --property=Timezone --value 2>/dev/null || echo '未设置')"
    echo "  - BBR状态: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未检测到')"
    echo "  - Swap大小: $(free -h | awk '/Swap/ {print $2}' || echo '未配置')"
    local dns_servers=""
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [ -r /run/systemd/resolve/resolv.conf ]; then
        dns_servers=$(grep '^nameserver' /run/systemd/resolve/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    else
        dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    fi
    dns_servers=$(echo "$dns_servers" | sed 's/ *$//')
    echo "  - DNS服务器: ${dns_servers:-"未配置或未知"}"
    echo -e "\n总执行时间: ${SECONDS} 秒"
    echo -e "完整日志已保存至: ${LOG_FILE}"
}

# --- 主函数 ---
main() {
    trap 'handle_error ${LINENO}' ERR
    SECONDS=0
    
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] 此脚本需要 root 权限运行。${NC}" >&2
        exit 1
    fi
    
    if [ "$1" = "--non-interactive" ]; then
        non_interactive=true
    fi
    
    # 定义日志文件并重定向输出
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    exec > >(tee -a "${LOG_FILE}") 2>&1

    echo -e "${BLUE}[INFO] 脚本启动。输出将记录到: ${LOG_FILE}${NC}"
    if [ "$non_interactive" = "true" ]; then
        echo -e "${BLUE}[INFO] 已启用非交互模式，将使用默认选项自动执行。${NC}"
    fi

    [ -f /etc/os-release ] && source /etc/os-release || { echo "错误: 无法找到 /etc/os-release"; exit 1; }
    
    pre_flight_checks
    configure_hostname
    configure_timezone_and_bbr
    configure_swap
    configure_dns
    install_tools_and_vim
    update_and_cleanup
    final_summary
    
    echo
    if [ "$non_interactive" = "true" ]; then
        echo -e "${BLUE}[INFO] 非交互模式：配置完成，正在自动重启系统...${NC}"
        reboot
    else
        read -p "是否立即重启系统以确保所有配置生效？ [Y/n] 默认 Y: " -r < /dev/tty
        [[ ! $REPLY =~ ^[Nn]$ ]] && { echo -e "${BLUE}[INFO] 正在立即重启系统...${NC}"; reboot; } || \
            echo -e "${BLUE}[INFO] 配置完成，建议稍后手动重启 (sudo reboot)。${NC}"
    fi
}

main "$@"
