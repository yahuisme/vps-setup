#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本 (简洁优化版)
# 版本: 2.15-simple
# 
# 主要修复:
#   - [修复] DNS配置逻辑问题
#   - [增强] 错误处理机制
#   - [安全] 移除危险的系统升级参数
#   - [简化] 去掉过度复杂的配置
# ==============================================================================

set -e

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 核心函数 ---

# 错误处理
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo
    echo -e "${RED}[ERROR] 脚本在第 $line_number 行执行失败 (退出码: $exit_code)${NC}"
    echo -e "${RED}[ERROR] 请检查错误信息、系统状态或网络连接。${NC}"
    exit $exit_code
}

# 云环境检测
is_known_cloud() {
    [ -f /sys/hypervisor/uuid ] && [ "$(head -c 3 /sys/hypervisor/uuid 2>/dev/null)" = "ec2" ] && return 0
    [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi "Amazon\|Microsoft\|Oracle\|Google\|DigitalOcean" /sys/class/dmi/id/sys_vendor 2>/dev/null && return 0
    [ -f /sys/class/dmi/id/product_name ] && grep -qi "Google\|Amazon" /sys/class/dmi/id/product_name 2>/dev/null && return 0
    [ -f /etc/cloud/cloud.cfg ] && return 0
    return 1
}

# IPv6 环境检测
has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' || \
    ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'
}

# 系统预检
pre_flight_checks() {
    echo -e "${BLUE}[INFO] 正在执行系统预检查...${NC}"
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] 此脚本需要 root 权限运行。${NC}"; exit 1
    fi

    local supported=false
    if [ "$ID" = "debian" ] && [[ "$VERSION_ID" =~ ^(10|11|12|13)$ ]]; then
        supported=true
    elif [ "$ID" = "ubuntu" ] && [[ "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
        supported=true
    fi

    if [ "$supported" = "false" ]; then
        echo -e "${YELLOW}[WARN] 此脚本为 Debian 10-13 或 Ubuntu 20.04-24.04 LTS 设计，当前系统为 $PRETTY_NAME。${NC}"
        read -p "是否强制继续? [y/N] " -r < /dev/tty
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then echo "操作已取消。"; exit 0; fi
    fi

    echo -e "${GREEN}[SUCCESS]${NC} ✅ 预检查完成。系统: $PRETTY_NAME"
}

# 配置主机名 (保留交互)
configure_hostname() {
    echo -e "\n${YELLOW}=============== 1. 配置主机名 ===============${NC}"
    local CURRENT_HOSTNAME=$(hostname)
    echo "当前主机名: $CURRENT_HOSTNAME"
    read -p "是否需要修改主机名？ [y/N] 默认 N: " -r < /dev/tty
    local FINAL_HOSTNAME="$CURRENT_HOSTNAME"
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
    
    # 更新hosts文件
    if grep -q "127.0.1.1" /etc/hosts; then
        sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t$FINAL_HOSTNAME/g" /etc/hosts
    else
        echo "127.0.1.1    $FINAL_HOSTNAME" >> /etc/hosts
    fi
}

# 配置时区和BBR (非交互)
configure_timezone_and_bbr() {
    echo -e "\n${YELLOW}=============== 2. 配置时区和BBR ===============${NC}"
    {  
        timedatectl set-timezone Asia/Hong_Kong 2>/dev/null && \
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 时区已设置为 Asia/Hong_Kong"
    } &
    {  
      cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
      sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
      echo -e "${GREEN}[SUCCESS]${NC} ✅ BBR 已启用"
    } &
    wait
}

# 配置Swap (非交互)
configure_swap() {
    echo -e "\n${YELLOW}=============== 3. 配置 Swap (1GB) ===============${NC}"
    if free | awk '/^Swap:/ {exit $2==0?1:0}'; then
        echo -e "${BLUE}[INFO] 检测到已存在 Swap，跳过此步骤。${NC}"
        return 0
    fi
    
    echo -e "${BLUE}[INFO] 正在配置 1024MB Swap...${NC}"
    if [ -f /swapfile ]; then swapoff /swapfile &>/dev/null || true; rm -f /swapfile; fi
    
    if fallocate -l 1G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none 2>/dev/null; then
        chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
        if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 1GB Swap 配置完成"
    else
        echo -e "${RED}[ERROR] Swap 文件创建失败${NC}"
        return 1
    fi
}

# 修复的DNS配置
configure_dns() {
    echo -e "\n${YELLOW}=============== 4. 配置 DNS (智能适配) ===============${NC}"

    if is_known_cloud; then
        echo -e "${GREEN}[INFO]${NC} ✅ 检测到已知云环境，为确保网络稳定，跳过DNS修改。"
        return
    fi
    
    read -p "是否将DNS修改为公共DNS(1.1.1.1, 8.8.8.8)？ [Y/n] 默认 Y: " -r < /dev/tty
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}[INFO] 已取消DNS修改。${NC}"
        return
    fi

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
            cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=2606:4700:4700::1111 2001:4860:4860::8888
EOF
        else
            cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=8.8.4.4 1.0.0.1
EOF
        fi
        
        systemctl restart systemd-resolved
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成。使用 'resolvectl status' 查看。"
    else
        echo -e "${BLUE}[INFO] 未检测到 systemd-resolved，使用传统方式覆盖 /etc/resolv.conf...${NC}"
        
        # 解锁文件（如果被锁定）
        if lsattr /etc/resolv.conf 2>/dev/null | grep -q -- '-i-'; then
            chattr -i /etc/resolv.conf
        fi

        # 写入新的DNS配置
        {
            echo "nameserver 1.1.1.1"
            echo "nameserver 8.8.8.8"
            if [ "$has_ipv6_support" = "true" ]; then
                echo "nameserver 2606:4700:4700::1111"
                echo "nameserver 2001:4860:4860::8888"
            fi
        } > /etc/resolv.conf
        
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成 (传统方式)。"
    fi
}

# 简化的工具安装和Vim配置
install_tools_and_vim() {
    echo -e "\n${YELLOW}=============== 5. 安装常用工具和配置Vim ===============${NC}"
    local packages="sudo wget zip vim curl"
    
    echo -e "${BLUE}[INFO] 更新软件包列表...${NC}"
    apt-get update -qq || { echo -e "${RED}[ERROR] 软件包列表更新失败。${NC}"; return 1; }
    
    echo -e "${BLUE}[INFO] 正在安装: $packages${NC}"
    if apt-get install -y $packages >/dev/null 2>&1; then
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 常用工具安装完成。"
    else
        echo -e "${YELLOW}[WARN] 部分软件包安装失败，请稍后手动安装。${NC}"
    fi

    # 简化的Vim配置
    if command -v vim &> /dev/null; then
        echo -e "${BLUE}[INFO] 配置Vim基础特性...${NC}"
        cat > /etc/vim/vimrc.local << 'EOF'
syntax on
set nocompatible
set backspace=indent,eol,start
set ruler showcmd
set hlsearch incsearch autoindent
set tabstop=4 shiftwidth=4 expandtab
set encoding=utf-8
set mouse=a nobackup noswapfile
EOF
        if [ -d /root ]; then
            echo "source /etc/vim/vimrc.local" > /root/.vimrc
        fi
        echo -e "${GREEN}[SUCCESS]${NC} ✅ Vim配置完成。"
    fi
}

# 系统更新和清理（移除危险参数）
update_and_cleanup() {
    echo -e "\n${YELLOW}=============== 6. 系统更新和清理 ===============${NC}"
    echo -e "${BLUE}[INFO] 执行系统升级... (这可能需要几分钟)${NC}"
    
    # 更安全的升级命令
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" 2>/dev/null || \
    echo -e "${YELLOW}[WARN] 系统升级过程出现错误，但继续执行。${NC}"
    
    echo -e "${BLUE}[INFO] 移除无用依赖并清理缓存...${NC}"
    apt-get autoremove --purge -y &>/dev/null
    apt-get clean &>/dev/null
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 系统更新和清理完成。"
}

# 显示最终摘要
final_summary() {
    echo -e "\n${YELLOW}===================== 配置完成 =====================${NC}"
    echo -e "${GREEN}[SUCCESS]${NC} 🎉 系统初始化配置圆满完成！\n"
    echo "配置摘要："
    echo "  - 主机名: $(hostname)"
    echo "  - 时区: $(timedatectl show --property=Timezone --value 2>/dev/null || echo '未设置')"
    echo "  - BBR状态: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未检测到')"
    echo "  - Swap大小: $(free -h | grep Swap | awk '{print $2}' || echo '未配置')"
    
    local dns_servers=""
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && [ -r /run/systemd/resolve/resolv.conf ]; then
        dns_servers=$(grep '^nameserver' /run/systemd/resolve/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
    else
        dns_servers=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
    fi
    dns_servers=$(echo "$dns_servers" | sed 's/ *$//')
    echo "  - DNS服务器: ${dns_servers:-"未配置或未知"}"
    
    echo -e "\n总执行时间: ${SECONDS} 秒"
}

# --- 主函数 ---
main() {
    trap 'handle_error ${LINENO}' ERR
    SECONDS=0 
    
    if [ -f /etc/os-release ]; then source /etc/os-release; else echo "错误: 无法找到 /etc/os-release"; exit 1; fi
    
    pre_flight_checks
    configure_hostname
    configure_timezone_and_bbr
    configure_swap
    configure_dns
    install_tools_and_vim
    update_and_cleanup
    final_summary
    
    echo
    read -p "是否立即重启系统以确保所有配置生效？ [Y/n] 默认 Y: " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        echo -e "${BLUE}[INFO] 正在立即重启系统...${NC}"
        reboot
    else
        echo -e "${BLUE}[INFO] 配置完成，建议稍后手动重启 (sudo reboot)。${NC}"
    fi
}

# --- 脚本执行入口 ---
main "$@"
