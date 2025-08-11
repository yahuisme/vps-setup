#!/bin/bash

# ==============================================================================
# Debian & Ubuntu LTS VPS 通用初始化脚本
# 版本: 2.7
# 更新日志 (v2.7):
#   - [修正] 彻底重写 final_summary 的 DNS 获取逻辑。优先读取 systemd-resolved
#     生成的底层 resolv.conf 文件，而不是解析人类可读的 status 输出，
#     以彻底解决在某些环境下 DNS 显示重复的问题。
#
# 特性:
#   - 兼容 Debian 10-13 和 Ubuntu 20.04-24.04 LTS
#   - 智能识别系统并采用最佳配置方案 (特别是DNS)
#   - 最小化交互，自动化执行
#   - 云环境智能感知
#   - 完整的错误处理和彩色输出
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
    [ -f /sys/hypervisor/uuid ] && [ "$(head -c 3 /sys/hypervisor/uuid)" = "ec2" ] && return 0
    [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi "Amazon\|Microsoft\|Oracle" /sys/class/dmi/id/sys_vendor && return 0
    [ -f /sys/class/dmi/id/product_name ] && grep -qi "Google" /sys/class/dmi/id/product_name && return 0
    [ -f /sys/class/dmi/id/chassis_asset_tag ] && grep -qi "OracleCloud" /sys/class/dmi/id/chassis_asset_tag && return 0
    return 1
}

# 系统预检
pre_flight_checks() {
    echo -e "${BLUE}[INFO] 正在执行系统预检查...${NC}"
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] 此脚本需要 root 权限运行。${NC}"; exit 1
    fi

    local supported=false
    if [ "$ID" = "debian" ] && [[ "$VERSION_ID" =~ ^(10|11|12|13) ]]; then
        supported=true
    elif [ "$ID" = "ubuntu" ] && [[ "$VERSION_ID" =~ ^(20.04|22.04|24.04) ]]; then
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
        if [ -n "$NEW_HOSTNAME" ]; then
            hostnamectl set-hostname "$NEW_HOSTNAME"
            FINAL_HOSTNAME="$NEW_HOSTNAME"
            echo -e "${GREEN}[SUCCESS]${NC} ✅ 主机名已更新为: $FINAL_HOSTNAME"
        else
            echo -e "${YELLOW}[WARN] 未输入新主机名，保持不变。${NC}"
        fi
    else
        echo -e "${BLUE}[INFO] 保持当前主机名。${NC}"
    fi
    
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
        timedatectl set-timezone Asia/Hong_Kong
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 时区已设置为 Asia/Hong_Kong"
    } &
    {  
      cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
      sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1
      echo -e "${GREEN}[SUCCESS]${NC} ✅ BBR 已启用。"
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
    
    fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none || {
        echo -e "${RED}[ERROR] 创建 Swap 文件失败。${NC}"; return 1;
    }

    chmod 600 /swapfile; mkswap /swapfile >/dev/null; swapon /swapfile
    if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 1GB Swap 配置完成。"
}

# 配置DNS (兼容Debian和Ubuntu)
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

    if systemctl is-active --quiet systemd-resolved; then
        echo -e "${BLUE}[INFO] 检测到 systemd-resolved 服务，使用 resolvectl 配置DNS...${NC}"
        
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << 'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=2606:4700:4700::1111 2001:4860:4860::8888
EOF
        
        systemctl restart systemd-resolved
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS 配置完成。使用 'resolvectl status' 查看。"
    else
        echo -e "${BLUE}[INFO] 未检测到 systemd-resolved，使用传统方式覆盖 /etc/resolv.conf...${NC}"
        cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
        cat > /etc/resolv.conf << 'EOF'
# Configured by script
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
EOF
        echo -e "${GREEN}[SUCCESS]${NC} ✅ Debian DNS 配置完成 (传统方式)。"
        echo -e "${YELLOW}[WARN] 此方式可能被网络服务覆盖。如需持久化，请修改网络管理工具(如 ifupdown)的配置。${NC}"
    fi
}

# 安装工具和Vim配置
install_tools_and_vim() {
    echo -e "\n${YELLOW}=============== 5. 安装常用工具和配置Vim ===============${NC}"
    local packages_to_install="sudo wget zip vim curl"
    
    echo -e "${BLUE}[INFO] 更新软件包列表...${NC}"
    apt-get update -qq || { echo -e "${RED}[ERROR] 软件包列表更新失败。${NC}"; return 1; }
    
    echo -e "${BLUE}[INFO] 正在安装: $packages_to_install${NC}"
    if ! apt-get install -y $packages_to_install >/dev/null 2>&1; then
        echo -e "${YELLOW}[WARN] 软件包安装失败，正在尝试修复并重试...${NC}"
        apt-get --fix-broken install -y >/dev/null 2>&1
        apt-get install -y $packages_to_install >/dev/null 2>&1 || echo -e "${RED}[ERROR] 工具安装失败。${NC}"
    fi
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 常用工具安装完成。"

    if command -v vim &> /dev/null; then
        echo -e "${BLUE}[INFO] 配置Vim现代特性...${NC}"
        cat > /etc/vim/vimrc.local << 'EOF'
syntax on
set nocompatible
set backspace=indent,eol,start
set ruler showcmd
set hlsearch incsearch autoindent
set tabstop=4 shiftwidth=4
set encoding=utf-8 fileencodings=utf-8,gbk,gb18030
set mouse=a nobackup noswapfile
EOF
        if [ -d /root ]; then
             cat > /root/.vimrc << 'EOF'
source /etc/vim/vimrc.local
EOF
        fi
        echo -e "${GREEN}[SUCCESS]${NC} ✅ Vim配置完成。"
    fi
}

# 系统更新和清理
update_and_cleanup() {
    echo -e "\n${YELLOW}=============== 6. 系统更新和清理 ===============${NC}"
    echo -e "${BLUE}[INFO] 执行系统完整升级... (这可能需要几分钟)${NC}"
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" --allow-downgrades --allow-remove-essential --allow-change-held-packages || echo -e "${YELLOW}[WARN] 系统升级过程出现非致命错误。${NC}"
    
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
    echo "  - 时区: $(timedatectl show --property=Timezone --value)"
    echo "  - BBR状态: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '未检测到')"
    echo "  - Swap大小: $(free -h | grep Swap | awk '{print $2}')"
    
    local dns_servers=""
    # 修正: 采用更可靠的方式获取DNS信息
    if systemctl is-active --quiet systemd-resolved && [ -r /run/systemd/resolve/resolv.conf ]; then
        # 优先读取 systemd-resolved 生成的 resolv.conf，这是最准确的源
        dns_servers=$(grep '^nameserver' /run/systemd/resolve/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    else
        # 后备方案: 读取传统的 /etc/resolv.conf
        dns_servers=$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    fi
    
    # 清理行尾可能多余的空格
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
        echo -e "${BLUE}[INFO] 系统将在 3 秒后重启...${NC}"
        sleep 3
        reboot
    else
        echo -e "${BLUE}[INFO] 配置完成，建议稍后手动重启 (sudo reboot)。${NC}"
    fi
}

# --- 脚本执行入口 ---
main "$@"
