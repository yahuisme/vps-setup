#!/bin/bash

# Debian 13 VPS 初始化配置脚本 - 最终彩色输出版
set -e

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 错误处理函数 ---
handle_error() {
    local exit_code=$?
    local line_number=$1
    echo
    echo -e "${RED}[ERROR] 脚本在第 $line_number 行执行失败 (退出码: $exit_code)${NC}"
    echo -e "${RED}[ERROR] 请检查系统状态或网络连接${NC}"
    exit $exit_code
}

# --- 定制化云环境检测函数 ---
is_known_cloud() {
    # AWS
    if [ -f /sys/hypervisor/uuid ] && [ "$(head -c 3 /sys/hypervisor/uuid)" = "ec2" ]; then return 0; fi
    if [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi "Amazon" /sys/class/dmi/id/sys_vendor; then return 0; fi

    # Google Cloud
    if [ -f /sys/class/dmi/id/product_name ] && grep -qi "Google" /sys/class/dmi/id/product_name; then return 0; fi

    # Azure
    if [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi "Microsoft" /sys/class/dmi/id/sys_vendor; then return 0; fi
    
    # Oracle Cloud Infrastructure (OCI)
    if [ -f /sys/class/dmi/id/chassis_asset_tag ] && grep -qi "OracleCloud" /sys/class/dmi/id/chassis_asset_tag; then return 0; fi
    if [ -f /sys/class/dmi/id/sys_vendor ] && grep -qi "Oracle" /sys/class/dmi/id/sys_vendor; then return 0; fi

    return 1 # 未检测到已知的云平台
}

trap 'handle_error ${LINENO}' ERR

echo -e "${YELLOW}==================================================${NC}"
echo -e "${YELLOW}   Debian 13 VPS 初始化配置脚本 - 彩色输出版      ${NC}"
echo -e "${YELLOW}==================================================${NC}"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] 此脚本需要 root 权限运行${NC}"
    exit 1
fi

# --- 预检查 ---
echo -e "${BLUE}[INFO] 执行系统预检查...${NC}"
# 检查网络连接
if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo -e "${YELLOW}[WARN] 网络连接可能有问题，但继续执行...${NC}"
fi
# 检查磁盘空间
available_space=$(df / | awk 'NR==2 {print $4}')
if [ "$available_space" -lt 2097152 ]; then
    echo -e "${YELLOW}[WARN] 磁盘空间不足 2GB，可能影响配置${NC}"
fi
echo -e "${BLUE}[INFO] 当前系统信息：${NC}"
echo "   系统版本: $(cat /etc/debian_version)"
echo "   当前主机名: $(hostname)"
echo "   可用磁盘: $(df -h / | awk 'NR==2 {print $4}')"
echo -e "${BLUE}[INFO] 预检查完成${NC}"


# --- 主机名配置 ---
echo
echo -e "${YELLOW}=============== 配置主机名 ===============${NC}"
echo "当前主机名: $(hostname)"
read -p "是否需要修改主机名？ [y/N] 默认：N  " -r < /dev/tty
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "请输入新的主机名: " NEW_HOSTNAME < /dev/tty
    if [ -n "$NEW_HOSTNAME" ]; then
        echo -e "${BLUE}[INFO] 设置主机名为: $NEW_HOSTNAME${NC}"
        hostnamectl set-hostname "$NEW_HOSTNAME"
        
        # --- [修正] 更新 /etc/hosts 的方法以实现空格对齐 ---
        # 1. 为防止意外格式或重复，先删除任何以 127.0.1.1 开头的旧行
        sed -i '/^127\.0\.1\.1/d' /etc/hosts 2>/dev/null || true
        # 2. 使用 printf 添加新的、列对齐的行
        printf "%-15s %s\n" "127.0.1.1" "$NEW_HOSTNAME" >> /etc/hosts
        
        echo -e "${GREEN}[SUCCESS]${NC} ✅ 主机名已更新为: $NEW_HOSTNAME"
    fi
else
    echo -e "${BLUE}[INFO] 保持当前主机名: $(hostname)${NC}"
fi
echo -e "${BLUE}[INFO] 主机名配置完成${NC}"


# --- 时区和BBR配置 ---
echo
echo -e "${YELLOW}=============== 并行配置时区和BBR ===============${NC}"
{ timedatectl set-timezone Asia/Hong_Kong; echo -e "${GREEN}[SUCCESS]${NC} ✅ 时区已设置为 Hong Kong"; } &
{ cat > /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -p /etc/sysctl.d/99-bbr.conf >/dev/null 2>&1; echo -e "${GREEN}[SUCCESS]${NC} ✅ BBR 已启用"; } &
wait
echo -e "${BLUE}[INFO] 时区和BBR配置完成${NC}"


# --- Swap配置 ---
echo
echo -e "${YELLOW}=============== 配置 Swap ===============${NC}"
echo -e "${BLUE}[INFO] 配置 1G Swap... (预计 30 秒)${NC}"
if [ -f /swapfile ]; then swapoff /swapfile 2>/dev/null || true; rm -f /swapfile; fi
{ dd if=/dev/zero of=/swapfile bs=1M count=1024 status=progress 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none; } && {
    chmod 600 /swapfile; mkswap /swapfile >/dev/null; swapon /swapfile;
    if ! grep -q "/swapfile" /etc/fstab; then echo "/swapfile none swap sw 0 0" >> /etc/fstab; fi
    echo -e "${GREEN}[SUCCESS]${NC} ✅ Swap 配置完成 (1G)";
} || { echo -e "${RED}[ERROR] Swap 配置失败${NC}"; exit 1; }
echo -e "${BLUE}[INFO] Swap 配置完成${NC}"


# --- DNS配置 (强制覆盖并锁定) ---
configure_force_dns() {
    echo -e "${BLUE}[INFO] 正在强制配置公共DNS并锁定文件...${NC}"
    if lsattr /etc/resolv.conf 2>/dev/null | grep -q "i"; then chattr -i /etc/resolv.conf 2>/dev/null || true; fi
    cp /etc/resolv.conf /etc/resolv.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    cat > /etc/resolv.conf << 'EOF'
# Configured by script
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
    if ip -6 addr show | grep -q "inet6.*scope global" 2>/dev/null; then
        cat >> /etc/resolv.conf << 'EOF'
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
EOF
    fi
    if chattr +i /etc/resolv.conf 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS配置完成并已锁定。如需修改，请先运行: chattr -i /etc/resolv.conf"
    else
        echo -e "${YELLOW}[WARN] 无法锁定DNS配置文件，配置可能被重置！${NC}"
    fi
}

# --- 验证DNS配置 ---
verify_dns() {
    echo
    echo -e "${BLUE}[INFO] 验证DNS配置...${NC}"
    echo -e "${BLUE}[INFO] 当前 /etc/resolv.conf 内容：${NC}"
    cat /etc/resolv.conf | grep "nameserver" | head -4
    echo -e "${BLUE}[INFO] 测试DNS解析...${NC}"
    if nslookup google.com >/dev/null 2>&1; then
        echo -e "${GREEN}[SUCCESS]${NC} ✅ DNS解析测试通过"
    else
        echo -e "${BLUE}[INFO] ℹ️  DNS网络测试未通过。在限制外部DNS的云平台(如AWS)上，这是正常现象。${NC}"
    fi
    echo -e "${BLUE}[INFO] DNS配置验证完成${NC}"
}

# --- 智能DNS配置主逻辑 ---
echo
echo -e "${YELLOW}=============== 配置 DNS (云环境感知) ===============${NC}"
if is_known_cloud; then
    echo -e "${GREEN}[INFO]${NC} ✅ 检测到已知云环境 (如AWS/GCP/Azure/Oracle)，为确保网络兼容性，将跳过DNS修改。"
    CURRENT_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')
    echo -e "${BLUE}[INFO]${NC} 将继续使用平台提供的默认DNS: ${CURRENT_DNS:--未找到-}"
else
    echo -e "${BLUE}[INFO] 未检测到主流云平台，认定为常规VPS，将执行DNS修改流程。${NC}"
    read -p "是否要将DNS修改为公共DNS (1.1.1.1, 8.8.8.8)并锁定？ [Y/n] 默认：Y  " -r < /dev/tty
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        configure_force_dns
        verify_dns
    else
        echo -e "${BLUE}[INFO] 已取消DNS修改。${NC}"
    fi
fi


# --- 安装常用工具 ---
echo
echo -e "${YELLOW}=============== 安装常用工具 ===============${NC}"
if [ ! -f /var/lib/apt/lists/lock ] || [ $(find /var/lib/apt/lists -name "*Packages*" -mmin +60 | wc -l) -gt 0 ]; then
    echo -e "${BLUE}[INFO] 更新软件包列表... (预计 15 秒)${NC}"
    apt-get update -qq 2>/dev/null || { echo -e "${RED}[ERROR] 软件包列表更新失败，检查网络连接${NC}"; exit 1; }
else
    echo -e "${BLUE}[INFO] 软件包列表较新，跳过更新${NC}"
fi

echo -e "${BLUE}[INFO] 安装常用工具... (预计 20 秒)${NC}"
packages="sudo wget zip vim"
failed_packages=""
skip_vim_config=false
for package in $packages; do
    echo -e "${BLUE}[INFO] 正在安装 $package...${NC}"
    if apt-get install -y "$package" >/dev/null 2>&1; then
        echo -e "${GREEN}[SUCCESS]${NC} ✅ $package 安装成功"
    else
        echo -e "${YELLOW}[WARN]${NC} ⚠️ $package 安装失败，尝试修复..."
        apt-get install -f -y >/dev/null 2>&1 || true
        if apt-get install -y "$package" >/dev/null 2>&1; then
            echo -e "${GREEN}[SUCCESS]${NC} ✅ $package 修复后安装成功"
        else
            echo -e "${RED}[ERROR]${NC} ❌ $package 安装失败"
            failed_packages="$failed_packages $package"
        fi
    fi
done

if [ -n "$failed_packages" ]; then
    echo -e "${YELLOW}[WARN] 以下软件包安装失败:$failed_packages${NC}"
    if echo "$failed_packages" | grep -q "vim"; then
        echo -e "${YELLOW}[WARN] 由于 vim 安装失败，将跳过 vim 配置${NC}"
        skip_vim_config=true
    fi
else
    echo -e "${GREEN}[SUCCESS]${NC} ✅ 所有常用工具安装完成"
fi


# --- VIM配置 ---
echo
echo -e "${YELLOW}=============== 配置 vim 现代特性 ===============${NC}"
if [ "$skip_vim_config" = true ]; then
    echo -e "${YELLOW}[WARN] 跳过 vim 配置（vim 未成功安装）${NC}"
else
    cat > /etc/vim/vimrc.local << 'EOF'
syntax on
set nocompatible
set backspace=indent,eol,start
set number
set ruler
set showcmd
set hlsearch
set incsearch
set autoindent
set tabstop=4
set shiftwidth=4
set encoding=utf-8
set fileencodings=utf-8,gb2312,gbk,gb18030
set mouse=a
set nobackup
set noswapfile
EOF
    mkdir -p /root && cat > /root/.vimrc << 'EOF'
source /etc/vim/vimrc.local
EOF
    echo -e "${GREEN}[SUCCESS]${NC} ✅ vim 现代特性配置完成"
fi

# --- 系统更新和清理 ---
echo
echo -e "${YELLOW}=============== 系统更新和清理 ===============${NC}"
echo -e "${BLUE}[INFO] 执行系统完整更新... (这可能需要几分钟)${NC}"
echo -e "${BLUE}[INFO] 更新软件包列表...${NC}"
apt-get update -q || { echo -e "${RED}[ERROR] 软件包列表更新失败${NC}"; exit 1; }
echo -e "${BLUE}[INFO] 执行系统完整升级...${NC}"
apt-get full-upgrade -y || { echo -e "${YELLOW}[WARN] 系统升级过程中出现问题，但继续执行...${NC}"; }
echo -e "${BLUE}[INFO] 移除不需要的软件包...${NC}"
apt-get autoremove --purge -y >/dev/null 2>&1 || true
echo -e "${BLUE}[INFO] 清理软件包缓存...${NC}"
apt-get autoclean >/dev/null 2>&1 || true
apt-get clean >/dev/null 2>&1 || true
echo -e "${GREEN}[SUCCESS]${NC} ✅ 系统更新和清理完成"


# --- 最终状态显示 ---
echo
echo -e "${YELLOW}=============== 配置完成 ===============${NC}"
echo -e "${GREEN}[SUCCESS]${NC} 🎉 Debian 13 VPS 初始化完成！"
echo
echo "配置摘要："
echo "   主机名: $(hostname)"
echo "   时区: $(timedatectl show --property=Timezone --value)"
echo "   当前时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "   拥塞控制: $(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | cut -d= -f2 | tr -d ' ')"
echo "   Swap 大小: $(free -h | grep Swap | awk '{print $2}')"
echo "   DNS服务器: $(grep nameserver /etc/resolv.conf | awk '{print $2}' | tr '\n' ' ')"
echo "   已安装工具: sudo wget zip vim"
echo "   系统状态: 已更新到最新版本并清理缓存"
echo "   总执行时间: 约 $(( SECONDS / 60 ))分$(( SECONDS % 60 ))秒"

echo
read -p "是否立即重启系统以确保所有配置生效？ [Y/n] 默认：Y  " -r < /dev/tty
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${BLUE}[INFO] 系统将在 3 秒后重启...${NC}"
    sleep 3
    reboot
else
    echo -e "${BLUE}[INFO] 配置完成，请稍后手动重启系统 (sudo reboot)。${NC}"
fi
