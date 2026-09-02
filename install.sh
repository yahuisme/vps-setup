#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: v26.09.02
# ==============================================================================
set -euo pipefail

# --- 默认配置 ---
# shellcheck disable=SC2034
SCRIPT_VERSION="v26.09.02"
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
SWAP_SIZE_MB="auto"
SWAP_TARGET_MB=""
INSTALL_PACKAGES=(sudo wget zip vim curl)
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
BBR_MODE="default"
ENABLE_FAIL2BAN=true
UPGRADE_SYSTEM=false
CLEAN_SYSTEM=false
# --- SSH 相关配置 ---
NEW_SSH_PORT=""
NEW_SSH_PASSWORD=""

# --- 颜色和全局变量 ---
readonly GREEN=$'\033[0;32m' RED=$'\033[0;31m' YELLOW=$'\033[1;33m'
readonly BLUE=$'\033[0;34m' CYAN=$'\033[0;36m' BOLD=$'\033[1m' DIM=$'\033[2m' NC=$'\033[0m'

non_interactive=false
LOG_FILE=""
# 后台 apt(如 unattended-upgrades)持锁时最多等待 600 秒，避免直接失败
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=600)
VERIFICATION_PASSED=0
VERIFICATION_FAILED=0
VERIFICATION_WARNINGS=0

log() {
    printf '%b\n' "$1"
}

display_width() {
    # 估算字符串的终端显示宽度（中文等宽字符按 2 列计），用于对齐；自动剥离 ANSI 颜色码。
    # 按字节解析 UTF-8，不依赖系统 locale（C locale 下同样正确）。
    local s="$1"
    s=$(printf '%s' "$s" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
    printf '%s' "$s" | od -An -v -tu1 | awk '
    {
        for (i = 1; i <= NF; i++) {
            b = $i
            if (b >= 192) { w += 2 }        # UTF-8 多字节首字节：按 2 列
            else if (b < 128) { w += 1 }    # ASCII：1 列
        }                                   # 128-191 续字节：跳过
    }
    END { print w }'
}

format_duration() {
    local seconds="$1" minutes
    if (( seconds < 60 )); then
        echo "${seconds} 秒"
    else
        minutes=$((seconds / 60)); seconds=$((seconds % 60))
        echo "${minutes} 分 ${seconds} 秒"
    fi
}

result_warn() {
    log "${YELLOW}  ⚠ $1${NC}"
}

section_header() {
    # 编号与标题（number 可为空）；close=false 时只画上框，便于插入内容行
    local number="$1" title="$2" close="${3:-true}" text fill
    if [[ -n "$title" ]]; then
        text="${number:+${number}. }${title}"
    else
        text="${number}"
    fi
    local box_width=46
    fill=$((box_width - $(display_width "$text") - 2))
    (( fill < 1 )) && fill=1
    log ""
    log "${YELLOW}╭──────────────────────────────────────────────╮${NC}"
    printf '%b' "${YELLOW}│  ${BOLD}${text}${NC}"
    printf '%*s' "$fill" ""
    printf '%b\n' "${YELLOW}│${NC}"
    if [[ "$close" = true ]]; then
        log "${YELLOW}╰──────────────────────────────────────────────╯${NC}"
    fi
}

print_summary_row() {
    # 配置摘要行：标签列宽 10，值右侧填充对齐右边界
    local label="$1" value="$2" pad fill2
    pad=$((10 - $(display_width "$label"))); (( pad < 1 )) && pad=1
    fill2=$((32 - $(display_width "$value"))); (( fill2 < 1 )) && fill2=1
    printf '%b' "${CYAN}│  ${label}"
    printf '%*s' "$pad" ""
    printf '%b' ": ${value}"
    printf '%*s' "$fill2" ""
    printf '%b\n' "${CYAN}│${NC}"
}

print_box_row() {
    # 框内普通行：内容右侧填充对齐右边界（content 可含颜色码）
    local content="$1" fill2
    fill2=$((44 - $(display_width "$content"))); (( fill2 < 1 )) && fill2=1
    printf '%b' "${CYAN}│  ${content}${NC}"
    printf '%*s' "$fill2" ""
    printf '%b\n' "${CYAN}│${NC}"
}

summary_close() {
    log "${YELLOW}╰──────────────────────────────────────────────╯${NC}"
}

step_info() {
    log "${BLUE}  ▸ $1${NC}"
}

result_ok() {
    log "${GREEN}  ✔ $1${NC}"
}


# shellcheck disable=SC2317 # 由 trap 'handle_error' 调用，静态分析不可见
handle_error() {
    local exit_code=$? line_number=$1
    set +e

    local error_message="\n${RED}✗ [ERROR] 脚本在第 ${line_number} 行失败 (退出码: ${exit_code})${NC}"
    printf '%b\n' "$error_message"
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] Script failed at line ${line_number} (exit code: ${exit_code})" >> "$LOG_FILE"
    exit "$exit_code"
}


has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' ||
        ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'
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

is_kernel_version_ge() {
    local required="$1" current
    current=$(uname -r | sed -nE 's/^([0-9]+\.[0-9]+).*/\1/p')
    [[ -n "$current" ]] && [[ "$(printf '%s\n' "$current" "$required" | sort -V | head -n1)" = "$required" ]]
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
    local current_cc current_qdisc
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    if [[ "$BBR_MODE" = "none" ]]; then
        if [[ "$current_cc" != "bbr" ]]; then
            record_verification "BBR" "PASS" "已禁用"
        else
            record_verification "BBR" "WARN" "可能需要重启生效 (当前: ${current_cc})"
        fi
    elif [[ "$current_cc" = "bbr" && "$current_qdisc" = "fq" ]]; then
        record_verification "BBR" "PASS" "已启用 (${BBR_MODE}模式)"
    else
        record_verification "BBR" "FAIL" "配置异常: ${current_cc}/${current_qdisc}"
    fi
}

verify_swap() {
    local current_swap_mb
    current_swap_mb=$(awk '/SwapTotal/ {print int($2/1024 + 0.5)}' /proc/meminfo)
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        if [[ $current_swap_mb -eq 0 ]]; then
            record_verification "Swap" "PASS" "已禁用"
        else
            record_verification "Swap" "FAIL" "期望禁用但仍有${current_swap_mb}MB"
        fi
    elif [[ -n "$SWAP_TARGET_MB" ]]; then
        if [[ $current_swap_mb -eq "$SWAP_TARGET_MB" ]]; then
            record_verification "Swap" "PASS" "${current_swap_mb}MB"
        else
            record_verification "Swap" "FAIL" "期望 ${SWAP_TARGET_MB}MB，实际 ${current_swap_mb}MB"
        fi
    elif [[ $current_swap_mb -gt 0 ]]; then
        record_verification "Swap" "PASS" "${current_swap_mb}MB"
    else
        record_verification "Swap" "FAIL" "未配置"
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
    elif (systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null); then
        record_verification "时间同步" "WARN" "正在使用第三方NTP (chrony/ntp)"
    else
        record_verification "时间同步" "FAIL" "NTP服务未运行"
    fi
}

run_verification() {
    section_header "" "配置验证"
    VERIFICATION_PASSED=0 VERIFICATION_FAILED=0 VERIFICATION_WARNINGS=0
    set +e
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    verify_config "时区" "$TIMEZONE" "$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    verify_time_sync
    verify_bbr

    verify_swap
    verify_dns
    local installed=0 total=0
    for pkg in "${INSTALL_PACKAGES[@]}"; do
        total=$((total + 1))
        dpkg -l "$pkg" >/dev/null 2>&1 && installed=$((installed + 1))
    done
    if [[ $installed -eq $total ]]; then
        record_verification "软件包" "PASS" "全部已安装 ($installed/$total)"
    else
        record_verification "软件包" "FAIL" "部分缺失 ($installed/$total)"
    fi
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local current_port
        current_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
        if grep -Fxq "$NEW_SSH_PORT" <<< "$current_port"; then
            record_verification "SSH端口" "PASS" "已监听/配置为 '${NEW_SSH_PORT}'"
        else
            record_verification "SSH端口" "FAIL" "期望 '${NEW_SSH_PORT}'，实际 '${current_port:-未知}'"
        fi
    fi
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then
        if (systemctl is-active --quiet fail2ban 2>/dev/null); then
            record_verification "Fail2ban" "PASS" "运行正常"
        else
            record_verification "Fail2ban" "FAIL" "服务异常"
        fi
    fi
    set -e
    log "\n${BOLD}验证结果:${NC}  ${GREEN}✔ 通过 ${VERIFICATION_PASSED}${NC}    ${YELLOW}⚠ 警告 ${VERIFICATION_WARNINGS}${NC}    ${RED}✗ 失败 ${VERIFICATION_FAILED}${NC}"
}

usage() {
    local exit_code="${1:-0}" out=/dev/stdout
    [[ "$exit_code" -eq 0 ]] || out=/dev/stderr
    cat > "$out" << EOF
${BOLD}用法: $0 [选项]${NC}

${YELLOW}▸ 核心${NC}
  --hostname <name>        设置主机名
  --timezone <tz>          设置时区
  --swap <size_mb>         设置 Swap 大小（auto / 0 / MB）
  --ip-dns <'主 备'>        设置 IPv4 DNS
  --ip6-dns <'主 备'>       设置 IPv6 DNS

${YELLOW}▸ BBR${NC}
  --bbr                    启用 BBR（默认）
  --no-bbr                 禁用 BBR

${YELLOW}▸ 安全${NC}
  --fail2ban               启用 Fail2ban，保护 SSH
  --no-fail2ban            禁用 Fail2ban
  --ssh-port <port>        设置 SSH 端口
  --ssh-password <pass>    设置 root 密码
  --upgrade                执行系统 full-upgrade
  --cleanup                执行 autoremove 和 apt clean

${YELLOW}▸ 其他${NC}
  -h, --help               显示帮助
  --non-interactive        非交互模式

${GREEN}示例: $0 --bbr --ssh-port 2222${NC}
EOF
    exit "$exit_code"
}

require_value() {
    [[ $# -ge 2 && -n "${2:-}" && "$2" != -* ]] || {
        printf '%b\n' "${RED}选项 $1 需要一个参数${NC}" >&2
        exit 2
    }
}

valid_ipv4() {
    local ip="$1" octet
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        # Force base-10 so 08/09 do not trigger Bash's octal parsing.
        (( 10#$octet <= 255 )) || return 1
    done
}

valid_ipv6() {
    local ip="$1" group groups
    [[ "$ip" =~ ^[0-9A-Fa-f:]+$ && "$ip" == *:* ]] || return 1
    [[ "$ip" != *::*::* && "$ip" != *:::* ]] || return 1
    # 单个首/尾冒号(非 ::) 属于非法地址，read 会吞掉边界空字段导致误判
    [[ "$ip" != :* || "$ip" == ::* ]] || return 1
    [[ "$ip" != *: || "$ip" == *:: ]] || return 1
    groups="${ip//:/ }"
    read -ra groups <<< "$groups"
    for group in "${groups[@]}"; do
        [[ -z "$group" || "$group" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    done
    if [[ "$ip" == *::* ]]; then
        [[ ${#groups[@]} -lt 8 ]]
    else
        [[ ${#groups[@]} -eq 8 ]]
    fi
}

ensure_swap_fstab_entry() {
    grep -Eq '^[[:space:]]*/swapfile[[:space:]]+' /etc/fstab ||
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
}

parse_args() {

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) [[ $# -eq 1 ]] || usage 2; usage 0 ;;
            --hostname)
                require_value "$@"
                [[ "$2" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || {
                    printf '%b\n' "${RED}无效主机名: $2${NC}" >&2
                    exit 2
                }
                NEW_HOSTNAME="$2"
                shift 2
                ;;
            --timezone)
                require_value "$@"
                if command -v timedatectl >/dev/null 2>&1 && ! timedatectl list-timezones 2>/dev/null | grep -Fxq "$2"; then
                    printf '%b\n' "${RED}无效时区: $2${NC}" >&2
                    exit 2
                fi
                TIMEZONE="$2"; shift 2 ;;
            --swap)
                require_value "$@"
                [[ "$2" = "auto" || "$2" =~ ^(0|[1-9][0-9]*)$ ]] || { printf '%b\n' "${RED}--swap 必须是 auto、0 或正整数 MB${NC}" >&2; exit 2; }
                SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns)
                require_value "$@"; read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"
                if ! valid_ipv4 "$PRIMARY_DNS_V4" || ! valid_ipv4 "$SECONDARY_DNS_V4"; then
                    printf '%b\n' "${RED}--ip-dns 需要两个有效 IPv4 地址${NC}" >&2
                    exit 2
                fi
                shift 2 ;;
            --ip6-dns)
                require_value "$@"; read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"
                if ! valid_ipv6 "$PRIMARY_DNS_V6" || ! valid_ipv6 "$SECONDARY_DNS_V6"; then
                    printf '%b\n' "${RED}--ip6-dns 需要两个有效 IPv6 地址${NC}" >&2
                    exit 2
                fi
                shift 2 ;;
            --bbr) BBR_MODE="default"; shift ;;
            --no-bbr) BBR_MODE="none"; shift ;;
            --fail2ban)
                ENABLE_FAIL2BAN=true
                shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --ssh-port)
                require_value "$@"
                [[ "$2" =~ ^[0-9]+$ && "$2" -ge 1 && "$2" -le 65535 ]] || { printf '%b\n' "${RED}--ssh-port 必须是 1-65535 的端口${NC}" >&2; exit 2; }
                NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password) require_value "$@"; NEW_SSH_PASSWORD="$2"; shift 2 ;;
            --upgrade) UPGRADE_SYSTEM=true; shift ;;
            --cleanup) CLEAN_SYSTEM=true; shift ;;
            --non-interactive) non_interactive=true; shift ;;
            *) printf '%b\n' "${RED}未知选项: $1${NC}" >&2; usage 2 ;;
        esac
    done
}

pre_flight_checks() {
    step_info "系统预检查..."

    if is_container; then
        log "${RED}[ERROR] 不支持在容器环境执行，请在完整 VPS 或虚拟机中运行${NC}"
        exit 1
    fi
    [[ ! -f /etc/os-release ]] && { log "${RED}错误: 系统信息缺失${NC}"; exit 1; }
    source /etc/os-release
    local supported=false
    [[ "$ID" = "debian" && "$VERSION_ID" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "$ID" = "ubuntu" && "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]] && supported=true
    if [[ "$supported" = "false" ]]; then
        log "${YELLOW}[WARN] 系统: ${PRETTY_NAME} (建议使用Debian 10-13或Ubuntu 20.04-24.04)${NC}"
        if [[ "$non_interactive" = true ]]; then
            log "${RED}[ERROR] 非交互模式不支持当前系统，已中止${NC}"
            exit 1
        fi
        read -p "继续? [y/N] " -r < /dev/tty
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0
    fi
    result_ok "系统: ${PRETTY_NAME}"
}

install_packages() {
    section_header "1" "软件包安装"
    step_info "更新软件包列表..."
    DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" update -qq >> "$LOG_FILE" 2>&1
    step_info "安装基础软件包..."
    DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y "${INSTALL_PACKAGES[@]}" >> "$LOG_FILE" 2>&1
    result_ok "基础软件包安装完成：${INSTALL_PACKAGES[*]}"
}

configure_hostname() {
    section_header "2" "主机名配置"
    local current_hostname
    current_hostname=$(hostname)
    log "${BLUE}  当前主机名：${current_hostname}${NC}"
    local final_hostname="$current_hostname"
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOG_FILE" 2>&1
            final_hostname="$NEW_HOSTNAME"
            log "${GREEN}✅ 主机名设为: ${NEW_HOSTNAME}${NC}"
        fi
    elif [[ "$non_interactive" = false ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            read -r -p "输入新主机名: " new_name < /dev/tty
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
            printf '%b\n' "127.0.1.1\t${final_hostname}" >> /etc/hosts
        fi
    fi
}

configure_timezone() {
    section_header "3" "时区配置"
    step_info "设置时区：${TIMEZONE}"
    timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1
    result_ok "时区已设置：${TIMEZONE}"
}

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

    # 启用现有服务，必要时安装后再启用。
    if systemctl cat systemd-timesyncd >/dev/null 2>&1; then
        step_info "启用 systemd-timesyncd..."
    elif ! systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        log "${YELLOW}[WARN] systemd-timesyncd 未运行或不存在，尝试安装...${NC}"
        step_info "安装 systemd-timesyncd..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y systemd-timesyncd >> "$LOG_FILE" 2>&1
    fi
    systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
    timedatectl set-ntp true >> "$LOG_FILE" 2>&1 || systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
    
    if timedatectl status 2>/dev/null | grep -q 'NTP service: active' || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        result_ok "时间同步配置完成"
    else
        log "${RED}[ERROR] 时间同步配置未生效${NC}"
        return 1
    fi
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

configure_bbr() {
    section_header "5" "BBR 配置"
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
    
    log "${BLUE}仅启用 BBR 核心参数：fq + bbr${NC}"
    cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    if ! sysctl -p "$config_file" >> "$LOG_FILE" 2>&1; then
        result_warn "部分 BBR 参数不受当前内核支持，将继续验证核心参数"
    fi
    verify_bbr_runtime "$config_file"
}

disable_active_swap() {
    # 关闭全部已激活 Swap；失败时清理 $1（可选临时文件）并返回 1
    local cleanup_file="${1:-}" active_swap
    while IFS= read -r active_swap; do
        [[ -n "$active_swap" ]] || continue
        if ! swapoff "$active_swap" >> "$LOG_FILE" 2>&1; then
            [[ -n "$cleanup_file" ]] && rm -f "$cleanup_file"
            log "${RED}[ERROR] 无法关闭现有 Swap：${active_swap}，保留原配置。${NC}"
            return 1
        fi
    done < <(swapon --show=NAME --noheadings 2>/dev/null)
}

remove_fstab_swap_entries() {
    # 删除 fstab 中所有非注释 swap 条目（含分区与文件 Swap）
    sed -i -E '\|^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+[^[:space:]]+[[:space:]]+swap([[:space:]]\|$)|d' /etc/fstab
}

configure_swap() {
    section_header "6" "Swap 配置"
    if [[ "$SWAP_SIZE_MB" = "0" ]]; then
        log "${BLUE}  Swap：禁用${NC}"
        local swap_file="/swapfile"
        disable_active_swap
        rm -f "$swap_file"
        # --swap 0 means disable all fstab swap entries, not only /swapfile.
        remove_fstab_swap_entries
        if [[ -n "$(swapon --show=NAME --noheadings 2>/dev/null)" ]]; then
            log "${RED}[ERROR] Swap 未能完全禁用。${NC}"
            return 1
        fi
        log "${GREEN}  ✔ Swap 已禁用并移除${NC}"
        return 0
    fi
    local swap_mb
    if [[ "$SWAP_SIZE_MB" = "auto" ]]; then
        local mem_mb
        mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
        if [[ $mem_mb -lt 1024 ]]; then swap_mb=$mem_mb
        elif [[ $mem_mb -lt 4096 ]]; then swap_mb=2048
        else swap_mb=4096; fi
        log "${BLUE}  自动计算目标 Swap：${swap_mb}MB${NC}"
    else
        swap_mb="$SWAP_SIZE_MB"
        log "${BLUE}  指定目标 Swap：${swap_mb}MB${NC}"
    fi
    SWAP_TARGET_MB="$swap_mb"
    check_disk_space $((swap_mb + 100)) || return 1
    local swap_file="/swapfile"
    local current_total_mb=0 size_bytes
    while IFS= read -r swap_line; do
        [[ -n "$swap_line" ]] || continue
        size_bytes=$(awk '{print $2}' <<< "$swap_line")
        [[ "$size_bytes" =~ ^[0-9]+$ ]] && current_total_mb=$((current_total_mb + (size_bytes + 524288) / 1048576 ))
    done < <(swapon --show=NAME,SIZE --bytes --noheadings 2>/dev/null)
    if [[ "$current_total_mb" -eq "$swap_mb" ]]; then
        if swapon --show=NAME --noheadings 2>/dev/null | grep -Fxq "$swap_file"; then
            ensure_swap_fstab_entry
        fi
        log "${GREEN}  ✔ 现有 Swap 与目标一致（${current_total_mb}MB），保留${NC}"
        return
    fi
    [[ "$current_total_mb" -gt 0 ]] && log "${YELLOW}  现有 Swap ${current_total_mb}MB 与目标 ${swap_mb}MB 不一致，将统一替换为 /swapfile${NC}"
    local new_swap="${swap_file}.new.$$"
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
    # 先创建新文件（旧 Swap 仍在运行，创建失败不影响现状）
    log "${BLUE}创建${swap_mb}MB Swap文件...${NC}"
    # 创建阶段失败时也清理临时文件，避免下次运行留下脏状态。
    # fallocate 不可用或失败（如 overlay 文件系统）时回退 dd。
    step_info "创建 Swap 文件（fallocate 优先，失败回退 dd）..."
    if ! { command -v fallocate &>/dev/null && fallocate -l "${swap_mb}M" "$new_swap" >> "$LOG_FILE" 2>&1; } && \
       ! dd if=/dev/zero of="$new_swap" bs=1M count="$swap_mb" status=none >> "$LOG_FILE" 2>&1; then
        rm -f "$new_swap"
        log "${RED}[ERROR] Swap文件创建失败。${NC}"
        return 1
    fi
    chmod 600 "$new_swap"
    if ! mkswap "$new_swap" >> "$LOG_FILE" 2>&1; then
        rm -f "$new_swap"
        log "${RED}[ERROR] Swap格式化失败。${NC}"
        return 1
    fi
    # 新文件就绪后，再关闭全部旧 Swap 并移除 fstab 条目（含分区 Swap）
    if [[ "$current_total_mb" -gt 0 ]]; then
        disable_active_swap "$new_swap" || return 1
        remove_fstab_swap_entries
        rm -f "$swap_file"
    fi
    if ! mv -f "$new_swap" "$swap_file"; then
        rm -f "$new_swap"
        log "${RED}[ERROR] Swap文件替换失败。${NC}"
        return 1
    fi
    if ! swapon "$swap_file" >> "$LOG_FILE" 2>&1; then
        rm -f "$swap_file"
        log "${RED}[ERROR] 新 Swap 启用失败。${NC}"
        return 1
    fi
    ensure_swap_fstab_entry
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
        if ! systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1; then
            log "${RED}[ERROR] systemd-resolved 重启失败，DNS 配置未确认生效${NC}"
            return 1
        fi
    else
        step_info "配置 resolv.conf..."
        if [[ -L /etc/resolv.conf ]]; then
            result_warn "/etc/resolv.conf 是符号链接，跳过直接修改，请由当前 DNS 管理器配置"
            return 0
        fi
        cp -a /etc/resolv.conf "/etc/resolv.conf.backup.$(date +%Y%m%d-%H%M%S).$$" 2>>"$LOG_FILE" || {
            log "${RED}[ERROR] 无法备份 /etc/resolv.conf，已停止修改。${NC}"
            return 1
        }
        local resolv_tmp="/etc/resolv.conf.vps-setup.$$"
        cat > "$resolv_tmp" << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$( [[ "$ipv6_enabled" == true ]] && printf 'nameserver %s\nnameserver %s\n' "$PRIMARY_DNS_V6" "$SECONDARY_DNS_V6" )
EOF
        if ! mv -f "$resolv_tmp" /etc/resolv.conf; then
            rm -f "$resolv_tmp"
            log "${RED}[ERROR] 无法替换 /etc/resolv.conf${NC}"
            return 1
        fi
    fi
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolvectl dns >/dev/null 2>&1 || {
            log "${RED}[ERROR] 无法验证 systemd-resolved DNS 状态${NC}"
            return 1
        }
    elif [[ ! -s /etc/resolv.conf ]]; then
        log "${RED}[ERROR] /etc/resolv.conf 为空，DNS 配置未生效${NC}"
        return 1
    fi
    result_ok "DNS 配置完成：IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$([ "$ipv6_enabled" = true ] && echo "，IPv6 已启用")"
}

configure_ssh() {
    section_header "8" "SSH 配置"

    [[ -z "$NEW_SSH_PORT" ]] && [[ "$non_interactive" = false ]] && { read -p "SSH端口 (留空跳过): " -r NEW_SSH_PORT < /dev/tty; }
    
    if [[ -z "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = false ]]; then
        read -r -s -p "root密码 (输入时不可见, 留空跳过): " NEW_SSH_PASSWORD < /dev/tty
        echo
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}[SECURITY WARNING] 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi

    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]] && ! dpkg -l openssh-server >/dev/null 2>&1; then
        step_info "安装 openssh-server..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y openssh-server >> "$LOG_FILE" 2>&1
    fi

    local ssh_changed=false ssh_backup="" ssh_dropin="/etc/ssh/sshd_config.d/99-vps-setup.conf"
    restart_ssh_service() {
        local unit
        for unit in ssh.service sshd.service; do
            if systemctl cat "$unit" >/dev/null 2>&1; then
                if systemctl restart "$unit" >> "$LOG_FILE" 2>&1; then
                    return 0
                fi
            fi
        done
        return 1
    }
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if [[ ! -f /etc/ssh/sshd_config ]] || ! command -v sshd >/dev/null 2>&1; then
            log "${RED}[ERROR] 未找到 SSH 配置或 sshd，无法修改 SSH。${NC}"
            return 1
        fi
    fi
    if [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ && "$NEW_SSH_PORT" -gt 0 && "$NEW_SSH_PORT" -lt 65536 ]]; then
        local current_ssh_port
        current_ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {printf "%s ", $2}')
        if [[ " $current_ssh_port " != *" ${NEW_SSH_PORT} "* ]] && ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
            log "${RED}[ERROR] SSH端口 ${NEW_SSH_PORT} 已被其他服务占用，未修改 SSH 配置。${NC}"
            return 1
        fi
        ssh_backup="${ssh_dropin}.backup.$(date +%Y%m%d-%H%M%S).$$"
        [[ -f "$ssh_dropin" ]] && cp -a "$ssh_dropin" "$ssh_backup"
        mkdir -p "${ssh_dropin%/*}"
        printf 'Port %s\n' "$NEW_SSH_PORT" > "${ssh_dropin}.tmp.$$"
        mv -f "${ssh_dropin}.tmp.$$" "$ssh_dropin"
        ssh_changed=true
        result_ok "SSH 端口设为: ${NEW_SSH_PORT}"
    fi
    
    if [[ "$ssh_changed" = true ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
            if ! restart_ssh_service; then
                log "${RED}[ERROR] SSH 服务重启失败，正在恢复配置。${NC}"
                if [[ -f "$ssh_backup" ]]; then cp -a "$ssh_backup" "$ssh_dropin"; else rm -f "$ssh_dropin"; fi
                restart_ssh_service || true
                return 1
            fi
            sleep 1
            if ! ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
                log "${RED}[ERROR] SSH 未监听新端口，正在恢复配置。${NC}"
                if [[ -f "$ssh_backup" ]]; then cp -a "$ssh_backup" "$ssh_dropin"; else rm -f "$ssh_dropin"; fi
                restart_ssh_service || true
                return 1
            fi
            log "${YELLOW}[WARN] SSH端口已更改，请用新端口重连！${NC}"
            rm -f "$ssh_backup"
        else
            log "${RED}[ERROR] SSH配置错误，已恢复备份${NC}"
            if [[ -f "$ssh_backup" ]]; then cp -a "$ssh_backup" "$ssh_dropin"; else rm -f "$ssh_dropin"; fi
            restart_ssh_service || true
            return 1
        fi
    fi

    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:${NEW_SSH_PASSWORD}" | chpasswd >> "$LOG_FILE" 2>&1
        result_ok "root 密码已设置"
    fi
}

configure_fail2ban() {
    section_header "9" "Fail2ban 配置"
    
    local ports=()
    [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ ]] && ports+=("$NEW_SSH_PORT")

    # Use the effective sshd configuration so includes and drop-ins are honored.
    if [[ -z "$NEW_SSH_PORT" ]] && command -v sshd >/dev/null 2>&1; then
        while IFS= read -r detected_port; do
            [[ "$detected_port" =~ ^[0-9]+$ ]] && ports+=("$detected_port")
        done < <(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}')
    fi
    [[ ${#ports[@]} -gt 0 ]] || ports=("22")

    local port_list
    port_list=$(printf "%s\n" "${ports[@]}" | sort -un | tr '\n' ',' | sed 's/,$//')
    
    step_info "安装 Fail2ban..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y fail2ban >> "$LOG_FILE" 2>&1; then
        log "${RED}[ERROR] Fail2ban 安装失败，请查看日志：${LOG_FILE}${NC}"
        return 1
    fi
    
    local jail_file="/etc/fail2ban/jail.d/99-vps-setup.local"
    local jail_tmp="${jail_file}.vps-setup.$$"
    local jail_backup
    jail_backup="${jail_file}.backup.$(date +%Y%m%d-%H%M%S).$$"
    mkdir -p "${jail_file%/*}"
    [[ -f "$jail_file" ]] && cp -a "$jail_file" "$jail_backup"
    restore_fail2ban_jail() {
        if [[ -f "$jail_backup" ]]; then
            mv -f "$jail_backup" "$jail_file"
        else
            rm -f "$jail_file"
        fi
    }
    cat > "$jail_tmp" << EOF
[DEFAULT]
# 永久封禁：输错 SSH 密码达到 maxretry 后，来源 IP 不会自动解封。
bantime = -1
findtime = 300
maxretry = 3
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ${port_list}
EOF
    mv -f "$jail_tmp" "$jail_file"
    if ! fail2ban-client -t >> "$LOG_FILE" 2>&1; then
        log "${RED}[ERROR] Fail2ban 配置校验失败${NC}"
        restore_fail2ban_jail
        return 1
    fi
    
    systemctl enable fail2ban >> "$LOG_FILE" 2>&1
    if ! systemctl restart fail2ban >> "$LOG_FILE" 2>&1; then
        restore_fail2ban_jail
        systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || true
        log "${RED}[ERROR] Fail2ban 重启失败，已恢复原配置。${NC}"
        return 1
    fi
    rm -f "$jail_backup"
    
    if (systemctl is-active --quiet fail2ban); then
        result_ok "Fail2ban 已启动，保护端口：${port_list}"
    else
        log "${RED}[ERROR] Fail2ban启动失败${NC}"
        return 1
    fi
}

system_update() {
    section_header "10" "系统更新与清理"
    if [[ "$UPGRADE_SYSTEM" = true ]]; then
        step_info "系统升级..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" full-upgrade -y -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
        result_ok "系统升级完成"
    fi
    if [[ "$CLEAN_SYSTEM" = true ]]; then
        step_info "清理缓存..."
        apt-get "${APT_LOCK_WAIT[@]}" autoremove --purge -y >> "$LOG_FILE" 2>&1
        apt-get clean >> "$LOG_FILE" 2>&1
        result_ok "系统清理完成"
    fi
    if [[ "$UPGRADE_SYSTEM" = false && "$CLEAN_SYSTEM" = false ]]; then
        log "${BLUE}未请求系统升级或清理，跳过${NC}"
    fi
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================
main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { printf '%b\n' "${RED}需要root权限${NC}"; exit 1; }
    
    parse_args "$@"

    if [[ "$non_interactive" = false && ! -t 0 && ! -t 1 ]]; then
        log "${RED}[ERROR] 当前没有可用终端，请使用 --non-interactive${NC}"
        exit 2
    fi

    section_header "" "配置摘要" false
    print_summary_row "主机名" "${NEW_HOSTNAME:-保持当前 / 交互}"
    print_summary_row "时区" "$TIMEZONE"
    print_summary_row "BBR" "$BBR_MODE"
    print_summary_row "Swap" "$SWAP_SIZE_MB"
    print_summary_row "DNS" "${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}"
    print_summary_row "Fail2ban" "$ENABLE_FAIL2BAN"
    [[ -n "$NEW_SSH_PORT" ]] && print_summary_row "SSH 端口" "$NEW_SSH_PORT"
    print_summary_row "系统升级" "$UPGRADE_SYSTEM"
    print_summary_row "系统清理" "$CLEAN_SYSTEM"
    summary_close

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

    if [[ $VERIFICATION_FAILED -gt 0 ]]; then
        log "${RED}[ERROR] 初始化完成，但存在 ${VERIFICATION_FAILED} 项验证失败${NC}"
        log "日志文件: ${LOG_FILE}"
        exit 1
    fi
    
    section_header "" "完成" false
    print_box_row "${GREEN}🎉 VPS 初始化完成！${NC}"
    print_box_row "${DIM}执行时间: $(format_duration "$SECONDS")${NC}"
    print_box_row "${DIM}日志文件:${NC}"
    print_box_row "${DIM}${LOG_FILE}${NC}"
    summary_close
    
    if [[ -n "$NEW_SSH_PORT" ]]; then
        log "\n${RED}⚠️  SSH端口已改为 ${NEW_SSH_PORT}，请用新端口重连！${NC}"
    fi
    
    log "\n${BLUE}建议重启以确保所有配置生效${NC}"
    if [[ "$non_interactive" = false ]]; then
        read -p "立即重启? [Y/n] " -r < /dev/tty
        [[ ! "$REPLY" =~ ^[Nn]$ ]] && { log "${BLUE}重启中...${NC}"; sleep 2; reboot; }
    fi
    
    exit 0
}

main "$@"
