#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: v26.11.19
# ==============================================================================
set -Eeuo pipefail

# --- 默认配置 ---
# shellcheck disable=SC2034
SCRIPT_VERSION="v26.11.19"
TIMEZONE=""
SWAP_SIZE_MB="auto"
INSTALL_PACKAGES=(sudo curl wget ca-certificates)
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
ENABLE_BBR=true
ENABLE_FAIL2BAN=true
UPGRADE_SYSTEM=false
CLEAN_SYSTEM=false
# --- SSH 相关配置 ---
NEW_SSH_PORT=""
NEW_SSH_PASSWORD=""

# --- 颜色和全局变量 ---
readonly GREEN=$'\033[0;32m' RED=$'\033[0;31m' YELLOW=$'\033[1;33m'
readonly BOLD=$'\033[1m' NC=$'\033[0m'

non_interactive=false
LOG_FILE=""
# 后台 apt(如 unattended-upgrades)持锁时最多等待 600 秒，避免直接失败
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=600)

log() {
    printf '%b\n' "$1"
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

section_header() {
    local number="$1" title="$2"
    log ""
    log "${BOLD}${number:+${number}. }${title}${NC}"
}

print_summary_row() {
    local label="$1" value="$2"
    printf '  %s：%s\n' "$label" "$value"
}

result_warn() {
    printf '  %b⚠%b %s\n' "$YELLOW" "$NC" "$1" >&2
}

step_info() {
    log "  ▸ $1${NC}"
}

result_ok() {
    printf '  %b✔%b %s\n' "$GREEN" "$NC" "$1"
}


# shellcheck disable=SC2317 # 由 trap 'handle_error' 调用，静态分析不可见
handle_error() {
    local exit_code=$? line_number=$1
    set +e

    local error_message="\n${RED}✗ 脚本在第 ${line_number} 行失败 (退出码: ${exit_code})${NC}"
    printf '%b\n' "$error_message"
    [[ -n "$LOG_FILE" ]] && echo "✗ 脚本在第 ${line_number} 行失败（退出码：${exit_code}）" >> "$LOG_FILE"
    exit "$exit_code"
}


has_ipv6() {
    ip -6 route show default 2>/dev/null | grep -q 'default' ||
        ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'
}

check_disk_space() {
    local required_mb="$1" available_mb
    available_mb=$(df -BM / | awk 'NR==2 {gsub(/M/,"",$4); print $4}' || echo 0)
    [[ "$available_mb" -eq 0 ]] && { log "${RED}✗ 无法获取可用磁盘空间信息。${NC}"; return 1; }
    if [[ "$available_mb" -lt "$required_mb" ]]; then
        log "${RED}✗ 磁盘空间不足: 需要${required_mb}MB，可用${available_mb}MB${NC}"
        return 1
    fi
}

is_container() {
    systemd-detect-virt --container >/dev/null 2>&1 && return 0
    [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] ||
    grep -q 'container=lxc\|container=docker' /proc/1/environ 2>/dev/null
}

is_kernel_version_ge() {
    local required="$1" current
    current=$(uname -r | sed -nE 's/^([0-9]+\.[0-9]+).*/\1/p')
    [[ -n "$current" ]] && [[ "$(printf '%s\n' "$current" "$required" | sort -V | head -n1)" = "$required" ]]
}

usage() {
    local exit_code="${1:-0}" out=1
    [[ "$exit_code" -eq 0 ]] || out=2
    cat >&"$out" << EOF
${BOLD}用法: $0 [选项]${NC}

${YELLOW}▸ 核心${NC}
  --hostname <name>        设置主机名（1-63 字符，字母、数字、连字符；首尾为字母或数字）
  --timezone <tz>          设置时区（如 Asia/Hong_Kong；默认当前时区）
  --swap <size_mb>         设置 Swap 大小（auto / MB；0 禁用全部）
  --ip-dns <'主 备'>        设置 IPv4 DNS
  --ip6-dns <'主 备'>       设置 IPv6 DNS

${YELLOW}▸ BBR${NC}
  --bbr                    启用 BBR（默认）
  --no-bbr                 切换拥塞控制为 cubic

${YELLOW}▸ 安全${NC}
  --fail2ban               启用 Fail2ban，保护 SSH
  --no-fail2ban            跳过 Fail2ban 配置（不停止已有服务）
  --ssh-port <port>        设置 SSH 端口（1-65535，无前导零）
  --ssh-password <pass>    设置 root 密码（单行，建议交互输入）
  --upgrade                执行系统 full-upgrade
  --cleanup                执行 autoremove 和 apt clean

${YELLOW}▸ 其他${NC}
  -h, --help               显示帮助
  --non-interactive        非交互模式

默认：保留主机名、时区和 SSH 设置；交互模式另行询问主机名和 SSH。
启用 BBR、Fail2ban；Swap 使用 auto，容量不一致时替换全部现有 Swap。
DNS 默认 IPv4：1.1.1.1 / 8.8.8.8；IPv6：2606:4700:4700::1111 / 2001:4860:4860::8888。
DNS 参数须用引号包含两个地址；仅检测到 IPv6 时配置 IPv6 DNS。
所有 VPS 统一静态接管 DNS，锁定 resolv.conf 并停用 systemd-resolved；不重启网络。
自动 DHCP/VPN DNS 更新将被阻止；手动修改前执行 chattr -i /etc/resolv.conf。
非交互模式仍执行默认初始化项目，不是仅执行显式指定的选项。

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
    local -a octets
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" = 0 || "$octet" != 0* ]] || return 1
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

append_line_break() {
    local last_byte
    last_byte=$(tail -c 1 -- "$1") || return 1
    [[ -z "$last_byte" ]] || printf '\n' >> "$1"
}

append_swap_fstab_entry() {
    append_line_break "$1" && printf '/swapfile none swap sw 0 0\n' >> "$1" || return 1
    awk -v path=/swapfile '$1 == path {
        n++; if ($2 != "none" || $3 != "swap" || $4 != "sw" || $5 != 0 || $6 != 0 || NF != 6) bad=1
    } END {exit (bad || n != 1)}' "$1"
}

ensure_swap_fstab_entry() {
    local state fstab_real
    fstab_real=$(realpath -e -- /etc/fstab) && [[ -f "$fstab_real" ]] || return 1
    state=$(awk -v path=/swapfile '
        $1 == path { n++; if ($3 != "swap" || NF < 4 || $4 ~ /(^|,)noauto(,|$)/) bad=1 }
        END { if (bad || n > 1) exit 1; print n+0 }
    ' "$fstab_real") || { result_warn "fstab 的 /swapfile 条目冲突，请自行整理"; return 1; }
    [[ "$state" = 0 ]] || return 0
    # Stage the append so short writes leave the live fstab byte-identical.
    local staged
    staged=$(mktemp "${fstab_real}.vps-setup.XXXXXX") || return 1
    if ! cp -p -- "$fstab_real" "$staged" || ! append_swap_fstab_entry "$staged" ||
       ! mv -fT -- "$staged" "$fstab_real"; then
        rm -f -- "$staged"
        return 1
    fi
}

valid_ssh_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 ))
}

parse_args() {

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) [[ $# -eq 1 ]] || usage 2; usage 0 ;;
            --hostname)
                require_value "$@"
                [[ "$2" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] || {
                    printf '%b\n' "${RED}无效主机名: $2${NC}" >&2
                    exit 2
                }
                NEW_HOSTNAME="$2"
                shift 2
                ;;
            --timezone)
                require_value "$@"
                if [[ "$2" = *$'\n'* || "$2" = *$'\r'* ]] ||
                   { command -v timedatectl >/dev/null 2>&1 && ! timedatectl list-timezones 2>/dev/null | grep -Fx -- "$2" >/dev/null; }; then
                    printf '%b\n' "${RED}无效时区: $2${NC}" >&2
                    exit 2
                fi
                TIMEZONE="$2"; shift 2 ;;
            --swap)
                require_value "$@"
                # Bound MiB before arithmetic; the resulting byte size must fit signed 64-bit.
                if [[ "$2" != auto ]] && { [[ ! "$2" =~ ^(0|[1-9][0-9]*)$ || ${#2} -gt 13 ]] || (( $2 > 8796093022207 )); }; then
                    printf '%b\n' "${RED}--swap 必须是 auto 或 0-8796093022207 MB 的整数${NC}" >&2
                    exit 2
                fi
                SWAP_SIZE_MB="$2"; shift 2 ;;
            --ip-dns)
                require_value "$@"; read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"
                if [[ "$2" = *$'\n'* || "$2" = *$'\r'* ]] || ! valid_ipv4 "$PRIMARY_DNS_V4" || ! valid_ipv4 "$SECONDARY_DNS_V4"; then
                    printf '%b\n' "${RED}--ip-dns 需要两个有效 IPv4 地址${NC}" >&2
                    exit 2
                fi
                shift 2 ;;
            --ip6-dns)
                require_value "$@"; read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"
                if [[ "$2" = *$'\n'* || "$2" = *$'\r'* ]] || ! valid_ipv6 "$PRIMARY_DNS_V6" || ! valid_ipv6 "$SECONDARY_DNS_V6"; then
                    printf '%b\n' "${RED}--ip6-dns 需要两个有效 IPv6 地址${NC}" >&2
                    exit 2
                fi
                shift 2 ;;
            --bbr) ENABLE_BBR=true; shift ;;
            --no-bbr) ENABLE_BBR=false; shift ;;
            --fail2ban)
                ENABLE_FAIL2BAN=true
                shift ;;
            --no-fail2ban) ENABLE_FAIL2BAN=false; shift ;;
            --ssh-port)
                require_value "$@"
                valid_ssh_port "$2" || { printf '%b\n' "${RED}--ssh-port 必须是 1-65535 的端口${NC}" >&2; exit 2; }
                NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password)
                [[ $# -ge 2 && -n "$2" ]] || { result_warn "选项 --ssh-password 需要一个参数"; exit 2; }
                [[ "$2" != *$'\n'* && "$2" != *$'\r'* ]] || { result_warn "root 密码必须为单行（不含换行或回车）"; exit 2; }
                NEW_SSH_PASSWORD="$2"; shift 2 ;;
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
        log "${RED}✗ 不支持在容器环境执行，请在完整 VPS 或虚拟机中运行${NC}"
        exit 1
    fi
    [[ ! -f /etc/os-release ]] && { log "${RED}错误: 系统信息缺失${NC}"; exit 1; }
    # shellcheck source=/dev/null
    source /etc/os-release
    local supported=false
    local os_name="${PRETTY_NAME:-${ID:-未知}}"
    [[ "${ID:-}" = debian && "${VERSION_ID:-}" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "${ID:-}" = ubuntu && "${VERSION_ID:-}" =~ ^(20\.04|22\.04|24\.04|26\.04)$ ]] && supported=true
    if [[ "$supported" = "false" ]]; then
        log "${YELLOW}⚠ 系统: ${os_name} (建议使用Debian 10-13或Ubuntu 20.04-26.04)${NC}"
        if [[ "$non_interactive" = true ]]; then
            log "${RED}✗ 非交互模式不支持当前系统，已中止${NC}"
            exit 1
        fi
        read -p "继续? [y/N] " -r < /dev/tty
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0
    fi
    result_ok "系统: ${os_name}"
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
    log "  当前主机名：${current_hostname}${NC}"
    local final_hostname="$current_hostname"
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOG_FILE" 2>&1
            final_hostname="$NEW_HOSTNAME"
        fi
    elif [[ "$non_interactive" = false ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            read -r -p "新主机名（留空保持当前）: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name" >> "$LOG_FILE" 2>&1
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"
            elif [[ -n "$new_name" ]]; then
                result_warn "主机名须为 1-63 字符，仅限字母、数字和连字符，首尾须为字母或数字；保持当前：${current_hostname}"
            fi
        fi
    fi
    if [[ "$final_hostname" != "$current_hostname" ]]; then
        if grep -qE '^[[:space:]]*127\.0\.1\.1([[:space:]]|$)' /etc/hosts; then
            sed -i -E "/^[[:space:]]*127\.0\.1\.1([[:space:]]|$)/ {
                s/^([[:space:]]*127\.0\.1\.1)[[:space:]]+[^[:space:]#]+/\\1\\t${final_hostname}/; t
                s/^([[:space:]]*127\.0\.1\.1)/\\1\\t${final_hostname}/
            }" /etc/hosts
        else
            append_line_break /etc/hosts || return 1
            printf '%b\n' "127.0.1.1\t${final_hostname}" >> /etc/hosts
        fi
        result_ok "主机名设为: ${final_hostname}"
    else
        log "  主机名保持当前${NC}"
    fi
}

configure_timezone() {
    section_header "3" "时区配置"
    if [[ -z "$TIMEZONE" ]]; then
        step_info "时区保持当前"
        return 0
    fi
    step_info "设置时区：${TIMEZONE}"
    timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1 || return 1
    result_ok "时区已设置：${TIMEZONE}"
}

configure_time_sync() {
    section_header "4" "时间同步配置"

    local provider
    for provider in chrony chronyd ntp ntpd ntpsec openntpd; do
        if systemctl is-active --quiet "$provider" 2>/dev/null; then
            result_ok "已有时间同步服务 $provider 正在运行，保持现状"
            return 0
        fi
    done
    if LC_ALL=C timedatectl status 2>/dev/null | grep -q 'NTP service: active'; then
        result_ok "已有时间同步服务正在运行，保持现状"
        return 0
    fi

    if ! command -v timedatectl >/dev/null 2>&1; then
        log "${YELLOW}  ⚠ 未找到 timedatectl 命令，跳过时间同步配置${NC}"
        return 0
    fi

    if ! systemctl cat systemd-timesyncd >/dev/null 2>&1; then
        step_info "安装 systemd-timesyncd..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
    fi

    systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
    timedatectl set-ntp true >> "$LOG_FILE" 2>&1 || systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true

    if LC_ALL=C timedatectl status 2>/dev/null | grep -q 'NTP service: active' || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        result_ok "时间同步服务已启用"
    else
        result_warn "时间同步服务未确认激活，建议后续检查"
    fi
}

# GNU sed preserves unrelated bytes, including a missing final newline.
# The owned file replaces active keys; other files keep retired lines as comments.
bbr_filter() {
    local key dotted slashed expression="" action='s/^/# vps-setup: /'
    [[ "${3:-}" != replace ]] || action=d
    while IFS= read -r key; do
        # Owned keys contain no literal dots in kernel path components.
        # procps swaps all separators only when the first separator is a dot.
        dotted=${key//./\\.}
        slashed=${key//./\/}
        expression+="\\|^[[:space:]]*-?(${dotted}\\|${slashed})[[:space:]]*=|${action};"
    done <<< "$1"
    sed -E "$expression" "$2"
}

configure_bbr() {
    section_header "5" "BBR 配置"
    local config_file="/etc/sysctl.d/99-bbr.conf" target=cubic backup config_target
    local file resolved dir key value keys="" i tmp="" runtime_started=false retain_backup=false
    local -a files=() changed=() runtime=()
    local -A seen=()
    if [[ "$ENABLE_BBR" = true ]]; then
        is_kernel_version_ge "4.9" || { result_warn "内核需要 4.9+，未修改 BBR"; return 1; }
        target=bbr
    fi
    backup=$(mktemp -d "${config_file}.backup.XXXXXX") || return 1
    # Nested helpers share this transaction's local state, including conditional callers.
    bbr_prepare() {
        if [[ "$target" = bbr ]]; then
            printf 'net.core.default_qdisc = fq\n' > "$backup/target" || return 1
        else
            : > "$backup/target" || return 1
        fi
        printf 'net.ipv4.tcp_congestion_control = %s\n' "$target" >> "$backup/target" || return 1
        keys=$(awk -F ' *= *' 'NF == 2 {print $1}' "$backup/target") || return 1
        [[ -n "$keys" ]] || return 1
        while IFS= read -r key; do
            value=$(sysctl -n "$key") || return 1
            [[ -n "$value" ]] || return 1
            runtime+=("$key=$value")
        done <<< "$keys"
        printf '%s\n' "${runtime[@]}" > "$backup/runtime" || return 1
        config_target=$(readlink -m -- "$config_file") || return 1
        # Reject an invalid owned symlink even if an earlier alias resolves to it too.
        [[ ! -L "$config_file" || -f "$config_target" ]] || return 1
        # Include shadowed files too, so removing a higher-priority file cannot revive conflicts.
        for dir in /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d; do
            for file in "$dir"/*.conf; do
                [[ -e "$file" || -L "$file" ]] || continue
                files+=("$file")
            done
        done
        files+=(/etc/sysctl.conf "$config_file")
        local -a candidates=("${files[@]}")
        files=()
        for file in "${candidates[@]}"; do
            [[ -e "$file" || -L "$file" || "$file" = "$config_file" ]] || continue
            resolved=$(readlink -m -- "$file") || return 1
            [[ ! ${seen[$resolved]+yes} ]] || continue
            seen[$resolved]=1
            # /dev/null masks are not configuration files; other special/dangling targets fail closed.
            [[ "$resolved" != /dev/null ]] || continue
            if [[ -e "$resolved" ]]; then
                [[ -f "$resolved" ]] || return 1
            elif [[ "$file" != "$config_file" || -L "$file" ]]; then
                return 1
            fi
            i=${#files[@]}
            : > "$backup/new.$i" || return 1
            if [[ "$resolved" = "$config_target" ]]; then
                # Prepend generated keys so an unrelated final line needs no added newline.
                cat "$backup/target" > "$backup/new.$i" || return 1
            fi
            if [[ -f "$resolved" ]]; then
                if [[ "$resolved" = "$config_target" ]]; then
                    bbr_filter "$keys" "$resolved" replace >> "$backup/new.$i" || return 1
                else
                    bbr_filter "$keys" "$resolved" >> "$backup/new.$i" || return 1
                fi
                if cmp -s -- "$resolved" "$backup/new.$i"; then
                    rm -f -- "$backup/new.$i" || return 1
                    continue
                fi
                cp -a -- "$resolved" "$backup/old.$i" || return 1
                retain_backup=true
            fi
            files+=("$resolved")
            printf '%s\n' "$resolved" >> "$backup/paths" || return 1
        done
    }
    bbr_apply() {
        for i in "${!files[@]}"; do
            file=${files[$i]}
            tmp=$(mktemp "${file}.XXXXXX") || return 1
            if [[ -f "$backup/old.$i" ]]; then
                cp -a -- "$backup/old.$i" "$tmp" || return 1
            else
                chmod 644 "$tmp" || return 1
            fi
            cat "$backup/new.$i" > "$tmp" || return 1
            # Track before rename: even a failed/partially completed operation must be recovered.
            changed+=("$i")
            mv -fT -- "$tmp" "$file" || return 1
            tmp=""
        done
        for i in "${!files[@]}"; do
            cmp -s -- "$backup/new.$i" "${files[$i]}" || return 1
        done
        runtime_started=true
        # Apply only generated assignments, never unrelated settings in another file.
        sysctl -p "$backup/target" >> "$LOG_FILE" 2>&1 || return 1
        while IFS='=' read -r key value; do
            key=${key// /}; value=${value// /}
            local actual
            actual=$(sysctl -n "$key") || return 1
            [[ "$actual" = "$value" ]] || return 1
        done < "$backup/target"
    }
    if ! bbr_prepare || ! bbr_apply; then
        local restore_failed=false
        [[ -z "$tmp" ]] || rm -f -- "$tmp" || restore_failed=true
        for i in "${changed[@]}"; do
            if [[ -f "$backup/old.$i" ]]; then
                cp -a --remove-destination -- "$backup/old.$i" "${files[$i]}" || restore_failed=true
                cmp -s -- "$backup/old.$i" "${files[$i]}" || restore_failed=true
            else
                rm -f -- "${files[$i]}" || restore_failed=true
            fi
        done
        if [[ "$runtime_started" = true ]]; then
            for value in "${runtime[@]}"; do
                sysctl -w "$value" >> "$LOG_FILE" 2>&1 || restore_failed=true
                key=${value%%=*}
                if ! resolved=$(sysctl -n "$key") || [[ "$resolved" != "${value#*=}" ]]; then
                    restore_failed=true
                fi
            done
        fi
        if [[ "$restore_failed" = true ]]; then
            result_warn "拥塞控制恢复不完整，请检查日志及备份（paths / old.* / runtime）：$backup"
        else
            rm -rf -- "$backup"
            result_warn "拥塞控制变更失败，未提交或已恢复本次配置及运行参数"
        fi
        return 1
    fi
    if [[ "$retain_backup" = true ]]; then
        print_summary_row "原配置备份" "$backup"
    else
        rm -rf -- "$backup" || return 1
    fi
    result_ok "拥塞控制已生效：$target$([[ "$target" = bbr ]] && echo ' / fq')"
    print_summary_row "配置文件" "$config_file"
}

remove_fstab_swap_entries() {
    sed -E '\|^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+[^[:space:]]+[[:space:]]+swap([[:space:]]\|$)|d' "$1"
}

configure_swap() {
    section_header "6" "Swap 配置"
    local swap_file="/swapfile" swap_mb="$SWAP_SIZE_MB" current_total_mb=0 size_bytes swap_line
    local active_swap new_swap="" backup old_moved=false new_installed=false
    local managed_active=false fstab_real fstab_staged
    local priority options entry_source entry_type entry_options option active_state fstab_entries find_rc=0
    local -A swap_options=()
    # A fixed path is not ownership evidence: never retire unrelated data.
    if [[ -e "$swap_file" || -L "$swap_file" ]]; then
        local swap_type
        if [[ -L "$swap_file" || ! -f "$swap_file" ]] ||
           ! swap_type=$(blkid -p -s TYPE -o value -- "$swap_file" 2>/dev/null) || [[ "$swap_type" != swap ]]; then
            result_warn "拒绝修改未识别的 Swap 普通文件：$swap_file"
            return 1
        fi
    fi

    if [[ "$swap_mb" = auto ]]; then
        local mem_mb
        mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo) || return 1
        if (( mem_mb <= 512 )); then swap_mb=512
        elif (( mem_mb <= 1024 )); then swap_mb=1024
        else swap_mb=2048; fi
    fi
    local sizes
    sizes=$(swapon --show=NAME,SIZE --bytes --noheadings --raw) || return 1
    while IFS= read -r swap_line; do
        [[ -n "$swap_line" ]] || continue
        size_bytes=${swap_line##* }
        [[ "$size_bytes" =~ ^[0-9]+$ ]] || return 1
        current_total_mb=$((current_total_mb + (size_bytes + 524288) / 1048576))
        if [[ "${swap_line% *}" = "$swap_file" ]]; then managed_active=true; fi
    done <<< "$sizes"
    if [[ "$swap_mb" != 0 && "$current_total_mb" -eq "$swap_mb" ]]; then
        if [[ "$managed_active" = true ]]; then ensure_swap_fstab_entry || return 1; fi
        result_ok "现有 Swap 与目标一致（${swap_mb}MB），保留"
        return 0
    fi
    if [[ "$swap_mb" = 0 ]]; then
        result_warn "将禁用全部 Swap（含分区），移除 Swap 启动条目及 /swapfile"
    else
        step_info "Swap 目标：${swap_mb}MB；当前：${current_total_mb}MB"
        if [[ "$current_total_mb" -gt 0 ]]; then
            result_warn "容量不一致，将停用全部现有 Swap（含分区），统一替换为 /swapfile"
        fi
    fi

    fstab_real=$(realpath -e -- /etc/fstab) && [[ -f "$fstab_real" ]] || return 1
    active_state=$(swapon --show=NAME,PRIO --noheadings --raw) || return 1
    fstab_entries=$(findmnt --fstab --tab-file "$fstab_real" --evaluate --noheadings --raw --output SOURCE,FSTYPE,OPTIONS) || find_rc=$?
    [[ "$find_rc" -le 1 && ( "$find_rc" -eq 0 || -z "$fstab_entries" ) ]] || return 1
    while read -r active_swap priority; do
        [[ -n "$active_swap" ]] || continue
        [[ "$priority" =~ ^-?[0-9]+$ ]] || return 1
        options=""
        while read -r entry_source entry_type entry_options; do
            [[ "$entry_source" = "$active_swap" && "$entry_type" = swap ]] || continue
            local -a entry_parts=()
            IFS=, read -r -a entry_parts <<< "$entry_options"
            for option in "${entry_parts[@]}"; do
                case "$option" in discard|discard=once|discard=pages) options+="${options:+,}$option";; esac
            done
        done <<< "$fstab_entries"
        swap_options["$active_swap"]=$options
    done <<< "$active_state"
    # Linux cannot assign negative priorities: stop lowest first, restore in reverse.
    active_state=$(LC_ALL=C sort -k2,2n <<< "$active_state") || return 1
    if [[ "$swap_mb" != 0 ]]; then
        check_disk_space $((swap_mb + 100)) || return 1
        new_swap=$(mktemp "${swap_file}.new.XXXXXX") || return 1
        if ! { fallocate -l "${swap_mb}M" "$new_swap" >> "$LOG_FILE" 2>&1 ||
            dd if=/dev/zero of="$new_swap" bs=1M count="$swap_mb" status=none >> "$LOG_FILE" 2>&1; } ||
            ! chmod 600 "$new_swap" || ! mkswap "$new_swap" >> "$LOG_FILE" 2>&1; then
            rm -f "$new_swap"; return 1
        fi
    fi
    # 同一文件系统保存旧文件，提交前不删除；只清理本次创建的路径。
    backup=$(mktemp -d "${swap_file}.backup.XXXXXX") || { [[ -z "$new_swap" ]] || rm -f "$new_swap"; return 1; }
    fstab_staged=$(mktemp "${fstab_real}.vps-setup.XXXXXX") || {
        [[ -z "$new_swap" ]] || rm -f -- "$new_swap"
        rmdir -- "$backup"; return 1
    }
    if ! cp -p -- "$fstab_real" "$backup/fstab" || ! cp -p -- "$backup/fstab" "$fstab_staged" ||
       ! remove_fstab_swap_entries "$backup/fstab" > "$fstab_staged" ||
       { [[ "$swap_mb" != 0 ]] && ! append_swap_fstab_entry "$fstab_staged"; }; then
        [[ -z "$new_swap" ]] || rm -f -- "$new_swap"
        rm -rf -- "$backup" "$fstab_staged"; return 1
    fi
    rollback_swap() {
        local restore_failed=false swap_file_blocked=false item remaining reverse_snapshot path attempt
        local -A active_names=()
        if [[ "$new_installed" = true ]]; then
            if ! swapoff "$swap_file" >> "$LOG_FILE" 2>&1; then
                if ! remaining=$(swapon --show=NAME --noheadings --raw) || grep -Fxq "$swap_file" <<< "$remaining"; then
                    result_warn "新 Swap 无法确认关闭，保留活动文件及备份：$backup"
                    swap_file_blocked=true
                    restore_failed=true
                fi
            fi
            if [[ "$swap_file_blocked" = false ]]; then
                if ! rm -f "$swap_file"; then swap_file_blocked=true; restore_failed=true; fi
            fi
        fi
        if [[ "$old_moved" = true && "$swap_file_blocked" = false ]]; then
            if ! mv -f "$backup/swapfile" "$swap_file"; then swap_file_blocked=true; restore_failed=true; fi
        fi
        if [[ ! -e "$fstab_staged" ]] &&
           ! { cp -p -- "$backup/fstab" "$fstab_staged" && mv -fT -- "$fstab_staged" "$fstab_real"; }; then
            restore_failed=true
        fi
        # A failed swapoff may have completed. Retry readback, not activation.
        for ((attempt=0; attempt<3; attempt++)); do
            remaining=$(swapon --show=NAME,PRIO --noheadings --raw) && break
        done
        if (( attempt == 3 )) || ! reverse_snapshot=$(tac <<< "$active_state"); then
            restore_failed=true
        else
            while read -r item _; do
                [[ -z "$item" ]] || active_names["$item"]=1
            done <<< "$remaining"
            while read -r item priority; do
                [[ -n "$item" && -z "${active_names[$item]:-}" ]] || continue
                printf -v path '%b' "$item"
                # 冲突路径不能冒充旧 Swap；fstab 和其他旧 Swap 仍独立恢复。
                [[ "$path" != "$swap_file" || "$swap_file_blocked" = false ]] || continue
                local -a restore_args=()
                [[ "$priority" -lt 0 ]] || restore_args+=(--priority "$priority")
                [[ -z "${swap_options[$item]}" ]] || restore_args+=(--options "${swap_options[$item]}")
                swapon "${restore_args[@]}" "$path" >> "$LOG_FILE" 2>&1 || restore_failed=true
            done <<< "$reverse_snapshot"
            if ! remaining=$(swapon --show=NAME,PRIO --noheadings --raw | LC_ALL=C sort -k2,2n) ||
               [[ "$remaining" != "$active_state" ]]; then
                restore_failed=true
            fi
        fi
        [[ -z "$new_swap" ]] || rm -f -- "$new_swap" || restore_failed=true
        rm -f -- "$fstab_staged" || restore_failed=true
        if [[ "$restore_failed" = true ]]; then
            result_warn "Swap 恢复不完整，请检查日志及备份：$backup"
        else
            rm -rf "$backup"
            result_warn "Swap 变更失败，已恢复旧配置和活动 Swap"
        fi
        return 1
    }
    local signal_rc=0 saved_int saved_term
    saved_int=$(trap -p INT); saved_term=$(trap -p TERM)
    # A trap only records cancellation: finish recording the command's real outcome
    # before recovery, otherwise mv/swapoff can outlive or undo the rollback.
    trap 'signal_rc=130' INT
    trap 'signal_rc=143' TERM
    swap_restore_traps() {
        trap - INT TERM
        [[ -z "$saved_int" ]] || eval "$saved_int"
        [[ -z "$saved_term" ]] || eval "$saved_term"
        return 0
    }
    swap_apply() {
        local final_swap path
        while read -r active_swap priority; do
            [[ -n "$active_swap" ]] || continue
            [[ "$signal_rc" -eq 0 ]] || return 1
            # Keep raw names for comparisons; decode util-linux escapes only for argv.
            printf -v path '%b' "$active_swap"
            swapoff "$path" >> "$LOG_FILE" 2>&1 || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
        done <<< "$active_state"
        if [[ -e "$swap_file" ]]; then
            if mv "$swap_file" "$backup/swapfile"; then old_moved=true
            else
                [[ ! -e "$backup/swapfile" ]] || old_moved=true
                return 1
            fi
            [[ "$signal_rc" -eq 0 ]] || return 1
        fi
        if [[ "$swap_mb" != 0 ]]; then
            if mv "$new_swap" "$swap_file"; then new_installed=true
            else
                [[ ! -e "$swap_file" ]] || new_installed=true
                return 1
            fi
            [[ "$signal_rc" -eq 0 ]] || return 1
            swapon "$swap_file" >> "$LOG_FILE" 2>&1 || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
        fi
        final_swap=$(swapon --show=NAME --noheadings --raw) || return 1
        [[ "$signal_rc" -eq 0 ]] || return 1
        if [[ "$swap_mb" = 0 ]]; then [[ -z "$final_swap" ]] || return 1
        else [[ "$final_swap" = "$swap_file" ]] || return 1; fi
        # Detect edits made while Swap was changing; comparison and rename are not a CAS.
        if [[ "$(realpath -e -- /etc/fstab)" != "$fstab_real" ]] || ! cmp -s -- "$backup/fstab" "$fstab_real"; then
            result_warn "fstab 已被其他操作修改或无法读取，保留其内容并恢复活动 Swap"
            return 1
        fi
        [[ "$signal_rc" -eq 0 ]] || return 1
        mv -fT -- "$fstab_staged" "$fstab_real"
    }
    if ! swap_apply || [[ "$signal_rc" -ne 0 ]]; then
        rollback_swap || :
        swap_restore_traps
        [[ "$signal_rc" -eq 0 ]] || return "$signal_rc"
        return 1
    fi
    swap_restore_traps
    rm -rf "$backup" || return 1
    if [[ "$swap_mb" = 0 ]]; then
        result_ok "全部 Swap 已禁用，Swap 启动条目及 /swapfile 已移除"
    else
        result_ok "Swap 已配置：${swap_mb}MB（/swapfile）"
    fi
}

dns_is_immutable() {
    local attributes
    attributes=$(lsattr -d -- "$1" 2>>"$LOG_FILE") || return 2
    attributes=${attributes%% *}
    [[ "$attributes" = *i* ]]
}

dns_resolved_state() {
    local reply load="" active="" line
    reply=$(systemctl show --property=LoadState --property=ActiveState systemd-resolved.service 2>>"$LOG_FILE") || return 1
    while IFS= read -r line; do
        case "$line" in LoadState=*) load=${line#*=};; ActiveState=*) active=${line#*=};; esac
    done <<< "$reply"
    case "$load:$active" in
        loaded:active|masked:active) printf '%s:active\n' "$load";;
        loaded:inactive|masked:inactive|not-found:inactive|loaded:failed|masked:failed) printf '%s:inactive\n' "$load";;
        *) return 1;;
    esac
}

dns_verify_file() {
    local actual
    [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]] || return 1
    actual=$(awk '$1 == "nameserver" {print $2}' /etc/resolv.conf) || return 1
    [[ "$actual" = "$expected_dns" ]] && dns_is_immutable /etc/resolv.conf
}

configure_dns() {
    section_header "7" "DNS 配置"
    local resolv_file="/etc/resolv.conf" unit="/etc/systemd/system/systemd-resolved.service"
    local runtime_unit="/run/systemd/system/systemd-resolved.service" runtime_mask=false
    local ipv6_enabled=false old_exists=false old_immutable=false old_active=false
    local unlocked=false installed=false service_touched=false unit_exists=false attr_status
    local resolv_tmp backup expected_dns unchanged=false service_state
    has_ipv6 && ipv6_enabled=true
    expected_dns=$(printf '%s\n' "$PRIMARY_DNS_V4" "$SECONDARY_DNS_V4"
        [[ "$ipv6_enabled" != true ]] || printf '%s\n' "$PRIMARY_DNS_V6" "$SECONDARY_DNS_V6")
    step_info "统一接管系统 DNS，禁止自动覆盖..."
    if [[ -e "$resolv_file" && ! -f "$resolv_file" ]]; then
        result_warn "DNS 配置路径不是普通文件，未修改：$resolv_file"
        return 1
    fi
    if ! command -v chattr >/dev/null 2>&1 || ! command -v lsattr >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y e2fsprogs >> "$LOG_FILE" 2>&1 || return 1
    fi
    if [[ -f "$resolv_file" && ! -L "$resolv_file" ]]; then
        if dns_is_immutable "$resolv_file"; then old_immutable=true
        else
            attr_status=$?
            [[ "$attr_status" = 1 ]] || { result_warn "无法读取 DNS 文件属性，未修改"; return 1; }
        fi
    fi
    service_state=$(dns_resolved_state) || { result_warn "无法确认 DNS 服务状态，未修改"; return 1; }
    [[ "$service_state" != *:active ]] || old_active=true
    if [[ -L "$runtime_unit" && "$(readlink -- "$runtime_unit")" = /dev/null ]]; then runtime_mask=true; fi
    resolv_tmp=$(mktemp "${resolv_file}.vps-setup.XXXXXX") || return 1
    if ! {
        printf 'nameserver %s\nnameserver %s\n' "$PRIMARY_DNS_V4" "$SECONDARY_DNS_V4" &&
        { [[ "$ipv6_enabled" != true ]] || printf 'nameserver %s\nnameserver %s\n' "$PRIMARY_DNS_V6" "$SECONDARY_DNS_V6"; } &&
        { [[ ! -f "$resolv_file" ]] || sed -E '/^[[:space:]]*nameserver([[:space:]]|$)/d' "$resolv_file"; }
    } > "$resolv_tmp" || ! chmod 644 "$resolv_tmp"; then
        rm -f "$resolv_tmp"; return 1
    fi
    if [[ "$old_immutable" = true ]] && cmp -s "$resolv_tmp" "$resolv_file"; then unchanged=true; fi
    if [[ "$unchanged" = true && "$service_state" = masked:inactive && -L "$unit" && "$(readlink -- "$unit")" = /dev/null ]]; then
        # The successful state query and byte comparison already verified the current state.
        rm -f -- "$resolv_tmp" || return 1
        dns_report "$ipv6_enabled"
        return 0
    fi
    # Keep the original link object and service mask, not the generated link target.
    backup=$(mktemp -d "${resolv_file}.backup.XXXXXX") || { rm -f "$resolv_tmp"; return 1; }
    dns_snapshot() {
        if [[ -e "$resolv_file" || -L "$resolv_file" ]]; then
            old_exists=true
            cp -a -- "$resolv_file" "$backup/resolv.conf" || return 1
        fi
        if [[ -e "$unit" || -L "$unit" ]]; then
            unit_exists=true
            cp -a -- "$unit" "$backup/resolved-unit" || return 1
        fi
        printf 'immutable=%s\nresolved_active=%s\n' "$old_immutable" "$old_active" > "$backup/state" || return 1
    }
    if ! dns_snapshot; then rm -f "$resolv_tmp"; rm -rf "$backup"; return 1; fi
    restore_dns() {
        local failed=false
        if [[ "$installed" = true ]]; then
            if ! chattr -i -- "$resolv_file" >> "$LOG_FILE" 2>&1; then failed=true; fi
            if [[ "$old_exists" = true ]]; then
                cp -a --remove-destination -- "$backup/resolv.conf" "$resolv_file" || failed=true
            else
                rm -f -- "$resolv_file" || failed=true
            fi
        fi
        if [[ "$old_immutable" = true && "$unlocked" = true ]]; then
            chattr +i -- "$resolv_file" >> "$LOG_FILE" 2>&1 || failed=true
        fi
        if [[ "$service_touched" = true ]]; then
            if [[ "$unit_exists" = true ]]; then
                cp -a --remove-destination -- "$backup/resolved-unit" "$unit" || failed=true
            else
                rm -f -- "$unit" || failed=true
            fi
            systemctl daemon-reload >> "$LOG_FILE" 2>&1 || failed=true
            if [[ "$old_active" = true ]]; then
                local restore_mask=false
                if [[ -L "$unit" && "$(readlink -- "$unit")" = /dev/null ]]; then
                    restore_mask=true
                    rm -f -- "$unit" || failed=true
                    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || failed=true
                fi
                if [[ "$runtime_mask" = true ]]; then
                    rm -f -- "$runtime_unit" || failed=true
                    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || failed=true
                fi
                systemctl start systemd-resolved.service >> "$LOG_FILE" 2>&1 || failed=true
                if [[ "$runtime_mask" = true ]]; then
                    ln -s /dev/null "$runtime_unit" || failed=true
                    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || failed=true
                fi
                if [[ "$restore_mask" = true ]]; then
                    cp -a --remove-destination -- "$backup/resolved-unit" "$unit" || failed=true
                    systemctl daemon-reload >> "$LOG_FILE" 2>&1 || failed=true
                fi
                service_state=$(dns_resolved_state) || failed=true
                [[ "$service_state" = *:active ]] || failed=true
            fi
        fi
        rm -f "$resolv_tmp" || failed=true
        if [[ "$failed" = true ]]; then
            result_warn "DNS 恢复不完整，请检查备份：$backup"
        else
            rm -rf "$backup"
            result_warn "DNS 接管失败，已恢复原配置"
        fi
        return 1
    }
    dns_apply() {
        if [[ "$unchanged" != true ]]; then
            if [[ "$old_immutable" = true ]]; then
                unlocked=true
                chattr -i -- "$resolv_file" >> "$LOG_FILE" 2>&1 || return 1
                [[ "$signal_rc" -eq 0 ]] || return 1
            fi
            if mv -fT -- "$resolv_tmp" "$resolv_file"; then installed=true
            else
                [[ -e "$resolv_tmp" ]] || installed=true
                return 1
            fi
            [[ "$signal_rc" -eq 0 ]] || return 1
            chattr +i -- "$resolv_file" >> "$LOG_FILE" 2>&1 || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
        fi
        # Mask even an inactive/absent resolved so a later boot cannot revive old DNS.
        if [[ ! -L "$unit" || "$(readlink -- "$unit")" != /dev/null ]]; then
            service_touched=true
            rm -f -- "$unit" || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
            systemctl mask --now systemd-resolved.service >> "$LOG_FILE" 2>&1 || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
        elif [[ "$service_state" != masked:inactive ]]; then
            service_touched=true
            systemctl daemon-reload >> "$LOG_FILE" 2>&1 || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
            if [[ "$old_active" = true ]]; then
                systemctl stop systemd-resolved.service >> "$LOG_FILE" 2>&1 || return 1
            fi
        fi
        [[ -L "$unit" && "$(readlink -- "$unit")" = /dev/null ]] || return 1
        service_state=$(dns_resolved_state) || return 1
        [[ "$service_state" = masked:inactive ]] || return 1
        dns_verify_file || return 1
        [[ "$signal_rc" -eq 0 ]]
    }
    local signal_rc=0 saved_int saved_term
    saved_int=$(trap -p INT); saved_term=$(trap -p TERM)
    # Defer local recovery until the in-flight command and its state flags agree.
    trap 'signal_rc=130' INT
    trap 'signal_rc=143' TERM
    dns_restore_traps() {
        trap - INT TERM
        [[ -z "$saved_int" ]] || eval "$saved_int"
        [[ -z "$saved_term" ]] || eval "$saved_term"
        return 0
    }
    if ! dns_apply || [[ "$signal_rc" -ne 0 ]]; then
        restore_dns || :
        dns_restore_traps
        [[ "$signal_rc" -eq 0 ]] || return "$signal_rc"
        return 1
    fi
    dns_restore_traps
    rm -f "$resolv_tmp" || return 1
    if [[ "$installed" = true || "$service_touched" = true ]]; then
        print_summary_row "原 DNS 备份" "$backup"
    else
        rm -rf "$backup" || return 1
    fi
    dns_report "$ipv6_enabled"
}

dns_report() {
    print_summary_row "DNS 管理" "静态接管，已禁止自动覆盖"
    local summary="IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}"
    [[ "$1" != true ]] || summary+="，IPv6 ${PRIMARY_DNS_V6} / ${SECONDARY_DNS_V6}"
    result_ok "DNS 配置完成：$summary"
}

# Output: one numeric, remotely usable endpoint per line.
ssh_remote_endpoints() {
    awk '
        NF {
            address=$1; sub(/:[^:]*$/, "", address)
            gsub(/[\[\]]/, "", address); address=tolower(address)
            if (address ~ /^127\./ || address == "::1" ||
                address ~ /^::ffff:127\./ || address ~ /^fe[89ab][0-9a-f]:/) next
            print $1
        }
    '
}

# Join socket inodes against the selected process's descriptors, not ss process names.
ssh_socket_rows() {
    local pid=$1 fd target inodes=' ' rows
    shift
    if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
        for fd in /proc/"$pid"/fd/*; do
            target=$(readlink -- "$fd" 2>/dev/null) || continue
            if [[ "$target" =~ ^socket:\[([0-9]+)\]$ ]]; then inodes+="${BASH_REMATCH[1]} "; fi
        done
    fi
    rows=$(ss -H -O -ltne "$@" 2>>"$LOG_FILE") || return 1
    awk -v inodes="$inodes" '$1 == "LISTEN" {
        owned=0
        for (i=6; i<=NF; i++) if ($i ~ /^ino:[0-9]+$/) {
            owned=(index(inodes, " " substr($i, 5) " ") != 0); break
        }
        print $4, owned
    }' <<< "$rows"
}

ssh_bindings_present() {
    local expected=$1 actual=$2 endpoint port
    while IFS= read -r endpoint; do
        [[ -n "$endpoint" ]] || continue
        if grep -Fx -- "$endpoint" <<< "$actual" >/dev/null; then continue; fi
        port=${endpoint##*:}
        case "$endpoint" in
            "0.0.0.0:$port"|"[::]:$port") grep -Fx -- "*:$port" <<< "$actual" >/dev/null || return 1;;
            *) return 1;;
        esac
    done <<< "$expected"
}

configure_ssh() {
    section_header "8" "SSH 配置"

    [[ -z "$NEW_SSH_PORT" ]] && [[ "$non_interactive" = false ]] && { read -p "SSH端口 (留空保持当前): " -r NEW_SSH_PORT < /dev/tty; }
    
    if [[ -n "$NEW_SSH_PORT" ]] && ! valid_ssh_port "$NEW_SSH_PORT"; then
        result_warn "SSH 端口必须是 1-65535 的十进制整数（无前导零）"
        return 1
    fi
    if [[ -z "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = false ]]; then
        read -r -s -p "root密码 (输入时不可见, 留空跳过): " NEW_SSH_PASSWORD < /dev/tty
        echo
    fi
    if [[ "$NEW_SSH_PASSWORD" = *$'\n'* || "$NEW_SSH_PASSWORD" = *$'\r'* ]]; then
        result_warn "root 密码必须为单行（不含换行或回车），未修改 SSH 或密码"
        return 1
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}⚠ 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi

    if [[ -n "$NEW_SSH_PORT" ]]; then
        local socket_unit
        for socket_unit in ssh.socket sshd.socket; do
            if systemctl is-active --quiet "$socket_unit"; then
                result_warn "检测到活动的 $socket_unit；端口由 socket 管理，未修改 SSH，请先自行配置 socket 监听端口"
                return 1
            fi
        done
    fi
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]] && ! command -v sshd >/dev/null 2>&1; then
        step_info "安装 openssh-server..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y openssh-server >> "$LOG_FILE" 2>&1 || return 1
    fi

    local ssh_backup="" ssh_unit="" ssh_dropin="/etc/ssh/sshd_config.d/99-vps-setup.conf"
    restart_ssh_service() {
        local unit
        for unit in ssh.service sshd.service; do
            if systemctl cat "$unit" >/dev/null 2>&1; then
                if systemctl restart "$unit" >> "$LOG_FILE" 2>&1 && systemctl is-active --quiet "$unit"; then
                    ssh_unit="$unit"
                    return 0
                fi
            fi
        done
        return 1
    }
    rollback_ssh() {
        if [[ -e "$ssh_backup" || -L "$ssh_backup" ]]; then
            cp -a --remove-destination "$ssh_backup" "$ssh_dropin" || { result_warn "SSH 恢复失败，备份：$ssh_backup"; return 1; }
        else
            rm -f "$ssh_dropin" || return 1
        fi
        if [[ "${1:-}" = restart ]]; then
            restart_ssh_service || { result_warn "原 SSH 服务恢复失败，请检查日志；备份：$ssh_backup"; return 1; }
        fi
        rm -f "$ssh_backup"
    }
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if [[ ! -f /etc/ssh/sshd_config ]] || ! command -v sshd >/dev/null 2>&1; then
            log "${RED}✗ 未找到 SSH 配置或 sshd，无法修改 SSH。${NC}"
            return 1
        fi
    fi
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local listeners ssh_tmp effective_ports effective ssh_pid unit expected actual
        result_warn "请先在防火墙和安全组放行 TCP ${NEW_SSH_PORT}，保留当前 SSH 连接"
        ssh_pid=0
        for unit in ssh.service sshd.service; do
            if ! systemctl is-active --quiet "$unit"; then continue; fi
            ssh_pid=$(systemctl show --property=MainPID --value "$unit" 2>>"$LOG_FILE") || return 1
            break
        done
        listeners=$(ssh_socket_rows "$ssh_pid" "sport = :${NEW_SSH_PORT}") || return 1
        if [[ "$listeners" = *' 0' || "$listeners" = *$' 0\n'* ]]; then
            log "${RED}✗ SSH端口 ${NEW_SSH_PORT} 已被其他服务占用，未修改 SSH 配置。${NC}"
            return 1
        fi
        ssh_backup="${ssh_dropin}.backup.$(date +%Y%m%d-%H%M%S).$$"
        if [[ -e "$ssh_dropin" || -L "$ssh_dropin" ]]; then cp -a "$ssh_dropin" "$ssh_backup" || return 1; fi
        mkdir -p "${ssh_dropin%/*}" || return 1
        ssh_tmp=$(mktemp "${ssh_dropin}.tmp.XXXXXX") || return 1
        apply_ssh_port() {
            printf 'Port %s\n' "$NEW_SSH_PORT" > "$ssh_tmp" || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
            mv -fT -- "$ssh_tmp" "$ssh_dropin" || return 1
            [[ "$signal_rc" -eq 0 ]] || return 1
            if ! effective=$(sshd -T 2>>"$LOG_FILE") ||
               ! effective_ports=$(awk '$1 == "port" {print $2}' <<< "$effective" | sort -u) ||
               [[ "$effective_ports" != "$NEW_SSH_PORT" ]] ||
               ! expected=$(awk -v port="$NEW_SSH_PORT" '$1 == "listenaddress" {
                   if ($2 !~ (":" port "$")) bad=1; else print $2
               } END {exit bad}' <<< "$effective"); then
                result_warn "SSH Port / ListenAddress 冲突、缺少 Include 或仅限本地绑定；请自行整理配置后重试"
                return 1
            fi
            # sshd -T lists IPv6 addresses even if the kernel has IPv6 disabled.
            if ! IFS= read -r _ 2>/dev/null < /proc/net/if_inet6; then
                expected=$(awk '$0 !~ /^\[/' <<< "$expected") || return 1
            fi
            if [[ -z "$(ssh_remote_endpoints <<< "$expected")" ]] || ! sshd -t 2>>"$LOG_FILE"; then
                result_warn "SSH 配置错误或仅限本地绑定，正在恢复原配置"
                return 1
            fi
            [[ "$signal_rc" -eq 0 ]] || return 1
            restart_needed=restart
            if ! restart_ssh_service; then
                result_warn "SSH 服务重启失败，正在恢复配置"
                return 1
            fi
            [[ "$signal_rc" -eq 0 ]] || return 1
            sleep 1
            [[ "$signal_rc" -eq 0 ]] || return 1
            if ! systemctl is-active --quiet "$ssh_unit" ||
               ! ssh_pid=$(systemctl show --property=MainPID --value "$ssh_unit" 2>>"$LOG_FILE") ||
               [[ ! "$ssh_pid" =~ ^[1-9][0-9]*$ ]] ||
               ! listeners=$(ssh_socket_rows "$ssh_pid" "sport = :${NEW_SSH_PORT}") ||
               [[ "$listeners" = *' 0' || "$listeners" = *$' 0\n'* ]] ||
               ! actual=$(awk -v port="$NEW_SSH_PORT" '$1 ~ (":" port "$") && $2 == 1 {print $1}' <<< "$listeners") ||
               [[ -z "$(ssh_remote_endpoints <<< "$actual")" ]] || ! ssh_bindings_present "$expected" "$actual"; then
                result_warn "SSH 未监听新端口，正在恢复配置"
                return 1
            fi
        }
        local signal_rc=0 saved_int saved_term restart_needed='' failed=false
        saved_int=$(trap -p INT); saved_term=$(trap -p TERM)
        # Keep the rollback in the foreground after any in-flight command returns.
        trap 'signal_rc=130' INT
        trap 'signal_rc=143' TERM
        if ! apply_ssh_port || [[ "$signal_rc" -ne 0 ]]; then
            failed=true
            # The rename can have completed even when the command returned nonzero.
            if [[ ! -e "$ssh_tmp" ]]; then
                rollback_ssh "$restart_needed" || :
            else
                rm -f -- "$ssh_tmp" "$ssh_backup" || :
            fi
        fi
        trap - INT TERM
        [[ -z "$saved_int" ]] || eval "$saved_int"
        [[ -z "$saved_term" ]] || eval "$saved_term"
        [[ "$signal_rc" -eq 0 ]] || return "$signal_rc"
        [[ "$failed" = false ]] || return 1
        rm -f -- "$ssh_backup" || return 1
        result_ok "SSH 已监听端口：${NEW_SSH_PORT}；请保留当前连接并测试新连接"
    fi

    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        printf 'root:%s\n' "$NEW_SSH_PASSWORD" | chpasswd >> "$LOG_FILE" 2>&1 || return 1
        result_ok "root 密码已设置"
    fi
}

ssh_listening_ports() {
    local unit state pid rows actual expected endpoint port endpoints=''
    for unit in ssh.service sshd.service ssh.socket sshd.socket; do
        state=$(systemctl show --property=ActiveState --value "$unit" 2>>"$LOG_FILE") || return 1
        case "$state" in
            inactive|failed) continue;;
            active) ;;
            *) return 1;;
        esac
        if [[ "$unit" = *.socket ]]; then
            # Systemd owns sockets before sshd starts. Confirm the active TCP
            # bindings listed by the manager against PID 1's actual sockets.
            expected=$(systemctl show --property=Listen --value "$unit" 2>>"$LOG_FILE" |
                awk '{for (i=2; i<=NF; i++) if ($i == "(Stream)" && $(i-1) ~ /:[0-9]+$/) print $(i-1)}') || return 1
            [[ -n "$expected" ]] || return 1
            pid=1
        else
            expected=''
            pid=$(systemctl show --property=MainPID --value "$unit" 2>>"$LOG_FILE") || return 1
            [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
        fi
        rows=$(ssh_socket_rows "$pid") || return 1
        actual=$(awk '$2 == 1 {print $1}' <<< "$rows") || return 1
        if [[ -n "$expected" ]]; then
            ssh_bindings_present "$expected" "$actual" || return 1
            actual=$expected
        fi
        endpoints+="$actual"$'\n'
    done
    endpoints=$(ssh_remote_endpoints <<< "$endpoints") || return 1
    [[ -n "$endpoints" ]] || return 1
    while IFS= read -r endpoint; do
        port=${endpoint##*:}
        valid_ssh_port "$port" || return 1
        printf '%s\n' "$port"
    done <<< "$endpoints" | sort -un | paste -sd, -
}

fail2ban_service_state() {
    systemctl show --property=LoadState --property=ActiveState --property=UnitFileState fail2ban.service 2>>"$LOG_FILE" |
        awk -F= '
            $1 == "LoadState" {load=$2}
            $1 == "ActiveState" {active=$2}
            $1 == "UnitFileState" {boot=$2}
            END {
                if (load == "not-found" && active == "inactive" && boot == "") print "inactive:absent"
                else if (load == "loaded" && active ~ /^(active|inactive|failed)$/ && boot ~ /^(enabled|enabled-runtime|disabled)$/)
                    print (active == "active" ? "active" : "inactive") ":" boot
                else exit 1
            }'
}

configure_fail2ban() {
    section_header "9" "Fail2ban 配置"
    local port_list original_state jail_file="/etc/fail2ban/jail.d/99-vps-setup.local" jail_tmp='' jail_backup
    port_list=$(ssh_listening_ports) || { result_warn "无法确认 SSH 实际监听端口，未修改 Fail2ban"; return 1; }
    original_state=$(fail2ban_service_state) || { result_warn "无法确认 Fail2ban 原服务状态，未修改"; return 1; }
    jail_backup="${jail_file}.backup.$(date +%Y%m%d-%H%M%S).$$"
    if [[ -e "$jail_file" || -L "$jail_file" ]]; then cp -a "$jail_file" "$jail_backup" || return 1; fi
    restore_fail2ban_jail() {
        local failed=false current wanted=${original_state%:*} boot=${original_state#*:}
        if [[ -e "$jail_backup" || -L "$jail_backup" ]]; then
            cp -a --remove-destination -- "$jail_backup" "$jail_file" || failed=true
        else
            rm -f -- "$jail_file" || failed=true
        fi
        if [[ "$wanted" = active ]]; then
            if [[ "$failed" = false && "$service_touched" = true ]]; then systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || failed=true; fi
        else
            current=$(fail2ban_service_state) || current=''
            if [[ "$current" != inactive:* ]]; then systemctl stop fail2ban >> "$LOG_FILE" 2>&1 || failed=true; fi
        fi
        current=$(fail2ban_service_state) || current=''
        if [[ "$boot" = absent && "$current" != *:absent ]]; then boot=disabled; fi
        if [[ "${current#*:}" != "$boot" ]]; then
            case "$boot" in
                enabled) systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || failed=true;;
                disabled|enabled-runtime)
                    systemctl disable fail2ban >> "$LOG_FILE" 2>&1 || failed=true
                    if [[ "$boot" = enabled-runtime ]]; then systemctl enable --runtime fail2ban >> "$LOG_FILE" 2>&1 || failed=true; fi;;
            esac
        fi
        current=$(fail2ban_service_state) || failed=true
        [[ "$current" = "$wanted:$boot" ]] || failed=true
        if [[ "$failed" = true ]]; then
            result_warn "Fail2ban 恢复不完整，请检查日志及原 jail 备份：$jail_backup"
            return 1
        fi
        rm -f -- "$jail_backup"
    }
    apply_fail2ban() {
        if [[ "$original_state" = *:absent ]] || ! command -v fail2ban-client >/dev/null 2>&1; then
            step_info "安装 Fail2ban..."
            service_touched=true
            DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y fail2ban >> "$LOG_FILE" 2>&1 || return 1
        fi
        [[ "$signal_rc" -eq 0 ]] || return 1
        mkdir -p "${jail_file%/*}" || return 1
        jail_tmp=$(mktemp "${jail_file}.vps-setup.XXXXXX") || return 1
        cat > "$jail_tmp" << EOF || return 1
[sshd]
# 永久封禁：输错 SSH 密码达到 maxretry 后，来源 IP 不会自动解封。
bantime = -1
findtime = 300
maxretry = 3
backend = systemd
enabled = true
port = ${port_list}
EOF

        [[ "$signal_rc" -eq 0 ]] || return 1
        mv -fT -- "$jail_tmp" "$jail_file" || return 1
        [[ "$signal_rc" -eq 0 ]] || return 1
        fail2ban-client -t >> "$LOG_FILE" 2>&1 || return 1
        [[ "$signal_rc" -eq 0 ]] || return 1
        service_touched=true
        systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || return 1
        local attempt current
        for attempt in 1 2 3 4 5; do
            [[ "$signal_rc" -eq 0 ]] || return 1
            if systemctl is-active --quiet fail2ban && verify_sshd_jail; then
                current=$(fail2ban_service_state) || return 1
                [[ "$signal_rc" -eq 0 ]] || return 1
                if [[ "$current" != active:enabled ]]; then
                    systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || return 1
                    current=$(fail2ban_service_state) || return 1
                fi
                [[ "$current" = active:enabled ]] || return 1
                return 0
            fi
            if [[ "$attempt" -lt 5 ]]; then sleep 1; fi
        done
        return 1
    }
    verify_sshd_jail() {
        local actual actions action found=false
        fail2ban-client status sshd >> "$LOG_FILE" 2>&1 || return 1
        actual=$(fail2ban-client get sshd maxretry 2>>"$LOG_FILE") || return 1
        [[ "$actual" = 3 ]] || return 1
        actual=$(fail2ban-client get sshd findtime 2>>"$LOG_FILE") || return 1
        [[ "$actual" = 300 ]] || return 1
        actual=$(fail2ban-client get sshd bantime 2>>"$LOG_FILE") || return 1
        [[ "$actual" = -1 ]] || return 1
        # A file backend cannot answer journalmatch; do not accept a silent override.
        actual=$(fail2ban-client get sshd journalmatch 2>>"$LOG_FILE") || return 1
        # Require an unqualified SSH branch, not a substring inside a
        # contradictory AND clause or a different process name.
        awk '
            function finish() { if (count && ssh && !extra) good=1; count=ssh=extra=0 }
            /^Current match filter:/ { next }
            { for (i=1; i<=NF; i++) {
                if ($i == "+") { finish(); continue }
                count++
                if ($i ~ /^(_COMM=sshd|_COMM=sshd-session|_SYSTEMD_UNIT=ssh[.]service|_SYSTEMD_UNIT=sshd[.]service)$/) ssh=1
                else extra=1
            } }
            END { finish(); exit !good }
        ' <<< "$actual" || return 1
        actions=$(fail2ban-client get sshd actions 2>>"$LOG_FILE") || return 1
        actions=$(printf '%s\n' "$actions" | sed '/^The jail /d' | tr ',' '\n') || return 1
        while IFS= read -r action; do
            action=${action//[[:space:]]/}
            [[ -n "$action" ]] || continue
            # Notification actions have no port property; require at least one
            # port-scoped action and validate every action that exposes ports.
            if ! actual=$(fail2ban-client get sshd action "$action" port 2>>"$LOG_FILE"); then continue; fi
            [[ "$actual" = "$port_list" ]] || return 1
            found=true
        done <<< "$actions"
        [[ "$found" = true ]]
    }
    local service_touched=false signal_rc=0 saved_int saved_term failed=false
    saved_int=$(trap -p INT); saved_term=$(trap -p TERM)
    # apt can start and enable Fail2ban before its jail has been written.
    trap 'signal_rc=130' INT
    trap 'signal_rc=143' TERM
    if ! apply_fail2ban || [[ "$signal_rc" -ne 0 ]]; then
        failed=true
        if [[ -n "$jail_tmp" ]]; then rm -f -- "$jail_tmp" || result_warn "无法清理 Fail2ban 临时文件：$jail_tmp"; fi
        if restore_fail2ban_jail; then result_warn "Fail2ban 安装、校验或启用失败，已恢复原 jail 和服务状态"; fi
    fi
    trap - INT TERM
    [[ -z "$saved_int" ]] || eval "$saved_int"
    [[ -z "$saved_term" ]] || eval "$saved_term"
    [[ "$signal_rc" -eq 0 ]] || return "$signal_rc"
    [[ "$failed" = false ]] || return 1
    rm -f -- "$jail_backup" || return 1
    result_ok "Fail2ban 已启动，保护 SSH 端口：${port_list}；5 分钟内失败 3 次永久封禁"
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
        log "未请求系统升级或清理，跳过${NC}"
    fi
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================
main() {
    trap 'handle_error ${LINENO}' ERR
    parse_args "$@"
    [[ $EUID -ne 0 ]] && { printf '%b\n' "${RED}需要root权限${NC}"; exit 1; }

    if [[ "$non_interactive" = false ]] && ! ( : < /dev/tty ) 2>/dev/null; then
        log "${RED}✗ 当前没有可用终端，请使用 --non-interactive${NC}"
        exit 2
    fi

    section_header "" "配置摘要"
    print_summary_row "主机名" "${NEW_HOSTNAME:-保持当前}"
    print_summary_row "时区" "${TIMEZONE:-保持当前}"
    print_summary_row "BBR" "$([[ "$ENABLE_BBR" = true ]] && echo "启用 (fq + bbr)" || echo "切换为 cubic（保留 qdisc）")"
    case "$SWAP_SIZE_MB" in
        auto) print_summary_row "Swap" "按内存自动配置" ;;
        0) print_summary_row "Swap" "禁用全部（含分区）" ;;
        *) print_summary_row "Swap" "${SWAP_SIZE_MB}MB" ;;
    esac
    print_summary_row "DNS" "IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$(has_ipv6 && echo "，IPv6 ${PRIMARY_DNS_V6} / ${SECONDARY_DNS_V6}")"
    print_summary_row "DNS 管理" "统一静态接管，停用 resolved 并禁止自动覆盖"
    print_summary_row "Fail2ban" "$([[ "$ENABLE_FAIL2BAN" = true ]] && echo "SSH 防护：5 分钟内失败 3 次永久封禁" || echo "跳过配置（保持已有服务）")"
    [[ -n "$NEW_SSH_PORT" ]] && print_summary_row "SSH 端口" "$NEW_SSH_PORT"
    print_summary_row "系统升级" "$([[ "$UPGRADE_SYSTEM" = true ]] && echo "是" || echo "否")"
    print_summary_row "系统清理" "$([[ "$CLEAN_SYSTEM" = true ]] && echo "是" || echo "否")"

    if [[ "$non_interactive" = false ]]; then
        read -p "开始配置? [Y/n] " -r < /dev/tty
        [[ "$REPLY" =~ ^[Nn]$ ]] && exit 0
    fi
    
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    echo "VPS 初始化日志 - $(date)" > "$LOG_FILE"
    
    log "\n开始执行配置...${NC}"
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
    if [[ "$ENABLE_FAIL2BAN" = true ]]; then configure_fail2ban; fi
    system_update
    
    section_header "" "完成"
    log "${GREEN}  ✔ VPS 初始化配置全部完成！${NC}"
    print_summary_row "执行耗时" "$(format_duration "$SECONDS")"
    print_summary_row "日志文件" "$LOG_FILE"
    
    log "\n建议重启以确保所有配置生效${NC}"
    if [[ "$non_interactive" = false ]]; then
        read -p "立即重启? [y/N] " -r < /dev/tty
        [[ "$REPLY" =~ ^[Yy]$ ]] && { log "重启中...${NC}"; sleep 2; reboot; }
    fi
    
    exit 0
}

main "$@"
