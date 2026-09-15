#!/bin/bash

# ==============================================================================
# VPS 通用初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: v26.09.15
# ==============================================================================
set -Eeuo pipefail

# --- 默认配置 ---
# shellcheck disable=SC2034
SCRIPT_VERSION="v26.09.15"
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
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
    local number="$1" title="$2" text
    if [[ -n "$title" ]]; then
        text="${number:+${number}. }${title}"
    else
        text="${number}"
    fi
    log ""
    log "${BOLD}${text}${NC}"
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

usage() {
    local exit_code="${1:-0}" out=/dev/stdout
    [[ "$exit_code" -eq 0 ]] || out=/dev/stderr
    cat > "$out" << EOF
${BOLD}用法: $0 [选项]${NC}

${YELLOW}▸ 核心${NC}
  --hostname <name>        设置主机名（字母、数字、连字符；首尾为字母或数字）
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
  --ssh-password <pass>    设置 root 密码
  --upgrade                执行系统 full-upgrade
  --cleanup                执行 autoremove 和 apt clean

${YELLOW}▸ 其他${NC}
  -h, --help               显示帮助
  --non-interactive        非交互模式

默认：保留主机名、时区和 SSH 设置；交互模式另行询问主机名和 SSH。
启用 BBR、Fail2ban；Swap 使用 auto，容量不一致时替换全部现有 Swap。
DNS 默认 IPv4：1.1.1.1 / 8.8.8.8；IPv6：2606:4700:4700::1111 / 2001:4860:4860::8888。
DNS 参数须用引号包含两个地址；仅检测到 IPv6 时配置 IPv6 DNS。
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

valid_ssh_port() {
    [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( $1 <= 65535 ))
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
        log "${RED}✗ 不支持在容器环境执行，请在完整 VPS 或虚拟机中运行${NC}"
        exit 1
    fi
    [[ ! -f /etc/os-release ]] && { log "${RED}错误: 系统信息缺失${NC}"; exit 1; }
    # shellcheck source=/dev/null
    source /etc/os-release
    local supported=false
    [[ "$ID" = "debian" && "$VERSION_ID" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "$ID" = "ubuntu" && "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04|26\.04)$ ]] && supported=true
    if [[ "$supported" = "false" ]]; then
        log "${YELLOW}⚠ 系统: ${PRETTY_NAME} (建议使用Debian 10-13或Ubuntu 20.04-26.04)${NC}"
        if [[ "$non_interactive" = true ]]; then
            log "${RED}✗ 非交互模式不支持当前系统，已中止${NC}"
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
    log "  当前主机名：${current_hostname}${NC}"
    local final_hostname="$current_hostname"
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOG_FILE" 2>&1
            final_hostname="$NEW_HOSTNAME"
        fi
    elif [[ "$non_interactive" = false ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            read -r -p "新主机名（留空保持当前）: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name" >> "$LOG_FILE" 2>&1
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"
            elif [[ -n "$new_name" ]]; then
                result_warn "主机名仅限字母、数字和连字符，首尾须为字母或数字；保持当前：${current_hostname}"
            fi
        fi
    fi
    if [[ "$final_hostname" != "$current_hostname" ]]; then
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t${final_hostname}/" /etc/hosts
        else
            printf '%b\n' "127.0.1.1\t${final_hostname}" >> /etc/hosts
        fi
        result_ok "主机名设为: ${final_hostname}"
    else
        log "  主机名保持当前${NC}"
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

    if systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null; then
        log "${YELLOW}  ⚠ 检测到已有 NTP 服务正在运行 (chrony/ntp)，保持现状${NC}"
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

    if timedatectl status 2>/dev/null | grep -q 'NTP service: active' || systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
        result_ok "时间同步已启用 (systemd-timesyncd)"
    else
        result_warn "时间同步服务未确认激活，建议后续检查"
    fi
}

# GNU sed preserves unrelated bytes, including a missing final newline.
# The owned file replaces active keys; other files keep retired lines as comments.
bbr_filter() {
    local key expression="" action='s/^/# vps-setup: /'
    [[ "${3:-}" != replace ]] || action=d
    while IFS= read -r key; do
        key=${key//./[.\/]}
        expression+="\\|^[[:space:]]*-?${key}[[:space:]]*=|${action};"
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
            [[ "$resolved" != /dev/null ]] || { [[ "$file" != "$config_file" ]] && continue; return 1; }
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
                cp -a -- "$resolved" "$backup/old.$i" || return 1
                if [[ "$resolved" = "$config_target" ]]; then
                    bbr_filter "$keys" "$resolved" replace >> "$backup/new.$i" || return 1
                else
                    bbr_filter "$keys" "$resolved" >> "$backup/new.$i" || return 1
                fi
                if cmp -s -- "$backup/old.$i" "$backup/new.$i"; then
                    rm -f -- "$backup/old.$i" "$backup/new.$i" || return 1
                    continue
                fi
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
            mv -f -- "$tmp" "$file" || return 1
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
    sed -i -E '\|^[[:space:]]*[^#[:space:]][^[:space:]]*[[:space:]]+[^[:space:]]+[[:space:]]+swap([[:space:]]\|$)|d' /etc/fstab
}

configure_swap() {
    section_header "6" "Swap 配置"
    local swap_file="/swapfile" swap_mb="$SWAP_SIZE_MB" current_total_mb=0 size_bytes swap_line
    local snapshot active_swap new_swap="" backup old_moved=false new_installed=false failed=false
    local -a stopped=()
    snapshot=$(swapon --show=NAME --noheadings --raw) || return 1
    if [[ "$swap_mb" = auto ]]; then
        local mem_mb
        mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo) || return 1
        if (( mem_mb < 1024 )); then swap_mb=$mem_mb
        elif (( mem_mb < 4096 )); then swap_mb=2048
        else swap_mb=4096; fi
    fi
    local sizes
    sizes=$(swapon --show=NAME,SIZE --bytes --noheadings --raw) || return 1
    while IFS= read -r swap_line; do
        [[ -n "$swap_line" ]] || continue
        size_bytes=${swap_line##* }
        [[ "$size_bytes" =~ ^[0-9]+$ ]] || return 1
        current_total_mb=$((current_total_mb + (size_bytes + 524288) / 1048576))
    done <<< "$sizes"
    if [[ "$swap_mb" != 0 && "$current_total_mb" -eq "$swap_mb" ]]; then
        if grep -Fxq "$swap_file" <<< "$snapshot"; then ensure_swap_fstab_entry || return 1; fi
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
    [[ ! -L "$swap_file" ]] || { result_warn "拒绝替换符号链接 $swap_file"; return 1; }
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
    if ! cp -a /etc/fstab "$backup/fstab"; then
        [[ -z "$new_swap" ]] || rm -f "$new_swap"
        rmdir "$backup"; return 1
    fi
    rollback_swap() {
        local restore_failed=false swap_file_blocked=false item remaining
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
        cp -a "$backup/fstab" /etc/fstab || restore_failed=true
        for item in "${stopped[@]}"; do
            # 冲突路径不能冒充旧 Swap；fstab 和其他旧 Swap 仍独立恢复。
            [[ "$item" != "$swap_file" || "$swap_file_blocked" = false ]] || continue
            swapon "$item" >> "$LOG_FILE" 2>&1 || restore_failed=true
        done
        [[ -z "$new_swap" ]] || rm -f "$new_swap"
        if [[ "$restore_failed" = true ]]; then
            result_warn "Swap 恢复不完整，请检查日志及备份：$backup"
        else
            rm -rf "$backup"
            result_warn "Swap 变更失败，已恢复旧配置和活动 Swap"
        fi
        return 1
    }
    while IFS= read -r active_swap; do
        [[ -n "$active_swap" ]] || continue
        if ! swapoff "$active_swap" >> "$LOG_FILE" 2>&1; then failed=true; break; fi
        stopped+=("$active_swap")
    done <<< "$snapshot"
    if [[ "$failed" = true ]]; then rollback_swap; return 1; fi
    if [[ -e "$swap_file" ]]; then
        if ! mv "$swap_file" "$backup/swapfile"; then rollback_swap; return 1; fi
        old_moved=true
    fi
    if ! remove_fstab_swap_entries; then rollback_swap; return 1; fi
    if [[ "$swap_mb" != 0 ]]; then
        if ! mv "$new_swap" "$swap_file"; then rollback_swap; return 1; fi
        new_installed=true
        if ! swapon "$swap_file" >> "$LOG_FILE" 2>&1 || ! ensure_swap_fstab_entry; then rollback_swap; return 1; fi
    fi
    local final_swap
    if ! final_swap=$(swapon --show=NAME --noheadings --raw) ||
       { [[ "$swap_mb" = 0 ]] && [[ -n "$final_swap" ]]; } ||
       { [[ "$swap_mb" != 0 ]] && [[ "$final_swap" != "$swap_file" ]]; }; then
        rollback_swap; return 1
    fi
    rm -rf "$backup" || return 1
    if [[ "$swap_mb" = 0 ]]; then
        result_ok "全部 Swap 已禁用，Swap 启动条目及 /swapfile 已移除"
    else
        result_ok "Swap 已配置：${swap_mb}MB（/swapfile）"
    fi
}

configure_dns() {
    section_header "7" "DNS 配置"
    local ipv6_enabled=false
    has_ipv6 && ipv6_enabled=true
    if (systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]); then
        result_warn "云环境可能覆盖 DNS 配置"
    fi
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        mkdir -p /etc/systemd/resolved.conf.d || return 1
        local resolved_file="/etc/systemd/resolved.conf.d/99-custom-dns.conf"
        local resolved_tmp resolved_backup
        resolved_backup=$(mktemp -d) || return 1
        if [[ -e "$resolved_file" || -L "$resolved_file" ]]; then
            cp -a "$resolved_file" "$resolved_backup/config" || { rmdir "$resolved_backup"; return 1; }
        fi
        resolved_tmp=$(mktemp "${resolved_file}.XXXXXX") || { rm -rf "$resolved_backup"; return 1; }
        restore_resolved() {
            if [[ -e "$resolved_backup/config" || -L "$resolved_backup/config" ]]; then
                cp -a --remove-destination "$resolved_backup/config" "$resolved_file" || { result_warn "恢复失败，备份：$resolved_backup"; return 1; }
            else
                rm -f "$resolved_file" || return 1
            fi
            if ! systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 ||
               ! systemctl is-active --quiet systemd-resolved || ! resolvectl dns >> "$LOG_FILE" 2>&1; then
                result_warn "原 DNS 服务恢复失败，请检查日志；保留备份：$resolved_backup"
                return 1
            fi
            rm -rf "$resolved_backup"
        }
        if ! cat > "$resolved_tmp" << EOF
[Resolve]
DNS=${PRIMARY_DNS_V4} ${SECONDARY_DNS_V4}$( [[ "$ipv6_enabled" == true ]] && echo " ${PRIMARY_DNS_V6} ${SECONDARY_DNS_V6}" )
FallbackDNS=1.0.0.1 8.8.4.4
EOF
        then
            rm -f "$resolved_tmp"; rm -rf "$resolved_backup"; return 1
        fi
        if ! chmod 644 "$resolved_tmp" || ! mv -f "$resolved_tmp" "$resolved_file"; then
            rm -f "$resolved_tmp"; rm -rf "$resolved_backup"; return 1
        fi
        local expected_dns="$PRIMARY_DNS_V4 $SECONDARY_DNS_V4" actual_dns
        [[ "$ipv6_enabled" != true ]] || expected_dns+=" $PRIMARY_DNS_V6 $SECONDARY_DNS_V6"
        verify_resolved_dns() {
            actual_dns=$(LC_ALL=C SYSTEMD_COLORS=0 resolvectl dns 2>>"$LOG_FILE") || return 1
            # 仅核对 Global（含折行），忽略 Link；地址按集合比较，IPv6 展开后比较。
            awk -v expected="$expected_dns" '
                function normalize(ip, halves, left, right, n, m, i, out) {
                    ip = tolower(ip)
                    if (ip !~ /^[0-9a-f:.]+$/) return ip
                    if (index(ip, ":")) {
                        split(ip, halves, "::")
                        n = split(halves[1], left, ":")
                        m = split(halves[2], right, ":")
                        if (index(ip, "::")) {
                            for (i = n + 1; i <= 8 - m; i++) left[i] = "0"
                            for (i = 1; i <= m; i++) left[8 - m + i] = right[i]
                            n = 8
                        }
                        for (i = 1; i <= n; i++) {
                            sub(/^0+/, "", left[i])
                            out = out ":" (left[i] == "" ? "0" : left[i])
                        }
                        return out
                    }
                    n = split(ip, left, ".")
                    for (i = 1; i <= n; i++) out = out "." (left[i] + 0)
                    return out
                }
                BEGIN { n = split(expected, a); for (i = 1; i <= n; i++) want[normalize(a[i])] = 1 }
                /^[^[:space:]]/ { global = 0 }
                /^Global:/ { global = 1; seen = 1; sub(/^Global:[[:space:]]*/, "") }
                global { for (i = 1; i <= NF; i++) got[normalize($i)] = 1 }
                END {
                    if (!seen) exit 1
                    for (ip in want) if (!(ip in got)) exit 1
                    for (ip in got) if (!(ip in want)) exit 1
                }
            ' <<< "$actual_dns"
        }
        if ! systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 ||
           ! systemctl is-active --quiet systemd-resolved || ! verify_resolved_dns; then
            restore_resolved
            result_warn "DNS 重启或验证失败，已尝试恢复原配置"
            return 1
        fi
        rm -rf "$resolved_backup"
        result_ok "DNS 配置完成：IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$([[ "$ipv6_enabled" = true ]] && echo "，IPv6 ${PRIMARY_DNS_V6} / ${SECONDARY_DNS_V6}")"
        return 0
    else
        step_info "配置 resolv.conf..."
        if [[ -L /etc/resolv.conf ]]; then
            result_warn "/etc/resolv.conf 是符号链接，跳过直接修改，请由当前 DNS 管理器配置"
            return 0
        fi
        cp -a /etc/resolv.conf "/etc/resolv.conf.backup.$(date +%Y%m%d-%H%M%S).$$" 2>>"$LOG_FILE" || {
            log "${RED}✗ 无法备份 /etc/resolv.conf，已停止修改。${NC}"
            return 1
        }
        local resolv_tmp="/etc/resolv.conf.vps-setup.$$"
        if ! cat > "$resolv_tmp" << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$( [[ "$ipv6_enabled" == true ]] && printf 'nameserver %s\nnameserver %s\n' "$PRIMARY_DNS_V6" "$SECONDARY_DNS_V6" )
EOF
        then
            rm -f "$resolv_tmp"; return 1
        fi
        if ! mv -f "$resolv_tmp" /etc/resolv.conf; then
            rm -f "$resolv_tmp"
            log "${RED}✗ 无法替换 /etc/resolv.conf${NC}"
            return 1
        fi
    fi
    if command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolvectl dns >/dev/null 2>&1 || {
            log "${RED}✗ 无法验证 systemd-resolved DNS 状态${NC}"
            return 1
        }
    elif [[ ! -s /etc/resolv.conf ]]; then
        log "${RED}✗ /etc/resolv.conf 为空，DNS 配置未生效${NC}"
        return 1
    fi
    result_ok "DNS 配置完成：IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$([[ "$ipv6_enabled" = true ]] && echo "，IPv6 ${PRIMARY_DNS_V6} / ${SECONDARY_DNS_V6}")"
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
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}⚠ 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi

    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]] && ! dpkg -l openssh-server >/dev/null 2>&1; then
        step_info "安装 openssh-server..."
        DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y openssh-server >> "$LOG_FILE" 2>&1 || return 1
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
    rollback_ssh() {
        if [[ -e "$ssh_backup" || -L "$ssh_backup" ]]; then
            cp -a --remove-destination "$ssh_backup" "$ssh_dropin" || { result_warn "SSH 恢复失败，备份：$ssh_backup"; return 1; }
        else
            rm -f "$ssh_dropin" || return 1
        fi
        restart_ssh_service || { result_warn "原 SSH 服务恢复失败，请检查日志"; return 1; }
        rm -f "$ssh_backup"
    }
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if [[ ! -f /etc/ssh/sshd_config ]] || ! command -v sshd >/dev/null 2>&1; then
            log "${RED}✗ 未找到 SSH 配置或 sshd，无法修改 SSH。${NC}"
            return 1
        fi
    fi
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local current_ssh_port
        result_warn "请先在防火墙和安全组放行 TCP ${NEW_SSH_PORT}，保留当前 SSH 连接"
        current_ssh_port=$(sshd -T 2>/dev/null | awk '$1 == "port" {printf "%s ", $2}') || return 1
        if [[ " $current_ssh_port " != *" ${NEW_SSH_PORT} "* ]] && ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
            log "${RED}✗ SSH端口 ${NEW_SSH_PORT} 已被其他服务占用，未修改 SSH 配置。${NC}"
            return 1
        fi
        ssh_backup="${ssh_dropin}.backup.$(date +%Y%m%d-%H%M%S).$$"
        if [[ -e "$ssh_dropin" || -L "$ssh_dropin" ]]; then cp -a "$ssh_dropin" "$ssh_backup" || return 1; fi
        mkdir -p "${ssh_dropin%/*}" || return 1
        if ! printf 'Port %s\n' "$NEW_SSH_PORT" > "${ssh_dropin}.tmp.$$" ||
           ! mv -f "${ssh_dropin}.tmp.$$" "$ssh_dropin"; then
            rm -f "${ssh_dropin}.tmp.$$"; return 1
        fi
        ssh_changed=true
        local effective_ports
        if ! effective_ports=$(sshd -T 2>>"$LOG_FILE" | awk '$1 == "port" {print $2}' | sort -u) ||
           [[ "$effective_ports" != "$NEW_SSH_PORT" ]]; then
            result_warn "SSH 有显式多端口、其他 Port 或缺少 Include；拒绝累加端口。请自行整理配置后重试"
            rollback_ssh
            return 1
        fi
    fi
    
    if [[ "$ssh_changed" = true ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
            if ! restart_ssh_service; then
                log "${RED}✗ SSH 服务重启失败，正在恢复配置。${NC}"
                rollback_ssh
                return 1
            fi
            sleep 1
            if ! ss -H -ltn 2>/dev/null | awk -v port=":${NEW_SSH_PORT}" '$4 ~ port "$" {found=1} END {exit !found}'; then
                log "${RED}✗ SSH 未监听新端口，正在恢复配置。${NC}"
                rollback_ssh
                return 1
            fi
            result_ok "SSH 已监听端口：${NEW_SSH_PORT}；请保留当前连接并测试新连接"
            rm -f "$ssh_backup"
        else
            log "${RED}✗ SSH配置错误，已恢复备份${NC}"
            rollback_ssh
            return 1
        fi
    fi

    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:${NEW_SSH_PASSWORD}" | chpasswd >> "$LOG_FILE" 2>&1 || return 1
        result_ok "root 密码已设置"
    fi
}

configure_fail2ban() {
    section_header "9" "Fail2ban 配置"
    
    local ports=() detected_port effective
    effective=$(sshd -T 2>>"$LOG_FILE") || { result_warn "无法读取 SSH 有效端口，未修改 Fail2ban"; return 1; }
    while IFS= read -r detected_port; do
        valid_ssh_port "$detected_port" || { result_warn "SSH 有效端口无效"; return 1; }
        ports+=("$detected_port")
    done < <(awk '$1 == "port" {print $2}' <<< "$effective")
    [[ ${#ports[@]} -gt 0 ]] || { result_warn "未发现 SSH 有效端口"; return 1; }

    local port_list
    port_list=$(printf "%s\n" "${ports[@]}" | sort -un | tr '\n' ',' | sed 's/,$//')
    
    step_info "安装 Fail2ban..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get "${APT_LOCK_WAIT[@]}" install -y fail2ban >> "$LOG_FILE" 2>&1; then
        log "${RED}✗ Fail2ban 安装失败，请查看日志：${LOG_FILE}${NC}"
        return 1
    fi
    
    local jail_file="/etc/fail2ban/jail.d/99-vps-setup.local"
    local jail_tmp="${jail_file}.vps-setup.$$"
    local jail_backup
    jail_backup="${jail_file}.backup.$(date +%Y%m%d-%H%M%S).$$"
    mkdir -p "${jail_file%/*}" || return 1
    if [[ -e "$jail_file" || -L "$jail_file" ]]; then cp -a "$jail_file" "$jail_backup" || return 1; fi
    restore_fail2ban_jail() {
        if [[ -e "$jail_backup" || -L "$jail_backup" ]]; then
            cp -a --remove-destination "$jail_backup" "$jail_file" || { result_warn "Fail2ban 恢复失败，备份：$jail_backup"; return 1; }
        else
            rm -f "$jail_file" || return 1
        fi
        if [[ "${1:-}" = restart ]]; then
            if ! systemctl restart fail2ban >> "$LOG_FILE" 2>&1 || ! systemctl is-active --quiet fail2ban; then
                result_warn "原 Fail2ban 服务恢复失败，请检查日志；保留备份：$jail_backup"
                return 1
            fi
        fi
        rm -f "$jail_backup"
    }
    if ! cat > "$jail_tmp" << EOF
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
    then
        rm -f "$jail_tmp"; return 1
    fi
    if ! mv -f "$jail_tmp" "$jail_file"; then rm -f "$jail_tmp"; return 1; fi
    if ! fail2ban-client -t >> "$LOG_FILE" 2>&1; then
        log "${RED}✗ Fail2ban 配置校验失败${NC}"
        restore_fail2ban_jail
        return 1
    fi
    
    if ! systemctl enable fail2ban >> "$LOG_FILE" 2>&1 || ! systemctl restart fail2ban >> "$LOG_FILE" 2>&1; then
        restore_fail2ban_jail restart || return 1
        log "${RED}✗ Fail2ban 重启失败，已恢复原配置。${NC}"
        return 1
    fi
    if systemctl is-active --quiet fail2ban; then
        rm -f "$jail_backup"
        result_ok "Fail2ban 已启动，保护 SSH 端口：${port_list}；5 分钟内失败 3 次永久封禁"
    else
        restore_fail2ban_jail restart || return 1
        log "${RED}✗ Fail2ban 启动失败，已恢复原配置${NC}"
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
        log "未请求系统升级或清理，跳过${NC}"
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
        log "${RED}✗ 当前没有可用终端，请使用 --non-interactive${NC}"
        exit 2
    fi

    section_header "" "配置摘要"
    print_summary_row "主机名" "${NEW_HOSTNAME:-保持当前}"
    print_summary_row "时区" "$TIMEZONE"
    print_summary_row "BBR" "$([[ "$ENABLE_BBR" = true ]] && echo "启用 (fq + bbr)" || echo "切换为 cubic（保留 qdisc）")"
    print_summary_row "Swap" "$([[ "$SWAP_SIZE_MB" = auto ]] && echo '按内存自动配置' || { [[ "$SWAP_SIZE_MB" = 0 ]] && echo '禁用全部（含分区）' || echo "${SWAP_SIZE_MB}MB"; })"
    print_summary_row "DNS" "IPv4 ${PRIMARY_DNS_V4} / ${SECONDARY_DNS_V4}$(has_ipv6 && echo "，IPv6 ${PRIMARY_DNS_V6} / ${SECONDARY_DNS_V6}")"
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
