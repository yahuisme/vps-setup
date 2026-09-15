#!/bin/bash
# Extract only BBR functions; all system paths and sysctl are isolated.
set -Eeuo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
export TMPDIR="$root/tmp"
mkdir -p "$TMPDIR"
mkdir -p "$root/etc/sysctl.d" "$root/run/sysctl.d" "$root/usr/local/lib/sysctl.d" "$root/usr/lib/sysctl.d" "$root/lib/sysctl.d"
# shellcheck disable=SC2218 # Deliberately use system awk before defining the fault injector.
command awk '/^(bbr_[a-z_]+|configure_bbr)\(\) \{/ { copy=1 } copy { print } copy && /^}/ { copy=0 }' "$repo/install.sh" > "$root/functions"
# Substitution is confined to the extracted functions and literal system paths.
source_text=$(<"$root/functions")
source_text=${source_text//\/etc\//$root\/etc\/}
source_text=${source_text//\/run\//$root\/run\/}
source_text=${source_text//\/usr\//$root\/usr\/}
source_text=${source_text// \/lib\/sysctl.d/ $root\/lib\/sysctl.d}
# shellcheck disable=SC1090
source /dev/stdin <<< "$source_text"
section_header() { :; }
result_warn() { printf '%s\n' "$*" >&2; }
result_ok() { printf '%s\n' "$*"; }
print_summary_row() { printf '%s：%s\n' "$1" "$2"; }
is_kernel_version_ge() { return 0; }
export LOG_FILE="$root/log"
export ENABLE_BBR=true
printf 'cubic\n' > "$root/cc"
printf 'pfifo_fast\n' > "$root/qdisc"
sysctl() {
    case "$1" in
        -n)
            case "$2" in
                net.ipv4.tcp_congestion_control) command cat "$root/cc" ;;
                net.core.default_qdisc) command cat "$root/qdisc" ;;
                *) return 1 ;;
            esac ;;
        -p)
            local key value
            while IFS='=' read -r key value; do
                key=${key// /}; value=${value// /}
                case "$key" in
                    net.ipv4.tcp_congestion_control) printf '%s\n' "$value" > "$root/cc" ;;
                    net.core.default_qdisc) printf '%s\n' "$value" > "$root/qdisc" ;;
                esac
            done < "$2" ;;
        -w)
            shift
            local pair
            for pair; do
                case "$pair" in
                    net.ipv4.tcp_congestion_control=*) printf '%s\n' "${pair#*=}" > "$root/cc" ;;
                    net.core.default_qdisc=*) printf '%s\n' "${pair#*=}" > "$root/qdisc" ;;
                    *) return 1 ;;
                esac
            done ;;
        *) return 1 ;;
    esac
}
printf '# keep\nvm.swappiness = 7\n-net/ipv4/tcp_congestion_control = reno\nnet.core.default_qdisc=fq_codel\nnet.ipv4.tcp_congestion_control_extra=keep\n' > "$root/etc/sysctl.conf"
ln -s ../sysctl.conf "$root/etc/sysctl.d/99-sysctl.conf"
if configure_bbr; then :; else printf 'FAIL: successful takeover\n' >&2; exit 1; fi
[[ -L "$root/etc/sysctl.d/99-sysctl.conf" ]]
if awk '/^-net\/ipv4\/tcp_congestion_control *=/ { found=1 } END {exit !found}' "$root/etc/sysctl.conf"; then
    printf 'FAIL: active conflicting assignment survives\n' >&2; exit 1
fi
for line in '# keep' 'vm.swappiness = 7' 'net.ipv4.tcp_congestion_control_extra=keep'; do
    grep -Fxq -- "$line" "$root/etc/sysctl.conf"
done
[[ $(<"$root/cc") == bbr && $(<"$root/qdisc") == fq ]]
# A changed file must preserve unrelated bytes, even an unterminated final line.
printf 'net.ipv4.tcp_congestion_control=reno\n# keep\t\\literal\r\nvm.swappiness=7' > "$root/etc/sysctl.conf"
printf '# vps-setup: net.ipv4.tcp_congestion_control=reno\n# keep\t\\literal\r\nvm.swappiness=7' > "$root/expected"
printf 'net.ipv4.tcp_congestion_control=reno\n# owned end' > "$root/etc/sysctl.d/99-bbr.conf"
# shellcheck disable=SC2218 # Use system cp before defining the fault injector.
command cp "$root/etc/sysctl.d/99-bbr.conf" "$root/before-owned"
configure_bbr > "$root/output"
cmp "$root/expected" "$root/etc/sysctl.conf"
retained=$(command sed -n 's/^原配置备份：//p' "$root/output")
[[ -d "$retained" && -f "$retained/paths" && -f "$retained/runtime" ]]
i=0
while IFS= read -r path; do
    if [[ "$path" = "$root/etc/sysctl.d/99-bbr.conf" ]]; then
        cmp "$root/before-owned" "$retained/old.$i"
    fi
    i=$((i + 1))
done < "$retained/paths"
printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n# owned end' > "$root/expected-owned"
cmp "$root/expected-owned" "$root/etc/sysctl.d/99-bbr.conf"
configure_bbr > "$root/output"
cmp "$root/expected-owned" "$root/etc/sysctl.d/99-bbr.conf"
! grep -q '原配置备份' "$root/output"
[[ -d "$retained" ]]
printf 'PASS: exact-key takeover, byte preservation, retained backups and stable repeat\n'
# Reuse real sysctl mock, injecting failures after partial application.
eval "$(declare -f sysctl | command sed '1s/sysctl/mock_sysctl/')"
sysctl() {
    printf '%s\n' "$*" >> "$root/calls"
    if [[ "$1" = -n && "${fault:-}" = snapshot ]]; then
        return 1
    elif [[ "$1" = -p ]]; then
        mock_sysctl "$@" || return 1
        case "${fault:-}" in
            apply|restore-copy|restore-runtime) return 1 ;;
            mismatch) printf 'reno\n' > "$root/cc" ;;
            readback) touch "$root/applied" ;;
        esac
    elif [[ "$1" = -n && -e "$root/applied" ]]; then
        rm -f "$root/applied"; return 1
    elif [[ "$1" = -w && "${fault:-}" = restore-runtime && "$2" = net.core.default_qdisc=* ]]; then
        return 1
    else
        mock_sysctl "$@"
    fi
}
cp() {
    if [[ "${fault:-}" = backup && "$*" = *'/old.'* ]]; then return 1; fi
    if [[ "${fault:-}" = restore-copy && "$*" = *--remove-destination* ]]; then return 1; fi
    command cp "$@"
}
mv() {
    if [[ "${fault:-}" = rename && "${*: -1}" = "$root/etc/sysctl.conf" ]]; then return 1; fi
    command mv "$@"
}
awk() {
    if [[ "${fault:-}" = generation && "$*" = *'/target'* ]]; then return 1; fi
    command awk "$@"
}
cat() {
    if [[ "${fault:-}" = write && "$*" = *'/new.'* ]]; then return 1; fi
    command cat "$@"
}
fixture() {
    command rm -rf "$root/etc" "$root/run" "$root/usr" "$root/lib" "$TMPDIR"
    mkdir -p "$root/etc/sysctl.d" "$root/run/sysctl.d" "$root/usr/local/lib/sysctl.d" "$root/usr/lib/sysctl.d" "$root/lib/sysctl.d" "$TMPDIR"
    printf '# keep\nnet/ipv4/tcp_congestion_control=reno\nvm.swappiness=9\n' > "$root/etc/sysctl.conf"
    printf 'net.core.default_qdisc=fq_codel\n' > "$root/etc/sysctl.d/99-bbr.conf"
    printf 'net.ipv4.tcp_congestion_control=bbr\n' > "$root/run/sysctl.d/10-vendor.conf"
    printf 'untouched-no-newline' > "$root/lib/sysctl.d/20-unrelated.conf"
    command cp "$root/etc/sysctl.conf" "$root/original"
    command cp "$root/etc/sysctl.d/99-bbr.conf" "$root/owned"
    command cp "$root/run/sysctl.d/10-vendor.conf" "$root/vendor"
    printf 'reno\n' > "$root/cc"
    printf 'pfifo_fast\n' > "$root/qdisc"
    : > "$root/calls"
}
for fault in generation snapshot backup write rename apply mismatch readback restore-copy restore-runtime; do
    fixture
    if configure_bbr > "$root/output" 2>&1; then printf 'FAIL: %s succeeded\n' "$fault"; exit 1; fi
    if [[ "$fault" != restore-copy ]]; then
        cmp "$root/original" "$root/etc/sysctl.conf"
        cmp "$root/owned" "$root/etc/sysctl.d/99-bbr.conf"
        cmp "$root/vendor" "$root/run/sysctl.d/10-vendor.conf"
    else
        grep -q -- '-w net.ipv4.tcp_congestion_control=reno' "$root/calls"
    fi
    [[ $(<"$root/cc") = reno ]]
    if [[ "$fault" != restore-runtime ]]; then [[ $(<"$root/qdisc") = pfifo_fast ]]; fi
    if [[ "$fault" = restore-* ]]; then
        grep -q '恢复不完整' "$root/output"
        backups=("$root/etc/sysctl.d"/99-bbr.conf.backup.*/runtime)
        [[ -f "${backups[0]}" ]]
    fi
    printf 'PASS: %s failure recovery\n' "$fault"
done
fault=''
fixture
ENABLE_BBR=false
configure_bbr > "$root/output"
cmp -s "$root/owned" "$root/etc/sysctl.d/99-bbr.conf" && { printf 'FAIL: missing cubic assignment\n'; exit 1; }
grep -Fxq 'net.core.default_qdisc=fq_codel' "$root/etc/sysctl.d/99-bbr.conf"
[[ $(<"$root/qdisc") = pfifo_fast && $(<"$root/cc") = cubic ]]
! grep -q 'net.core.default_qdisc' "$root/calls"
[[ $(<"$root/lib/sysctl.d/20-unrelated.conf") = untouched-no-newline ]]
printf 'PASS: cubic only owns congestion control; unrelated no-op\n'
fixture
ENABLE_BBR=true
mv "$root/etc/sysctl.d/99-bbr.conf" "$root/etc/actual"
ln -s ../actual "$root/etc/sysctl.d/99-bbr.conf"
ln -s sysctl.conf "$root/etc/alias"
ln -s ../alias "$root/etc/sysctl.d/99-sysctl.conf"
configure_bbr > "$root/output"
[[ -L "$root/etc/sysctl.d/99-bbr.conf" && -L "$root/etc/sysctl.d/99-sysctl.conf" && -L "$root/etc/alias" ]]
[[ $(grep -c '^# vps-setup: net/ipv4' "$root/etc/sysctl.conf") = 1 ]]
printf 'PASS: owned symlink and alias deduplication\n'
fixture
for dir in etc run usr/local/lib usr/lib lib; do
    printf '; comment\n -net/core/default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\nnet.ipv4.* = untouched\n' > "$root/$dir/sysctl.d/30-same.conf"
done
ln -s /dev/null "$root/etc/sysctl.d/01-mask.conf"
configure_bbr > "$root/output"
for dir in etc run usr/local/lib usr/lib lib; do
    [[ $(grep -c '^# vps-setup:' "$root/$dir/sysctl.d/30-same.conf") = 2 ]]
    grep -Fxq 'net.ipv4.* = untouched' "$root/$dir/sysctl.d/30-same.conf"
done
[[ -L "$root/etc/sysctl.d/01-mask.conf" ]]
printf 'PASS: all procps dirs, equal values, mask and unrelated wildcard\n'
fixture
rm "$root/etc/sysctl.d/99-bbr.conf"
fault=apply
if configure_bbr > "$root/output" 2>&1; then exit 1; fi
[[ ! -e "$root/etc/sysctl.d/99-bbr.conf" ]]
cmp "$root/original" "$root/etc/sysctl.conf"
printf 'PASS: failure removes newly created owned file\n'
fault=''
fixture
is_kernel_version_ge() { return 1; }
if configure_bbr > "$root/output" 2>&1; then exit 1; fi
cmp "$root/original" "$root/etc/sysctl.conf"
[[ ! -s "$root/calls" ]]
! grep -q '已生效' "$root/output"
printf 'PASS: unsupported kernel does not claim success\n'
