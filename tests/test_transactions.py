#!/usr/bin/env python3
"""Extracted system transactions; all mutators private/mocked, real signals.
Run under a bounded test slice with PYTHONDONTWRITEBYTECODE=1.
TRANSACTION_EVIDENCE optionally retains fixtures and process output.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('regression_helpers', REPO / 'tests/regression.py')
assert spec is not None and spec.loader is not None
reg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reg)

SWAP_MOCK = r'''
blkid() { printf 'swap\n'; }
swapon() { python3 "$ROOT/mock.py" swapon "$@"; }
swapoff() { python3 "$ROOT/mock.py" swapoff "$@"; }
findmnt() { python3 "$ROOT/mock.py" findmnt "$@"; }
'''
MOCK = r'''
import json, os, sys
from pathlib import Path
r = Path(os.environ['ROOT'])
s = json.loads((r/'state.json').read_text())
cmd, args = sys.argv[1], sys.argv[2:]
with (r/'calls').open('a') as f: f.write(cmd+' '+' '.join(args)+'\n')
if cmd == 'findmnt':
    print(s['fstab'], end='')
elif cmd == 'swapon' and args[0].startswith('--show='):
    cols = args[0].split('=')[1]
    for name, pri, opts in s['active']:
        print(name if cols == 'NAME' else f'{name} {1048576 if cols == "NAME,SIZE" else pri}')
elif cmd == 'swapoff':
    target = args[0]
    if target == s.get('fail_off'): sys.exit(1)
    s['active'] = [x for x in s['active'] if x[0] != target]
    # Kernel default-priority slots compact after removal.
    negative = sorted([x for x in s['active'] if x[1] < 0], key=lambda x: -x[1])
    for i, x in enumerate(negative): x[1] = -2-i
elif cmd == 'swapon':
    if '-a' in args: raise SystemExit('global activation forbidden')
    target = args[-1]
    if any(x[0] == target for x in s['active']): sys.exit(1)
    pri = min([-1]+[x[1] for x in s['active'] if x[1] < 0])-1
    opts = ''
    for i, a in enumerate(args[:-1]):
        if a in ('--priority', '-p'):
            pri = int(args[i+1])
            if pri < 0: raise SystemExit('negative priority cannot be assigned')
        if a in ('--options', '-o'): opts = args[i+1]
    s['active'].append([target, pri, ','.join(x for x in opts.split(',') if x.startswith('discard'))])
(r/'state.json').write_text(json.dumps(s))
'''


class Transactions(unittest.TestCase):
    def setUp(self):
        cgroup = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                      if line.startswith('0::'))
        group = Path('/sys/fs/cgroup') / cgroup.lstrip('/')
        for ancestor in group.parents:
            if ancestor.name in ('hermes-tests.slice', 'hermes-vps-audit.slice'):
                limit = (ancestor / 'memory.max').read_text().strip()
                swap = (ancestor / 'memory.swap.max').read_text().strip()
                if limit != 'max' and int(limit) <= 4 * 1024**3 and swap == '0':
                    break
        else:
            self.fail('Run inside a shared test slice capped at 4 GiB with swap disabled')
        evidence = os.environ.get('TRANSACTION_EVIDENCE')
        if evidence:
            self.root = Path(evidence) / self.id().split('.')[-1]
            self.root.mkdir(parents=True, exist_ok=True)
        else:
            self.temp = tempfile.TemporaryDirectory(prefix='vps-transactions-')
            self.addCleanup(self.temp.cleanup)
            self.root = Path(self.temp.name)
        for d in ('etc/systemd/system', 'run/systemd/system', 'proc', 'tmp'):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root/'etc/fstab').write_text('# original\n')
        (self.root/'calls').write_text('')
        (self.root/'mock.py').write_text(MOCK)
        self.state = {'active': [], 'fstab': ''}

    def run_case(self, names, body):
        source = (REPO/'install.sh').read_text()
        funcs = dict(re.findall(r'^([a-z_][a-z_0-9]*)\(\) \{\n(.*?^\})', source, re.M|re.S))
        if 'configure_dns' in names:
            names = [n for n in funcs if n.startswith('dns_')] + names
        if {'configure_ssh', 'configure_fail2ban'}.intersection(names):
            names += [n for n in funcs if n.startswith('ssh_') or n == 'fail2ban_service_state']
        code = '\n'.join(n+'() {\n'+funcs[n] for n in names)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/(etc|run|usr|lib|proc)/', lambda m: str(self.root)+'/'+m[1]+'/', code)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/swapfile', str(self.root)+'/swapfile', code)
        (self.root/'state.json').write_text(json.dumps(self.state))
        fixture = self.root/'fixture.sh'
        fixture.write_text(reg.COMMON+f"\nexport ROOT='{self.root}'\nLOG_FILE='$ROOT/log'\n".replace("LOG_FILE='$ROOT/log'", 'LOG_FILE="$ROOT/log"')+code+'\n'+SWAP_MOCK+body)
        out = subprocess.run(['bash', str(fixture)], capture_output=True, text=True, timeout=20,
                             env={**os.environ, 'TMPDIR': str(self.root/'tmp')})
        (self.root/'stdout.log').write_text(out.stdout)
        (self.root/'stderr.log').write_text(out.stderr)
        (self.root/'status').write_text(str(out.returncode)+'\n')
        return out

    def test_swap_replacement_failures_restore_only_original_active_entries(self):
        for failure in ('activate', 'verify', 'fstab-rename'):
            with self.subTest(failure=failure):
                swap = self.root / 'swapfile'
                swap.write_text('old-swap')
                original = f'{swap} none swap sw,discard=once 0 0\n/dev/inactive none swap sw,noauto 0 0\n# preserve'
                (self.root / 'etc/fstab').write_text(original)
                self.state = {'active': [[str(swap), -2, 'discard=once'], ['/dev/priority', 10, 'discard=pages']],
                              'fstab': f'{swap} swap sw,discard=once\n/dev/priority swap sw,pri=10,discard=pages\n/dev/inactive swap sw,noauto\n'}
                out = self.run_case(reg.SWAP, f'FAILURE={failure}\n' + r'''
SWAP_SIZE_MB=512
mkswap() { printf 'new-swap' > "$1"; }
swapon() {
    if [[ "$1" != --show=* ]]; then
        python3 "$ROOT/mock.py" swapon "$@" || return 1
        if [[ $(< "$ROOT/swapfile") = new-swap ]]; then
            touch "$ROOT/new-activated"
            [[ "$FAILURE" != activate ]] || return 1
        fi
    elif [[ "$FAILURE" = verify && "$1" = --show=NAME && -e "$ROOT/new-activated" ]]; then
        rm -f "$ROOT/new-activated"
        printf '/dev/foreign\n'
    else python3 "$ROOT/mock.py" swapon "$@"; fi
}
mv() {
    if [[ "$FAILURE" = fstab-rename && "${@: -1}" = "$ROOT/etc/fstab" ]]; then return 1; fi
    command mv "$@"
}
if configure_swap; then exit 9; fi
''')
                self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
                self.assertIn('已恢复旧配置和活动 Swap', out.stdout)
                self.assertEqual(swap.read_text(), 'old-swap')
                self.assertEqual((self.root / 'etc/fstab').read_text(), original)
                self.assertEqual(sorted(json.loads((self.root / 'state.json').read_text())['active']), sorted(self.state['active']))
                self.assertFalse(list(self.root.glob('swapfile.backup.*')))
                (self.root / 'new-activated').unlink(missing_ok=True)

    def test_swap_rollback_preserves_priority_and_discard(self):
        self.state = {'active': [['/dev/low', 10, 'discard=pages'], ['/dev/auto-a', -2, 'discard=once'],
                                 ['/dev/auto-b', -3, ''], ['/dev/blocker', 100, 'discard']],
                      'fstab': '/dev/low swap sw,pri=10,discard=pages\n/dev/auto-a swap sw,discard=once\n/dev/auto-b swap sw\n/dev/blocker swap sw,pri=100,discard\n/dev/inactive swap sw,discard\n',
                      'fail_off': '/dev/blocker'}
        before = sorted(self.state['active'])
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
trap ':' TERM
swapoff() {
    if [[ "$1" = /dev/blocker ]]; then kill -TERM "$BASHPID"; fi
    python3 "$ROOT/mock.py" swapoff "$@"
}
configure_swap
''')
        self.assertIn(out.returncode, (1, 143), out.stdout+out.stderr)
        after = json.loads((self.root/'state.json').read_text())['active']
        self.assertEqual(sorted(after), before, out.stdout+out.stderr)
        self.assertEqual((self.root/'etc/fstab').read_text(), '# original\n')

    def swap_signal_case(self, signal):
        swap = self.root/'swapfile'
        swap.write_text('old-swap')
        self.state = {'active': [[str(swap), -2, 'discard=once']],
                      'fstab': f'{swap} swap sw,discard=once\n'}
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
trap 'printf old-int >> "$ROOT/original-handler"' INT
trap 'printf old-term >> "$ROOT/original-handler"' TERM
trap -p INT TERM > "$ROOT/traps-before"
mv() {
    command mv "$@" || return
    if [[ "$1" = "$ROOT/swapfile" && ! -e "$ROOT/signalled" ]]; then
        touch "$ROOT/signalled"
        kill -SIGNAL "$BASHPID"
    fi
}
set +e
configure_swap
rc=$?
trap -p INT TERM > "$ROOT/traps-after"
exit "$rc"
'''.replace('SIGNAL', signal))
        self.assertEqual(out.returncode, 130 if signal == 'INT' else 143, out.stdout+out.stderr)
        self.assertTrue((self.root/'signalled').exists())
        self.assertEqual(swap.read_text(), 'old-swap')
        self.assertEqual(json.loads((self.root/'state.json').read_text())['active'], self.state['active'])
        self.assertEqual((self.root/'traps-before').read_text(), (self.root/'traps-after').read_text())
        self.assertFalse((self.root/'original-handler').exists())

    def test_swap_term_after_old_rename(self):
        self.swap_signal_case('TERM')

    def test_swap_int_after_old_rename(self):
        self.swap_signal_case('INT')

    def swapoff_error_with_failed_queries(self, failures):
        self.state['active'] = [['/dev/old', -2, '']]
        out = self.run_case(reg.SWAP, f'FAILURES={failures}\n' + r'''
SWAP_SIZE_MB=0
swapoff() {
    python3 "$ROOT/mock.py" swapoff "$@" || return 1
    printf '%s\n' "$FAILURES" > "$ROOT/failed-queries-left"
    return 1
}
swapon() {
    if [[ "$1" = --show=* && -s "$ROOT/failed-queries-left" ]]; then
        local left
        read -r left < "$ROOT/failed-queries-left"
        if (( left > 0 )); then
            printf '%s\n' "$((left - 1))" > "$ROOT/failed-queries-left"
            return 1
        fi
    fi
    python3 "$ROOT/mock.py" swapon "$@"
}
configure_swap
''')
        self.assertEqual(out.returncode, 1, out.stdout+out.stderr)
        return out

    def test_swap_rollback_reconciles_completed_swapoff_after_two_failed_queries(self):
        out = self.swapoff_error_with_failed_queries(2)
        self.assertEqual((self.root/'failed-queries-left').read_text(), '0\n')
        self.assertEqual(json.loads((self.root/'state.json').read_text())['active'], self.state['active'])
        self.assertIn('已恢复旧配置和活动 Swap', out.stdout)
        self.assertFalse(list(self.root.glob('swapfile.backup.*')))

    def test_swap_rollback_retains_backup_when_runtime_query_retries_exhausted(self):
        out = self.swapoff_error_with_failed_queries(4)
        self.assertEqual((self.root/'failed-queries-left').read_text(), '1\n')
        self.assertNotIn('swapon /dev/old', (self.root/'calls').read_text())
        self.assertIn('Swap 恢复不完整', out.stdout)
        self.assertEqual([p.read_text() for p in self.root.glob('swapfile.backup.*/fstab')], ['# original\n'])

    def test_swap_rollback_reconciles_completed_swapoff_when_first_query_fails(self):
        self.state['active'] = [['/dev/old', -2, '']]
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
swapoff() {
    python3 "$ROOT/mock.py" swapoff "$@" || return 1
    touch "$ROOT/fail-next-query"
    return 1
}
swapon() {
    if [[ -e "$ROOT/fail-next-query" && "$1" == --show=* ]]; then
        rm "$ROOT/fail-next-query"
        return 1
    fi
    python3 "$ROOT/mock.py" swapon "$@"
}
configure_swap
''')
        self.assertEqual(out.returncode, 1, out.stdout+out.stderr)
        self.assertEqual(json.loads((self.root/'state.json').read_text())['active'], self.state['active'])
        self.assertIn('已恢复旧配置和活动 Swap', out.stdout)

    def test_swap_rollback_passes_decoded_path_to_mutators(self):
        self.state = {'active': [[r'/dev/old\x20swap\x5cfile', -2, 'discard=pages'], ['/dev/blocker', 5, '']],
                      'fstab': r'/dev/old\x20swap\x5cfile swap sw,discard=pages' + '\n'}
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
EXPECTED_RAW='/dev/old\x20swap\x5cfile'
EXPECTED_PATH='/dev/old swap\file'
swapoff() {
    [[ "$1" = "$EXPECTED_PATH" ]] || return 1
    touch "$ROOT/stopped"
    python3 "$ROOT/mock.py" swapoff "$EXPECTED_RAW"
}
swapon() {
    if [[ "$1" = --show=* ]]; then python3 "$ROOT/mock.py" swapon "$@"; return; fi
    [[ "$#" = 3 && "$1" = --options && "$2" = discard=pages && "$3" = "$EXPECTED_PATH" ]] || return 1
    touch "$ROOT/restored"
    python3 "$ROOT/mock.py" swapon --options discard=pages "$EXPECTED_RAW"
}
configure_swap
''')
        self.assertEqual(out.returncode, 1, out.stdout+out.stderr)
        self.assertTrue((self.root/'stopped').exists(), out.stdout+out.stderr)
        self.assertTrue((self.root/'restored').exists(), out.stdout+out.stderr)
        self.assertIn('已恢复旧配置和活动 Swap', out.stdout)

    def test_swap_fstab_keeps_symlink_and_restores_target_after_signal(self):
        fstab = self.root / 'etc/fstab'
        boot = fstab.with_name('boot')
        original = b'/dev/mock none swap sw 0 0\n# keep'
        fstab.unlink()
        boot.write_bytes(original)
        boot.chmod(0o640)
        fstab.symlink_to('boot')
        self.state['active'] = [['/dev/mock', -2, '']]
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
mv() {
    command mv "$@" || return 1
    if [[ "${@: -1}" = "$ROOT/etc/boot" && ! -e "$ROOT/signalled" ]]; then
        touch "$ROOT/signalled"
        kill -TERM "$BASHPID"
        return 143
    fi
}
configure_swap
''')
        self.assertEqual(out.returncode, 143, out.stdout+out.stderr)
        self.assertTrue((self.root/'signalled').exists())
        self.assertTrue(fstab.is_symlink())
        self.assertEqual(boot.read_bytes(), original)
        self.assertEqual(boot.stat().st_mode & 0o777, 0o640)
        self.assertEqual(json.loads((self.root/'state.json').read_text())['active'], self.state['active'])

    def test_swap_preserves_concurrent_fstab_edit(self):
        self.state['active'] = [['/dev/mock', -2, '']]
        out = self.run_case(reg.SWAP, r'''
SWAP_SIZE_MB=0
swapoff() {
    python3 "$ROOT/mock.py" swapoff "$@" || return 1
    printf '# external edit\n' >> "$ROOT/etc/fstab"
}
configure_swap
''')
        self.assertEqual(out.returncode, 1, out.stdout+out.stderr)
        self.assertIn('fstab 已被其他操作修改', out.stdout)
        self.assertEqual((self.root/'etc/fstab').read_text(), '# original\n# external edit\n')
        self.assertEqual(json.loads((self.root/'state.json').read_text())['active'], self.state['active'])

    def test_ssh_term_after_dropin_rename_restores_without_restart(self):
        dropin = self.root/'etc/ssh/sshd_config.d/99-vps-setup.conf'
        dropin.parent.mkdir(parents=True)
        dropin.write_text('Port 22\n# old\n')
        (dropin.parent.parent/'sshd_config').touch()
        out = self.run_case(['valid_ssh_port', 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { touch "$ROOT/checked"; return 1; }
ss() { :; }
systemctl() { printf '%s\n' "$*" >> "$ROOT/calls"; return 1; }
mv() {
    command mv "$@" || return 1
    if [[ "${@: -1}" = "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf" ]]; then
        kill -TERM "$BASHPID"
        return 143
    fi
}
configure_ssh
''')
        self.assertEqual(dropin.read_text(), 'Port 22\n# old\n')
        self.assertEqual(out.returncode, 143, out.stdout+out.stderr)
        self.assertFalse((self.root/'checked').exists())
        self.assertNotIn('restart', (self.root/'calls').read_text())

    def test_fail2ban_int_after_package_started_service(self):
        out = self.run_case(['valid_ssh_port', 'configure_fail2ban'], r'''
ssh_listening_ports() { printf '22\n'; }
apt-get() {
    touch "$ROOT/installed" "$ROOT/running" "$ROOT/enabled"
    kill -INT "$BASHPID"
    return 130
}
systemctl() {
    case "$1" in
        show)
            if [[ ! -e "$ROOT/installed" ]]; then printf 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\n'; return; fi
            local state=inactive boot=disabled
            [[ ! -e "$ROOT/running" ]] || state=active
            [[ ! -e "$ROOT/enabled" ]] || boot=enabled
            printf 'LoadState=loaded\nActiveState=%s\nUnitFileState=%s\n' "$state" "$boot";;
        stop) rm -f "$ROOT/running";;
        disable) rm -f "$ROOT/enabled";;
        *) return 99;;
    esac
}
fail2ban-client() { touch "$ROOT/checked"; return 1; }
configure_fail2ban
''')
        self.assertTrue((self.root/'installed').exists())
        self.assertFalse((self.root/'running').exists())
        self.assertFalse((self.root/'enabled').exists())
        self.assertFalse((self.root/'checked').exists())
        self.assertEqual(out.returncode, 130, out.stdout+out.stderr)

    def test_bbr_signals_recover_completed_mutations_and_restore_traps(self):
        names = ['bbr_filter', 'configure_bbr']
        for signal in ('INT', 'TERM'):
            for phase in ('rename', 'runtime'):
                for command_fails in (False, True):
                    with self.subTest(signal=signal, phase=phase, command_fails=command_fails):
                        (self.root / 'signalled').unlink(missing_ok=True)
                        (self.root / 'original-handler').unlink(missing_ok=True)
                        caller = ('set +e\nconfigure_bbr\nrc=$?' if command_fails else
                                  'if configure_bbr; then rc=0; else rc=$?; fi')
                        out = self.run_case(names, f'SIGNAL={signal} PHASE={phase} COMMAND_FAILS={str(command_fails).lower()}\n' + r'''
ENABLE_BBR=true
mkdir -p "$ROOT/etc/sysctl.d"
printf 'net.ipv4.tcp_congestion_control=reno\n# keep' > "$ROOT/etc/sysctl.conf"
printf 'net.core.default_qdisc=fq_codel\n' > "$ROOT/etc/sysctl.d/99-bbr.conf"
cp -p "$ROOT/etc/sysctl.conf" "$ROOT/original"
cp -p "$ROOT/etc/sysctl.d/99-bbr.conf" "$ROOT/original-owned"
printf 'reno\n' > "$ROOT/cc"
printf 'pfifo_fast\n' > "$ROOT/qdisc"
is_kernel_version_ge() { return 0; }
signal_once() {
    if [[ ! -e "$ROOT/signalled" ]]; then
        touch "$ROOT/signalled"
        kill -s "$SIGNAL" "$BASHPID"
        [[ "$COMMAND_FAILS" != true ]] || return 1
    fi
}
sysctl() {
    local key value
    printf 'sysctl %s\n' "$*" >> "$ROOT/calls"
    case "$1" in
        -n) case "$2" in
            net.ipv4.tcp_congestion_control) cat "$ROOT/cc";;
            net.core.default_qdisc) cat "$ROOT/qdisc";;
            *) return 99;;
        esac;;
        -p) while IFS='=' read -r key value; do
            key=${key// /}; value=${value// /}
            case "$key" in
                net.ipv4.tcp_congestion_control) printf '%s\n' "$value" > "$ROOT/cc";;
                net.core.default_qdisc) printf '%s\n' "$value" > "$ROOT/qdisc";;
                *) return 99;;
            esac
        done < "$2"
        [[ "$PHASE" != runtime ]] || signal_once;;
        -w) case "$2" in
            net.ipv4.tcp_congestion_control=*) printf '%s\n' "${2#*=}" > "$ROOT/cc";;
            net.core.default_qdisc=*) printf '%s\n' "${2#*=}" > "$ROOT/qdisc";;
            *) return 99;;
        esac;;
        *) return 99;;
    esac
}
mv() {
    command mv "$@" || return 1
    [[ "$PHASE" != rename ]] || signal_once
}
trap 'printf old-int >> "$ROOT/original-handler"' INT
trap 'printf old-term >> "$ROOT/original-handler"' TERM
trap -p INT TERM > "$ROOT/traps-before"
CALLER
set -e
trap -p INT TERM > "$ROOT/traps-after"
cmp "$ROOT/original" "$ROOT/etc/sysctl.conf"
cmp "$ROOT/original-owned" "$ROOT/etc/sysctl.d/99-bbr.conf"
[[ $(< "$ROOT/cc") = reno && $(< "$ROOT/qdisc") = pfifo_fast ]]
[[ ! -e "$ROOT/original-handler" ]]
exit "$rc"
'''.replace('CALLER', caller))
                        self.assertEqual(out.returncode, 130 if signal == 'INT' else 143, out.stdout + out.stderr)
                        self.assertTrue((self.root / 'signalled').exists())
                        self.assertEqual((self.root / 'traps-before').read_text(), (self.root / 'traps-after').read_text())
                        self.assertNotIn('OK 拥塞控制已生效', out.stdout)
                        (self.root / 'signalled').unlink()

    def dns_signal_case(self, signal):
        resolv = self.root/'etc/resolv.conf'
        original = 'nameserver 10.0.0.53\nsearch private.internal\n'
        resolv.write_text(original)
        (self.root/'dns-immutable').touch()
        out = self.run_case(['configure_dns'], r'''
PRIMARY_DNS_V4=1.1.1.1 SECONDARY_DNS_V4=8.8.8.8
PRIMARY_DNS_V6=2606:4700:4700::1111 SECONDARY_DNS_V6=2001:4860:4860::8888
has_ipv6() { return 1; }
trap 'printf old-int >> "$ROOT/original-handler"' INT
trap 'printf old-term >> "$ROOT/original-handler"' TERM
trap -p INT TERM > "$ROOT/traps-before"
mv() {
    command mv "$@" || return
    if [[ "${@: -1}" = "$ROOT/etc/resolv.conf" && ! -e "$ROOT/signalled" ]]; then
        touch "$ROOT/signalled"
        kill -SIGNAL "$BASHPID"
    fi
}
set +e
configure_dns
rc=$?
trap -p INT TERM > "$ROOT/traps-after"
exit "$rc"
'''.replace('SIGNAL', signal))
        self.assertEqual(out.returncode, 130 if signal == 'INT' else 143, out.stdout+out.stderr)
        self.assertTrue((self.root/'signalled').exists())
        self.assertEqual(resolv.read_text(), original)
        self.assertTrue((self.root/'dns-immutable').exists())
        self.assertFalse((self.root/'etc/systemd/system/systemd-resolved.service').exists())
        self.assertEqual((self.root/'traps-before').read_text(), (self.root/'traps-after').read_text())
        self.assertFalse((self.root/'original-handler').exists())

    def test_dns_term_after_install_rename(self):
        self.dns_signal_case('TERM')

    def test_dns_int_after_install_rename(self):
        self.dns_signal_case('INT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
