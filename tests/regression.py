#!/usr/bin/env python3
"""Extract real functions into regular fixture scripts; never run the initializer.
Requires openssh-server and fail2ban parsers for the SSH/Fail2ban tests.
All service, package, kernel and Swap mutators are mocked.
"""
import ast
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'install.sh').read_text()
FUNCTIONS = dict(re.findall(r'^([a-z_][a-z_0-9]*)\(\) \{\n(.*?^\})', SOURCE, re.M | re.S))
COMMON = r'''set -Eeuo pipefail
GREEN='' RED='' YELLOW='' BOLD='' NC=''
section_header() { :; }
step_info() { printf '%s\n' "$*"; }
result_ok() { printf 'OK %s\n' "$*"; }
result_warn() { printf 'WARN %s\n' "$*"; }
print_summary_row() { printf '%s:%s\n' "$@"; }
log() { printf '%s\n' "$*"; }
APT_LOCK_WAIT=()
apt-get() { printf 'apt %s\n' "$*" >> "$ROOT/calls"; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$ROOT/calls"; return 1; }
swapon() { [[ "$*" = --show=* ]] && return 0; printf 'swapon %s\n' "$*" >> "$ROOT/calls"; }
swapoff() { printf 'swapoff %s\n' "$*" >> "$ROOT/calls"; }
fallocate() { :; }
dd() { :; }
mkswap() { :; }
check_disk_space() { :; }
blkid() { return 2; }
sysctl() { return 99; }
modprobe() { return 99; }
chpasswd() { return 99; }
sleep() { :; }
'''
SWAP = ['ensure_swap_fstab_entry', 'remove_fstab_swap_entries', 'configure_swap']

class Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vps-regression-')
        self.root = Path(self.temp.name)
        for d in ['etc/ssh/sshd_config.d', 'etc/systemd/resolved.conf.d', 'etc/sysctl.d', 'proc', 'run', 'tmp']:
            (self.root / d).mkdir(parents=True)
        (self.root / 'etc/fstab').write_text('# preserve\n')
        (self.root / 'calls').touch()

    def tearDown(self):
        self.temp.cleanup()

    def run_shell(self, names, body):
        code = '\n'.join(n + '() {\n' + FUNCTIONS[n] for n in names)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/(etc|run|usr|lib|proc)/', lambda m: str(self.root) + '/' + m[1] + '/', code)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/swapfile', str(self.root) + '/swapfile', code)
        code = code.replace('/.dockerenv', str(self.root / '.dockerenv'))
        fixture = self.root / 'fixture.sh'
        fixture.write_text(COMMON + f"ROOT='{self.root}'\nLOG_FILE='{self.root}/log'\n" + code + '\n' + body)
        out = subprocess.run(['bash', str(fixture)], capture_output=True, text=True,
                             env={**os.environ, 'TMPDIR': str(self.root / 'tmp')})
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr + ((self.root / 'log').read_text() if (self.root / 'log').exists() else ''))
        return out.stdout

    def setup_fail2ban(self):
        dst = self.root / 'etc/fail2ban'
        shutil.copytree('/etc/fail2ban', dst)
        shutil.rmtree(dst / 'jail.d'); (dst / 'jail.d').mkdir()
        (dst / 'jail.local').unlink(missing_ok=True)
        (self.root / 'nginx.log').touch()
        (dst / 'jail.d/10-existing.local').write_text(
            '[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 192.0.2.10\n'
            '[nginx-http-auth]\nenabled = true\n'
            f'logpath = {self.root}/nginx.log\n')
        return r'''
sshd() { printf 'port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:2222\n'; }
systemctl() { printf 'systemctl %s\n' "$*" >> "$ROOT/calls"; return 0; }
fail2ban-client() {
    case "$1" in
        -t|-d) /usr/bin/fail2ban-client -c "$ROOT/etc/fail2ban" "$@" ;;
        *) python3 'RUNTIME' "$ROOT/etc/fail2ban" "$@" ;;
    esac
}
'''.replace('RUNTIME', str(REPO / 'tests/fail2ban-runtime.py'))

    def dump_fail2ban(self):
        out = subprocess.check_output(['/usr/bin/fail2ban-client', '-c', str(self.root / 'etc/fail2ban'), '-d'], text=True)
        return [ast.literal_eval(line) for line in out.splitlines()]

    def test_fail2ban_other_jail_unchanged(self):
        body = self.setup_fail2ban()
        before = [x for x in self.dump_fail2ban() if len(x) > 1 and x[1] == 'nginx-http-auth']
        self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nconfigure_fail2ban\n')
        after = self.dump_fail2ban()
        self.assertEqual(before, [x for x in after if len(x) > 1 and x[1] == 'nginx-http-auth'])
        self.assertIn(['set', 'sshd', 'addignoreip', '127.0.0.1/8', '::1', '192.0.2.10'], after)

    def test_fail2ban_override_rolls_back(self):
        body = self.setup_fail2ban()
        owned = self.root / 'etc/fail2ban/jail.d/99-vps-setup.local'
        original = '# administrator content\n'
        for setting in ['enabled = false', 'maxretry = 9', 'findtime = 900', 'bantime = 600', 'port = 1234', 'backend = polling\nlogpath = ' + str(self.root / 'nginx.log')]:
            with self.subTest(setting=setting):
                owned.write_text(original)
                (self.root / 'etc/fail2ban/jail.d/zz-existing.local').write_text('[sshd]\n' + setting + '\n')
                output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nif configure_fail2ban; then exit 9; fi\n')
                self.assertEqual(owned.read_text(), original)
                self.assertNotIn('OK Fail2ban', output)

    def test_fail2ban_readiness_timeout_is_bounded(self):
        body = self.setup_fail2ban()
        body = body.replace('*) python3', '''status) printf 'status\\n' >> "$ROOT/status-calls"; return 1 ;;
        *) python3''')
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nif configure_fail2ban; then exit 9; fi\n')
        self.assertEqual((self.root / 'status-calls').read_text().splitlines(), ['status'] * 5)
        self.assertFalse((self.root / 'etc/fail2ban/jail.d/99-vps-setup.local').exists())
        self.assertNotIn('OK Fail2ban', output)

    def test_fail2ban_notification_only_is_not_protection(self):
        body = self.setup_fail2ban()
        (self.root / 'etc/fail2ban/jail.d/20-actions.local').write_text(
            '[sshd]\naction = sendmail-whois-lines\n')
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nif configure_fail2ban; then exit 9; fi\n')
        self.assertNotIn('OK Fail2ban', output)
        self.assertFalse((self.root / 'etc/fail2ban/jail.d/99-vps-setup.local').exists())

    def test_fail2ban_waits_for_jail_readiness(self):
        body = self.setup_fail2ban()
        body = body.replace('*) python3', '''status) if [[ ! -e "$ROOT/ready" ]]; then touch "$ROOT/ready"; return 1; fi
            python3 'RUNTIME' "$ROOT/etc/fail2ban" "$@" ;;
        *) python3'''.replace('RUNTIME', str(REPO / 'tests/fail2ban-runtime.py')))
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nconfigure_fail2ban\n')
        self.assertIn('OK Fail2ban', output)

    def test_fail2ban_notification_action_allowed(self):
        body = self.setup_fail2ban()
        (self.root / 'etc/fail2ban/jail.d/20-actions.local').write_text(
            '[sshd]\naction = %(action_mwl)s\n')
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nconfigure_fail2ban\n')
        self.assertIn('OK Fail2ban', output)

    def test_fail2ban_multiple_actions(self):
        body = self.setup_fail2ban()
        (self.root / 'etc/fail2ban/jail.d/20-actions.local').write_text(
            '[sshd]\naction = iptables-multiport[name=one, actname=one, port="%(port)s"]\n'
            '         iptables-multiport[name=two, actname=two, port="%(port)s"]\n')
        self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + '\nconfigure_fail2ban\n')

    def test_fail2ban_uses_listenaddress_ports(self):
        body = self.setup_fail2ban()
        config = self.root / 'etc/ssh/sshd_config'
        config.write_text('Port 2222\nListenAddress 0.0.0.0:22\nListenAddress [::]:2200\n')
        self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + r'''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
configure_fail2ban
''')
        self.assertIn('port = 22,2200\n', (self.root / 'etc/fail2ban/jail.d/99-vps-setup.local').read_text())

    def test_ssh_effective_bindings(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        for binding, accepted in [
            ('ListenAddress 0.0.0.0:22\nListenAddress 127.0.0.1', False),
            ('ListenAddress [::]:22\nListenAddress ::1', False),
            ('ListenAddress 127.0.0.1', False), ('ListenAddress ::1', False),
            ('ListenAddress ::ffff:127.0.0.1', False),
            ('ListenAddress 0.0.0.0', True), ('ListenAddress ::', True),
            ('ListenAddress 192.0.2.5', True), ('ListenAddress 2001:db8::5', True)]:
            with self.subTest(binding=binding):
                config.write_text(f'Include {dropin.parent}/*.conf\nPasswordAuthentication no\n{binding}\n')
                dropin.unlink(missing_ok=True)
                self.run_shell(['valid_ssh_port', *[n for n in FUNCTIONS if n.startswith('ssh_')], 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
systemctl() { return 0; }
ss() { if [[ -f "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf" ]]; then
    sshd -T | awk '$1 == "listenaddress" {print "LISTEN 0 128 " $2 " *:*"}'
fi; }
''' + ('configure_ssh\n' if accepted else 'if configure_ssh; then exit 9; fi\n'))
                self.assertEqual(dropin.exists(), accepted)
                out = subprocess.check_output(['/usr/sbin/sshd', '-T', '-f', str(config)], text=True)
                self.assertIn('passwordauthentication no', out)

    def test_dns_respects_managers(self):
        for manager, header in [('NetworkManager', ''), ('connman', ''), ('resolvconf', ''),
                                ('none', '# Generated by NetworkManager\n'), ('none', '# Generated by dhcpcd\n')]:
            with self.subTest(manager=manager, header=header):
                original = header + 'search private.internal\noptions ndots:2\nnameserver 10.0.0.53\n'
                (self.root / 'etc/resolv.conf').write_text(original)
                output = self.run_shell(['configure_dns'], self.dns_defaults() + f'''
systemctl() {{ [[ "$*" = 'is-active --quiet {manager}' ]]; }}
configure_dns
''')
                self.assertEqual((self.root / 'etc/resolv.conf').read_text(), original)
                self.assertNotIn('OK DNS', output)

    def test_dns_direct_preserves_options(self):
        path = self.root / 'etc/resolv.conf'
        path.write_bytes(b'# local\nsearch private.internal\nnameserver 10.0.0.53\noptions ndots:2')
        self.run_shell(['configure_dns'], self.dns_defaults() + '\nconfigure_dns\n')
        self.assertEqual(path.read_bytes(), b'nameserver 1.1.1.1\nnameserver 8.8.8.8\n# local\nsearch private.internal\noptions ndots:2')
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def dns_defaults(self):
        return '''PRIMARY_DNS_V4=1.1.1.1 SECONDARY_DNS_V4=8.8.8.8
PRIMARY_DNS_V6=2606:4700:4700::1111 SECONDARY_DNS_V6=2001:4860:4860::8888
has_ipv6() { return 1; }
'''

    def test_swap_auto_tiers(self):
        for mem, target in [(256, 512), (512, 512), (513, 1024), (1024, 1024), (1025, 2048), (4096, 2048), (16384, 2048)]:
            with self.subTest(mem=mem):
                (self.root / 'proc/meminfo').write_text(f'MemTotal: {mem * 1024} kB\n')
                output = self.run_shell(SWAP, f'''SWAP_SIZE_MB=auto
swapon() {{ case "$*" in --show=NAME,SIZE*) printf '/dev/mock {target * 1048576}\\n';; --show=NAME*) printf '/dev/mock\\n';; *) return 99;; esac; }}
swapoff() {{ return 99; }}
configure_swap
''')
                self.assertIn(f'现有 Swap 与目标一致（{target}MB）', output)

    def test_swap_equal_capacity_fstab(self):
        swap = self.root / 'swapfile'
        swap.write_text('mock-swap')
        fstab = self.root / 'etc/fstab'
        for content, accepted in [('# no newline', True), ('# newline\n', True),
                                  (f'{swap} none swap sw 0 0\n', True),
                                  (f'{swap} /mnt ext4 defaults 0 0\n', False),
                                  (f'{swap} none swap sw,noauto 0 0\n', False),
                                  (f'{swap} none swap sw 0 0\n{swap} none swap sw 0 0\n', False)]:
            with self.subTest(content=content):
                fstab.write_text(content)
                self.run_shell(SWAP, r'''SWAP_SIZE_MB=512
blkid() { printf 'swap\n'; }
swapon() { case "$*" in --show=NAME,SIZE*) printf '%s 536870912\n' "$ROOT/swapfile";; --show=NAME*) printf '%s\n' "$ROOT/swapfile";; *) return 99;; esac; }
swapoff() { return 99; }
''' + ('configure_swap\n' if accepted else 'if configure_swap; then exit 9; fi\n'))
                if not accepted:
                    self.assertEqual(fstab.read_text(), content)
                else:
                    lines = [line.split() for line in fstab.read_text().splitlines() if line and not line.startswith('#')]
                    self.assertEqual(lines, [[str(swap), 'none', 'swap', 'sw', '0', '0']])
                self.assertEqual(swap.read_text(), 'mock-swap')

    def test_container_detector_status_and_fallback(self):
        for kind, rc, detected in [('docker', 0, True), ('systemd-nspawn', 0, True), ('lxc-libvirt', 0, True), ('future-container', 0, True), ('none', 1, False)]:
            with self.subTest(kind=kind):
                self.run_shell(['is_container'], f'''systemd-detect-virt() {{ printf '{kind}\\n'; return {rc}; }}
''' + ('is_container\n' if detected else 'if is_container; then exit 9; fi\n'))
        (self.root / 'run/.containerenv').touch()
        self.run_shell(['is_container'], 'systemd-detect-virt() { return 127; }; is_container\n')

    def test_time_sync_preserves_existing_provider(self):
        for provider in ['chrony', 'ntp', 'ntpsec', 'openntpd', 'custom-provider']:
            with self.subTest(provider=provider):
                (self.root / 'calls').write_text('')
                output = self.run_shell(['configure_time_sync'], f'''
systemctl() {{ printf '%s\\n' "$*" >> "$ROOT/calls"; [[ "$*" = 'is-active --quiet {provider}' ]]; }}
timedatectl() {{ [[ "$1" = status ]] && printf 'NTP service: active\\n'; }}
configure_time_sync
''')
                self.assertNotIn('systemd-timesyncd', output)
                calls = (self.root / 'calls').read_text()
                self.assertNotIn('apt ', calls)
                self.assertNotIn('unmask', calls)
                self.assertNotIn('enable', calls)

    def test_time_sync_does_not_invent_provider(self):
        output = self.run_shell(['configure_time_sync'], r'''
systemctl() { [[ "$1" = cat || "$1" = unmask ]]; }
timedatectl() {
    if [[ "$1" = set-ntp ]]; then touch "$ROOT/ntp-started";
    elif [[ -f "$ROOT/ntp-started" ]]; then printf 'NTP service: active\n'; fi
}
configure_time_sync
''')
        self.assertNotIn('(systemd-timesyncd)', output)
        self.assertIn('OK 时间同步', output)

    def test_bbr_first_separator_and_bytes(self):
        matching = [b'net.ipv4.tcp_congestion_control=reno\r\n', b' -net/ipv4/tcp_congestion_control = reno\n']
        # Slash first leaves dots literal; dot first swaps dots and slashes.
        unrelated = b'net/ipv4.tcp_congestion_control=keep\nnet.ipv4/tcp_congestion_control=keep\nnet.ipv4.*=keep\n# end\t\\literal'
        (self.root / 'input').write_bytes(b''.join(matching) + unrelated)
        self.run_shell(['bbr_filter'], 'bbr_filter net.ipv4.tcp_congestion_control "$ROOT/input" > "$ROOT/out"\nbbr_filter net.ipv4.tcp_congestion_control "$ROOT/input" replace > "$ROOT/replaced"\n')
        self.assertEqual((self.root / 'out').read_bytes(), b''.join(b'# vps-setup: ' + line for line in matching) + unrelated)
        self.assertEqual((self.root / 'replaced').read_bytes(), unrelated)

    def test_readme_scope_and_defaults(self):
        readme = (REPO / 'README.md').read_text()
        for required in ['≤512 MiB', '≤1024 MiB', '2048 MiB', '局部回滚', '不是整轮初始化事务', 'search/options', 'ignoreip', '密码登录开关']:
            self.assertIn(required, readme)
        self.assertIn('v26.09.27', readme)
        self.assertNotIn('其余为 4 GiB', readme)

    def test_swap_probe_failure_is_not_identity(self):
        (self.root / 'swapfile').write_text('precious')
        self.run_shell(SWAP, r'''SWAP_SIZE_MB=0
blkid() { printf 'swap\n'; return 2; }
if configure_swap; then exit 9; fi
''')
        self.assertEqual((self.root / 'swapfile').read_text(), 'precious')

    def test_existing_rollback_and_parser_paths(self):
        self.run_shell(SWAP, r'''SWAP_SIZE_MB=0
printf '/dev/mock1 none swap sw 0 0\n/dev/mock2 none swap sw 0 0\n' > "$ROOT/etc/fstab"
cp "$ROOT/etc/fstab" "$ROOT/original"
swapon() { case "$*" in --show=NAME\ --*) printf '/dev/mock1\n/dev/mock2\n';; --show=NAME,SIZE*) printf '/dev/mock1 1048576\n/dev/mock2 1048576\n';; *) printf 'swapon %s\n' "$*" >> "$ROOT/calls";; esac; }
swapoff() { [[ "$1" != /dev/mock2 ]]; }
if configure_swap; then exit 9; fi
cmp "$ROOT/original" "$ROOT/etc/fstab"
grep -Fxq 'swapon /dev/mock1' "$ROOT/calls"
''')
        parsers = ['require_value', 'usage', 'valid_ipv4', 'valid_ipv6', 'valid_ssh_port', 'parse_args']
        for args in ['--unknown', '--swap', '--ssh-port 022', "--ip-dns '1.1.1.1 999.1.1.1'", "--ip6-dns ':1:2:3:4:5:6:7:8 2001::1'"]:
            with self.subTest(args=args):
                self.run_shell(parsers, f'if (parse_args {args}) >/dev/null 2>&1; then exit 9; else [[ $? = 2 ]]; fi\n')

    def test_dns_resolved_verification_and_rollback(self):
        path = self.root / 'etc/systemd/resolved.conf.d/99-custom-dns.conf'
        prefix = self.dns_defaults() + '\nhas_ipv6() { return 0; }\nsystemctl() { return 0; }\n'
        output = self.run_shell(['configure_dns'], prefix + r'''
resolvectl() { printf 'Global: 8.8.8.8 1.1.1.1\n        2606:4700:4700:0000:0000:0000:0000:1111 2001:4860:4860:0:0:0:0:8888\nLink 2 (eth0): 9.9.9.9\n'; }
configure_dns
''')
        self.assertIn('2606:4700:4700::1111 / 2001:4860:4860::8888', output)
        path.write_text('original\n')
        self.run_shell(['configure_dns'], prefix + r'''
resolvectl() { printf 'Global: 9.9.9.9\nLink 2 (eth0): 1.1.1.1 8.8.8.8\n'; }
if configure_dns; then exit 9; fi
''')
        self.assertEqual(path.read_text(), 'original\n')

    def test_ssh_runtime_listener_rollback(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        for endpoint in ['', '127.0.0.1:2222', '[::1]:2222', '0.0.0.0:22220']:
            with self.subTest(endpoint=endpoint):
                dropin.write_text('Port 22\n# old\n')
                self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
systemctl() { return 0; }
''' + f'''ss() {{ if [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = 'Port 2222' ]]; then printf 'LISTEN 0 128 {endpoint} *:*\\n'; fi; }}
if configure_ssh; then exit 9; fi
''')
                self.assertEqual(dropin.read_text(), 'Port 22\n# old\n')

    def test_swap_recognized_disable_and_replace(self):
        for size in [0, 512]:
            with self.subTest(size=size):
                (self.root / 'swapfile').write_text('old-swap')
                (self.root / 'etc/fstab').write_text('# keep\n')
                self.run_shell(SWAP, f'SWAP_SIZE_MB={size}\n' + r'''
blkid() { printf 'swap\n'; }
swapon() {
    case "$*" in
        --show=NAME,SIZE*) :;;
        --show=NAME*) [[ ! -f "$ROOT/active" ]] || printf '%s\n' "$ROOT/swapfile";;
        *) touch "$ROOT/active";;
    esac
}
swapoff() { rm -f "$ROOT/active"; }
mkswap() { printf 'new-swap' > "$1"; }
configure_swap
''')
                self.assertEqual((self.root / 'swapfile').exists(), size != 0)
                if size: self.assertEqual((self.root / 'swapfile').read_text(), 'new-swap')

    def test_swap_collision_rejected(self):
        for kind in ['file', 'directory', 'symlink']:
            for size in [0, 1024]:
                with self.subTest(kind=kind, size=size):
                    path = self.root / 'swapfile'
                    if path.is_symlink() or path.is_file(): path.unlink()
                    elif path.exists(): shutil.rmtree(path)
                    if kind == 'directory': path.mkdir(); (path / 'precious').write_text('keep')
                    elif kind == 'symlink': path.symlink_to('absent')
                    else: path.write_text('valuable-not-swap')
                    self.run_shell(SWAP, f'SWAP_SIZE_MB={size}\nif configure_swap; then exit 9; fi\n')
                    self.assertTrue(path.exists() or path.is_symlink())
                    self.assertEqual((self.root / 'etc/fstab').read_text(), '# preserve\n')
                    self.assertEqual((self.root / 'calls').read_text(), '')
                    if kind == 'file': self.assertEqual(path.read_text(), 'valuable-not-swap')

if __name__ == '__main__':
    unittest.main(verbosity=2)
