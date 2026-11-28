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
resolved_load() {
    if [[ "$(readlink "$ROOT/etc/systemd/system/systemd-resolved.service")" = /dev/null ]]; then
        printf masked
    else
        printf loaded
    fi
}
APT_LOCK_WAIT=()
apt-get() { printf 'apt %s\n' "$*" >> "$ROOT/calls"; }
systemctl() {
    printf 'systemctl %s\n' "$*" >> "$ROOT/calls"
    if [[ "$1" = show ]]; then printf 'LoadState=%s\nActiveState=inactive\n' "$(resolved_load)"; return 0; fi
    if [[ "$1" = mask ]]; then
        mkdir -p "$ROOT/etc/systemd/system"
        ln -sf /dev/null "$ROOT/etc/systemd/system/systemd-resolved.service"
        return 0
    fi
    [[ "$1" = daemon-reload ]] && return 0
    return 1
}
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
# Model attributes only inside fixtures; never touch host file attributes.
lsattr() { if [[ -f "$ROOT/dns-immutable" ]]; then printf '%s %s\n' '----i---------' "${@: -1}"; else printf '%s %s\n' '--------------' "${@: -1}"; fi; }
chattr() { case "$1" in +i) printf yes > "$ROOT/dns-immutable";; -i) rm -f "$ROOT/dns-immutable";; *) return 99;; esac; }
'''
FSTAB = ['append_line_break', 'append_swap_fstab_entry', 'ensure_swap_fstab_entry']
SWAP = [*FSTAB, 'remove_fstab_swap_entries', 'configure_swap']

class Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vps-regression-')
        self.root = Path(self.temp.name)
        for d in ['etc/ssh/sshd_config.d', 'etc/systemd/resolved.conf.d', 'etc/sysctl.d', 'var/log', 'proc', 'run', 'tmp']:
            (self.root / d).mkdir(parents=True)
        (self.root / 'etc/fstab').write_text('# preserve\n')
        (self.root / 'calls').touch()
        (self.root / 'proc/net').mkdir()
        (self.root / 'proc/net/if_inet6').write_text('mock-ipv6\n')
        for pid, inode in [(123, 100), (1, 101)]:
            fd = self.root / f'proc/{pid}/fd'
            fd.mkdir(parents=True)
            (fd / '3').symlink_to(f'socket:[{inode}]')
        stub = self.root / 'run/systemd/resolve/stub-resolv.conf'
        stub.parent.mkdir(parents=True)
        stub.write_text('nameserver 127.0.0.53\n')

    def tearDown(self):
        self.temp.cleanup()

    def run_shell(self, names, body, interactive_input=None, expected_returncode=0):
        if 'configure_ssh' in names or 'configure_fail2ban' in names:
            names = [n for n in names if not n.startswith('ssh_')] + [n for n in FUNCTIONS if n.startswith('ssh_')]
        if 'configure_fail2ban' in names and 'fail2ban_service_state' in FUNCTIONS:
            names += ['fail2ban_service_state']
        if 'configure_dns' in names:
            names = [n for n in names if n != 'configure_dns'] + [n for n in FUNCTIONS if n.startswith('dns_')] + ['configure_dns']
        code = '\n'.join(n + '() {\n' + FUNCTIONS[n] for n in names)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/(etc|run|usr|lib|proc|var)/', lambda m: str(self.root) + '/' + m[1] + '/', code)
        code = re.sub(r'(?<![A-Za-z0-9_$}])/swapfile', str(self.root) + '/swapfile', code)
        code = code.replace('/.dockerenv', str(self.root / '.dockerenv'))
        if interactive_input is not None:
            code = code.replace(' < /dev/tty', '')
        fixture = self.root / 'fixture.sh'
        fixture.write_text(COMMON + f"ROOT='{self.root}'\nLOG_FILE='{self.root}/log'\n" + code + '\n' + body)
        out = subprocess.run(['bash', str(fixture)], capture_output=True, text=True, input=interactive_input,
                             env={**os.environ, 'TMPDIR': str(self.root / 'tmp')})
        self.assertEqual(out.returncode, expected_returncode, out.stdout + out.stderr + ((self.root / 'log').read_text() if (self.root / 'log').exists() else ''))
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
ss() { printf '%s\n' 'LISTEN 0 128 0.0.0.0:22 *:* ino:100' 'LISTEN 0 128 [::]:2222 *:* ino:100'; }
F2B_LOAD=loaded F2B_ACTIVE=active F2B_BOOT=enabled SSH_MODE=service
mock_systemctl() {
    printf 'systemctl %s\n' "$*" >> "$ROOT/calls"
    case "${@: -1}" in
        ssh.service|sshd.service|ssh.socket|sshd.socket)
            case "$*:$SSH_MODE" in
                *ActiveState*' ssh.service:service'|*ActiveState*' ssh.socket:socket') printf 'active\n';;
                *ActiveState*) printf 'inactive\n';;
                *MainPID*) printf '123\n';;
                *Listen*) printf '[::]:2200 (Stream) /run/unused (Stream)\n';;
                *) return 99;;
            esac;;
        *) case "$1" in
            show) printf 'LoadState=%s\nActiveState=%s\nUnitFileState=%s\n' "$F2B_LOAD" "$F2B_ACTIVE" "$F2B_BOOT";;
            is-active) [[ "$F2B_ACTIVE" = active ]];;
            restart) F2B_ACTIVE=active;;
            stop) F2B_ACTIVE=inactive;;
            enable) F2B_BOOT=enabled;;
            disable) F2B_BOOT=disabled;;
            *) return 99;;
        esac;;
    esac
}
systemctl() { mock_systemctl "$@"; }
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

    def test_fail2ban_rejects_nonmatching_journal_conjunction(self):
        body = self.setup_fail2ban()
        owned = self.root / 'etc/fail2ban/jail.d/99-vps-setup.local'
        for match in ('_COMM=sshd _SYSTEMD_UNIT=not-ssh.service', '_COMM=sshd-other'):
            with self.subTest(match=match):
                owned.write_text('# original\n')
                (self.root / 'etc/fail2ban/jail.d/zz-existing.local').write_text(
                    '[sshd]\njournalmatch = ' + match + '\n')
                output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'],
                                        body + '\nif configure_fail2ban; then exit 9; fi\n')
                self.assertNotIn('OK Fail2ban', output)
                self.assertEqual(owned.read_text(), '# original\n')

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

    def test_fail2ban_uses_live_socket_ports(self):
        body = self.setup_fail2ban()
        config = self.root / 'etc/ssh/sshd_config'
        config.write_text('Port 22\n')
        self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + r'''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
SSH_MODE=socket
ss() { printf '%s\n' 'LISTEN 0 128 *:2200 *:* ino:101' 'LISTEN 0 128 0.0.0.0:22 *:* ino:555'; }
configure_fail2ban
''')
        self.assertIn('port = 2200\n', (self.root / 'etc/fail2ban/jail.d/99-vps-setup.local').read_text())

    def test_fail2ban_does_not_change_unverified_service(self):
        body = self.setup_fail2ban()
        for mode in ['socket-missing', 'unknown-state']:
            with self.subTest(mode=mode):
                (self.root / 'calls').write_text('')
                output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body + f'\nFAIL={mode}\n' + r'''
if [[ "$FAIL" = socket-missing ]]; then
    SSH_MODE=socket
else
    F2B_BOOT=unknown
fi
if configure_fail2ban; then exit 9; fi
''')
                self.assertIn('未修改', output)
                self.assertNotIn('OK Fail2ban', output)
                self.assertNotRegex((self.root / 'calls').read_text(), r'(?m)^(apt |systemctl (enable|disable|start|stop|restart) )')

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
systemctl() { if [[ "$1" = show ]]; then printf '123\n'; else [[ "${@: -1}" != *.socket ]]; fi; }
ss() { if [[ -f "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf" ]]; then
    sshd -T | awk '$1 == "listenaddress" {print "LISTEN 0 128 " $2 " *:* ino:100"}'
fi; }
''' + ('configure_ssh\n' if accepted else 'if configure_ssh; then exit 9; fi\n'))
                self.assertEqual(dropin.exists(), accepted)
                out = subprocess.check_output(['/usr/sbin/sshd', '-T', '-f', str(config)], text=True)
                self.assertIn('passwordauthentication no', out)

    def test_password_is_single_line_before_any_change(self):
        names = ['valid_ssh_port', 'configure_ssh']
        for value in ["$'secret\\nother:injected'", "$'secret\\rnext'"]:
            with self.subTest(value=value):
                output = self.run_shell(names, f'''non_interactive=true NEW_SSH_PORT='' NEW_SSH_PASSWORD={value}
printf '# fixture\\n' > "$ROOT/etc/ssh/sshd_config"
dpkg() {{ return 0; }}
sshd() {{ return 0; }}
chpasswd() {{ command cat > "$ROOT/password-input"; }}
if configure_ssh; then exit 9; fi
[[ ! -f "$ROOT/password-input" ]]
''')
                self.assertNotIn('OK', output)
                self.assertEqual((self.root / 'calls').read_text(), '')
        self.run_shell(names, r'''non_interactive=true NEW_SSH_PORT='' NEW_SSH_PASSWORD='colon:back\\slash'
dpkg() { return 0; }
chpasswd() { command cat > "$ROOT/password-input"; }
printf '# fixture\n' > "$ROOT/etc/ssh/sshd_config"
sshd() { return 0; }
configure_ssh
''')
        self.assertEqual((self.root / 'password-input').read_bytes(), b'root:colon:back\\\\slash\n')

    def test_password_cli_preserves_leading_hyphen(self):
        self.run_shell(['require_value', 'parse_args'], r'''
parse_args --ssh-password '-single-line:with\\slash'
[[ "$NEW_SSH_PASSWORD" = '-single-line:with\\slash' ]]
if (parse_args --ssh-password); then exit 9; else [[ $? = 2 ]]; fi
''')

    def test_password_missing_value_cannot_consume_an_option(self):
        names = ['parse_args', 'usage']
        for flag in ('--no-fail2ban', '--help', '-h'):
            with self.subTest(flag=flag):
                self.run_shell(names, f'parse_args --ssh-password {flag}\n',
                               expected_returncode=2)
        self.run_shell(names, r'''
parse_args '--ssh-password=--sample' --no-fail2ban
[[ "$NEW_SSH_PASSWORD" = --sample && "$ENABLE_FAIL2BAN" = false ]]
''')
        for value in ("--ssh-password=", "$'--ssh-password=sample\\nother'"):
            with self.subTest(value=value):
                self.run_shell(names, f'parse_args {value}\n', expected_returncode=2)

    def test_interactive_password_preserves_whitespace(self):
        (self.root / 'etc/ssh/sshd_config').touch()
        self.run_shell(['valid_ssh_port', 'configure_ssh'], r'''
non_interactive=false NEW_SSH_PORT='' NEW_SSH_PASSWORD=''
sshd() { return 0; }
chpasswd() { command cat > "$ROOT/password-input"; }
configure_ssh
''', interactive_input='\n \tsample pass  \n')
        self.assertEqual((self.root / 'password-input').read_bytes(), b'root: \tsample pass  \n')

    def test_password_cli_rejects_multiline_without_disclosing_secret(self):
        for value in ["$'secret\\nother:injected'", "$'secret\\rnext'"]:
            with self.subTest(value=value):
                out = self.run_shell(['require_value', 'parse_args'],
                                     f'if (parse_args --ssh-password {value}); then exit 9; else [[ $? = 2 ]]; fi\n')
                self.assertNotIn('secret', out)
                self.assertNotIn('injected', out)

    def test_fstab_repair_failure_preserves_original_bytes(self):
        for failure in ('shortwrite', 'rename'):
            with self.subTest(failure=failure):
                self.run_shell(FSTAB, 'FAILURE=' + failure + r'''
printf '#%01018d' 0 > "$ROOT/etc/fstab"
chmod 640 "$ROOT/etc/fstab"
cp -p "$ROOT/etc/fstab" "$ROOT/expected"
if [[ "$FAILURE" = shortwrite ]]; then
    trap '' XFSZ
    ulimit -f 1
else
    mv() { return 1; }
fi
if ensure_swap_fstab_entry; then exit 9; fi
cmp "$ROOT/etc/fstab" "$ROOT/expected"
[[ $(stat -c %a "$ROOT/etc/fstab") = 640 ]]
[[ -z $(compgen -G "$ROOT/etc/fstab.vps-setup.*") ]]
''')

    def test_swap_size_rejects_arithmetic_overflow(self):
        parsers = ['require_value', 'valid_ipv4', 'valid_ipv6', 'valid_ssh_port', 'parse_args']
        for value in ['9223372036854775808', '18446744073709551616', '8796093022208', '9' * 100]:
            with self.subTest(value=value):
                self.run_shell(parsers, f'if (parse_args --swap {value}); then exit 9; else [[ $? = 2 ]]; fi\n')
        self.run_shell(parsers, 'parse_args --swap 8796093022207\n[[ "$SWAP_SIZE_MB" = 8796093022207 ]]\n')

    def test_hostname_matches_exact_address_and_preserves_aliases(self):
        hosts = self.root / 'etc/hosts'
        hosts.write_text('127.0.0.1 localhost\n127.0.1.10 keep-alias\n'
                         ' 127.0.1.1 old-host old-host.internal service-alias # keep note\n')
        self.run_shell(['configure_hostname'], r'''
non_interactive=true NEW_HOSTNAME=new-host
hostname() { printf 'old-host\n'; }
hostnamectl() { return 0; }
configure_hostname
''')
        self.assertIn('127.0.1.10 keep-alias\n', hosts.read_text())
        self.assertIn('new-host old-host.internal service-alias # keep note\n', hosts.read_text())

    def test_hostname_adds_missing_exact_address(self):
        hosts = self.root / 'etc/hosts'
        hosts.write_text('127.0.1.10 keep-alias\n')
        self.run_shell(['append_line_break', 'configure_hostname'], r'''
non_interactive=true NEW_HOSTNAME=new-host
hostname() { printf 'old-host\n'; }
hostnamectl() { return 0; }
configure_hostname
''')
        self.assertEqual(hosts.read_text(), '127.0.1.10 keep-alias\n127.0.1.1\tnew-host\n')

    def test_hostname_handles_address_without_name_and_unterminated_hosts(self):
        hosts = self.root / 'etc/hosts'
        for original, expected in [
            ('127.0.1.1 # keep', '127.0.1.1\tnew-host # keep'),
            ('127.0.0.1 localhost', '127.0.0.1 localhost\n127.0.1.1\tnew-host\n'),
        ]:
            with self.subTest(original=original):
                hosts.write_text(original)
                self.run_shell(['append_line_break', 'configure_hostname'], r'''
non_interactive=true NEW_HOSTNAME=new-host
hostname() { printf 'old-host\n'; }
hostnamectl() { return 0; }
configure_hostname
''')
                self.assertEqual(hosts.read_text(), expected)

    def test_hostname_length_is_validated_before_mutation(self):
        parsers = ['require_value', 'parse_args']
        self.run_shell(parsers, 'parse_args --hostname ' + 'a' * 63 + '\n')
        for value in ['a' * 64, 'a' * 65, '-invalid', 'invalid-']:
            with self.subTest(value=value):
                self.run_shell(parsers, f'if (parse_args --hostname {value}); then exit 9; else [[ $? = 2 ]]; fi\n')

    def test_interactive_hostname_and_password_validation(self):
        output = self.run_shell(['configure_hostname'], r'''
non_interactive=false NEW_HOSTNAME=''
hostname() { printf 'current\n'; }
hostnamectl() { printf 'MUTATION\n' >> "$ROOT/calls"; }
configure_hostname
''', interactive_input='y\n' + 'a' * 64 + '\n')
        self.assertIn('1-63', output)
        self.assertEqual((self.root / 'calls').read_text(), '')
        output = self.run_shell(['valid_ssh_port', 'configure_ssh'], r'''
non_interactive=false NEW_SSH_PORT='' NEW_SSH_PASSWORD=''
if configure_ssh; then exit 9; fi
''', interactive_input='\nsecret\rnext\n')
        self.assertNotIn('secret', output)
        self.assertEqual((self.root / 'calls').read_text(), '')

    def test_timezone_validation_consumes_full_list(self):
        # A producer larger than the pipe buffer deterministically exposes grep -q SIGPIPE.
        self.run_shell(['require_value', 'parse_args'], r'''
timedatectl() {
    [[ "$1" = list-timezones ]] || return 99
    printf 'UTC\n'
    for ((i=0; i<10000; i++)); do printf 'Example/Zone%s\n' "$i"; done
}
parse_args --timezone UTC
[[ "$TIMEZONE" = UTC ]]
if (parse_args --timezone invalid); then exit 9; else [[ $? = 2 ]]; fi
if (parse_args --timezone $'UTC\ninvalid'); then exit 9; else [[ $? = 2 ]]; fi
''')

    def test_timezone_only_mutates_on_explicit_request(self):
        self.run_shell(['configure_timezone'], r'''
timedatectl() { printf '%s\n' "$*" >> "$ROOT/calls"; }
TIMEZONE=''
configure_timezone
[[ ! -s "$ROOT/calls" ]]
TIMEZONE=Asia/Hong_Kong
configure_timezone
[[ $(< "$ROOT/calls") = 'set-timezone Asia/Hong_Kong' ]]
''')

    def test_ssh_socket_activation_is_left_untouched(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        dropin.write_text('Port 22\n# administrator\n')
        for socket in ['ssh.socket', 'sshd.socket']:
            with self.subTest(socket=socket):
                output = self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], f'ACTIVE_SOCKET={socket}\n' + r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
systemctl() {
    if [[ "$1" = is-active ]]; then [[ "${@: -1}" = "$ACTIVE_SOCKET" ]]; return; fi
    printf 'MUTATION %s\n' "$*" >> "$ROOT/calls"
}
ss() { if [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = 'Port 2222' ]]; then printf 'LISTEN 0 128 0.0.0.0:2222 *:*\n'; fi; }
if configure_ssh; then exit 9; fi
''')
                self.assertEqual(dropin.read_text(), 'Port 22\n# administrator\n')
                self.assertEqual((self.root / 'calls').read_text(), '')
                self.assertNotIn('OK SSH', output)

    def test_ssh_failed_restart_restores_config_and_keeps_failed_recovery_backup(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        original = 'Port 22\n# administrator\n'
        for recovery in ['true', 'false']:
            with self.subTest(recovery=recovery):
                dropin.write_text(original)
                output = self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], f'RECOVERY={recovery}\n' + r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
systemctl() {
    case "$1" in
        is-active) [[ "${@: -1}" != *.socket ]];;
        cat) return 0;;
        show) printf '123\n';;
        restart) printf 'restart\n' >> "$ROOT/restarts"
            [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = *administrator* && "$RECOVERY" = true ]];;
        *) return 99;;
    esac
}
ss() { :; }
if configure_ssh; then exit 9; fi
''')
                self.assertEqual(dropin.read_text(), original)
                self.assertNotIn('OK SSH', output)
                backups = list(dropin.parent.glob('*.backup.*'))
                self.assertEqual(len(backups), 0 if recovery == 'true' else 1)
                if backups: self.assertEqual(backups[0].read_text(), original)

    def test_fail2ban_failed_restart_restores_owned_config(self):
        body = self.setup_fail2ban()
        owned = self.root / 'etc/fail2ban/jail.d/99-vps-setup.local'
        owned.write_text('# administrator\n')
        body += r'''
systemctl() {
    if [[ "$1" = restart ]]; then
        printf 'restart\n' >> "$ROOT/restarts"
        grep -q administrator "$ROOT/etc/fail2ban/jail.d/99-vps-setup.local"
    else mock_systemctl "$@"; fi
}
if configure_fail2ban; then exit 9; fi
'''
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body)
        self.assertEqual(owned.read_text(), '# administrator\n')
        self.assertEqual((self.root / 'restarts').read_text().splitlines(), ['restart', 'restart'])
        self.assertNotIn('OK Fail2ban', output)

    def test_fail2ban_rejected_jail_is_not_enabled_or_left_running(self):
        body = self.setup_fail2ban() + r'''
F2B_LOAD=not-found F2B_ACTIVE=inactive F2B_BOOT=''
apt-get() {
    printf 'apt %s\n' "$*" >> "$ROOT/calls"
    F2B_LOAD=loaded F2B_ACTIVE=active F2B_BOOT=enabled
}
if configure_fail2ban; then exit 9; fi
[[ "$F2B_ACTIVE:$F2B_BOOT" = inactive:disabled ]]
'''
        (self.root / 'etc/fail2ban/jail.d/zz-existing.local').write_text('[sshd]\nenabled = false\n')
        output = self.run_shell(['valid_ssh_port', 'configure_fail2ban'], body)
        calls = (self.root / 'calls').read_text().splitlines()
        self.assertIn('systemctl restart fail2ban', calls)
        self.assertIn('systemctl stop fail2ban', calls)
        self.assertIn('systemctl disable fail2ban', calls)
        self.assertNotIn('systemctl enable fail2ban', calls)
        self.assertNotIn('OK Fail2ban', output)

    def test_ssh_restart_success_requires_active_service(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        dropin.write_text('Port 22\n# administrator\n')
        for failure_phase in ['immediate', 'after-wait']:
            with self.subTest(failure_phase=failure_phase):
                output = self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], f'FAILURE_PHASE={failure_phase}\n' + r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
sleep() { touch "$ROOT/after-wait"; }
systemctl() {
    case "$1" in
        cat|restart) return 0;;
        is-active)
            [[ "${@: -1}" != *.socket ]] || return 1
            [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = *administrator* ||
               ( "$FAILURE_PHASE" = after-wait && ! -f "$ROOT/after-wait" ) ]];;
        *) return 99;;
    esac
}
ss() { if [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = 'Port 2222' ]]; then printf 'LISTEN 0 128 0.0.0.0:2222 *:*\n'; fi; }
if configure_ssh; then exit 9; fi
''')
                self.assertEqual(dropin.read_text(), 'Port 22\n# administrator\n')
                self.assertNotIn('OK SSH', output)

    def test_dns_takes_over_managers(self):
        for manager, header in [('NetworkManager', ''), ('connman', ''), ('resolvconf', ''), ('dhcpcd', ''),
                                ('none', '# Generated by NetworkManager\n'), ('none', '# Generated by dhcpcd\n')]:
            with self.subTest(manager=manager, header=header):
                original = header + 'search private.internal\noptions ndots:2\nnameserver 10.0.0.53\n'
                (self.root / 'etc/resolv.conf').write_text(original)
                output = self.run_shell(['configure_dns'], self.dns_defaults() + f'''
systemctl() {{
    if [[ "$1" = show ]]; then printf 'LoadState=%s\nActiveState=inactive\n' "$(resolved_load)";
    elif [[ "$1" = mask ]]; then mkdir -p "$ROOT/etc/systemd/system"; ln -sf /dev/null "$ROOT/etc/systemd/system/systemd-resolved.service";
    else [[ "$*" = 'is-active --quiet {manager}' ]]; fi
}}
configure_dns
''')
                self.assertEqual((self.root / 'etc/resolv.conf').read_text(),
                                 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' + header +
                                 'search private.internal\noptions ndots:2\n')
                self.assertIn('OK DNS', output)
                self.assertEqual((self.root / 'dns-immutable').read_text(), 'yes')

    def test_dns_direct_preserves_options(self):
        path = self.root / 'etc/resolv.conf'
        path.write_bytes(b'# local\nsearch private.internal\nnameserver 10.0.0.53\noptions ndots:2')
        self.run_shell(['configure_dns'], self.dns_defaults() + '\nconfigure_dns\n')
        self.assertEqual(path.read_bytes(), b'nameserver 1.1.1.1\nnameserver 8.8.8.8\n# local\nsearch private.internal\noptions ndots:2')
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def dns_defaults(self):
        defaults = re.findall(r'^(?:PRIMARY|SECONDARY)_DNS_V[46]="[^"]+"$', SOURCE, re.M)
        self.assertEqual(len(defaults), 4)
        return '\n'.join(defaults) + '\nhas_ipv6() { return 1; }\n'

    def test_ipv6_detection_consumes_complete_ip_output(self):
        for branch in ('route', 'addr'):
            with self.subTest(branch=branch):
                self.run_shell(['has_ipv6'], f'BRANCH={branch}\n' + r'''
ip() {
    [[ "$2" = "$BRANCH" ]] || return 0
    case "$2" in
        route) printf 'default via 2001:db8::1 dev eth0\n';;
        addr) printf 'inet6 2001:db8::2/64 scope global\n';;
        *) return 99;;
    esac
    for ((i=0; i<10000; i++)); do printf '2001:db8:%s::/64 dev eth0\n' "$i"; done
}
has_ipv6
''')
        self.run_shell(['has_ipv6'], 'ip() { return 0; }\nif has_ipv6; then exit 9; fi\n')

    def test_packages_install_network_inspection_dependency(self):
        defaults = re.search(r'^INSTALL_PACKAGES=\([^\n]+\)$', SOURCE, re.M)
        self.assertIsNotNone(defaults)
        assert defaults is not None
        self.run_shell(['install_packages', 'has_ipv6', 'valid_ssh_port', 'ssh_listening_ports',
                        'ssh_socket_rows', 'ssh_remote_endpoints', 'ssh_bindings_present'], defaults[0] + r'''
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=600)
apt-get() {
    printf 'apt %s\n' "$*" >> "$ROOT/calls"
    if [[ " $* " = *' iproute2 '* ]]; then touch "$ROOT/iproute2-installed"; fi
}
ip() {
    [[ -e "$ROOT/iproute2-installed" ]] || return 127
    printf 'default via 2001:db8::1 dev eth0\n'
}
ss() {
    [[ -e "$ROOT/iproute2-installed" ]] || return 127
    printf 'LISTEN 0 128 0.0.0.0:22 *:* ino:100\n'
}
systemctl() {
    case "$*" in
        *ActiveState*ssh.service) printf 'active\n';;
        *ActiveState*) printf 'inactive\n';;
        *MainPID*) printf '123\n';;
        *) return 99;;
    esac
}
if has_ipv6; then exit 9; fi
if ssh_listening_ports; then exit 9; fi
install_packages
has_ipv6
[[ $(ssh_listening_ports) = 22 ]]
grep -Fx 'apt -o DPkg::Lock::Timeout=600 update -qq' "$ROOT/calls"
''')

    def test_package_failures_stop_conditional_callers_without_success(self):
        for failure in ('update', 'install', 'full-upgrade', 'autoremove', 'clean'):
            with self.subTest(failure=failure):
                names = ['install_packages'] if failure in ('update', 'install') else ['system_update']
                output = self.run_shell(names, f'FAILURE={failure}\n' + r'''
INSTALL_PACKAGES=(sudo curl wget ca-certificates iproute2)
UPGRADE_SYSTEM=true CLEAN_SYSTEM=true
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=600)
: > "$ROOT/calls"
apt-get() {
    printf '%s\n' "$*" >> "$ROOT/calls"
    [[ " $* " != *" $FAILURE "* ]]
}
''' + ('if install_packages; then exit 9; fi\n' if names == ['install_packages'] else 'if system_update; then exit 9; fi\n'))
                if failure in ('update', 'install'):
                    self.assertNotIn('OK 基础软件包安装完成', output)
                elif failure == 'full-upgrade':
                    self.assertNotIn('OK 系统升级完成', output)
                else:
                    self.assertNotIn('OK 系统清理完成', output)
                calls = (self.root / 'calls').read_text().splitlines()
                self.assertIn(failure, calls[-1].split())

    def test_hostname_failure_does_not_edit_hosts_or_report_success(self):
        hosts = self.root / 'etc/hosts'
        hosts.write_text('127.0.1.1 old-host\n')
        output = self.run_shell(['configure_hostname'], r'''
non_interactive=true NEW_HOSTNAME=new-host
hostname() { printf 'old-host\n'; }
hostnamectl() { printf 'attempted\n' >> "$ROOT/calls"; return 1; }
if configure_hostname; then exit 9; fi
''')
        self.assertEqual((self.root / 'calls').read_text(), 'attempted\n')
        self.assertEqual(hosts.read_text(), '127.0.1.1 old-host\n')
        self.assertNotIn('OK 主机名设为', output)

    def test_dns_default_order_and_help(self):
        path = self.root / 'etc/resolv.conf'
        path.write_text('# local\n')
        self.run_shell(['configure_dns'], self.dns_defaults() + '\nhas_ipv6() { return 0; }\nconfigure_dns\n')
        self.assertEqual(path.read_text(), 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n'
                         'nameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888\n# local\n')
        help_text = self.run_shell(['usage'], 'usage\n')
        readme = (REPO / 'README.md').read_text()
        for addresses in ['1.1.1.1 / 8.8.8.8', '2606:4700:4700::1111 / 2001:4860:4860::8888']:
            self.assertIn(addresses, help_text)
            self.assertIn(addresses, readme)

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
        for required in ['≤512 MiB', '513–1024 MiB', '2048 MiB', '尝试恢复该步骤', '不撤销已完成的步骤', 'search/options', 'ignoreip', '密码登录开关']:
            self.assertIn(required, readme)
        version_match = re.search(r'^SCRIPT_VERSION="([^"]+)"$', SOURCE, re.M)
        self.assertIsNotNone(version_match)
        assert version_match is not None
        self.assertIn('# 版本: ' + version_match[1], SOURCE)
        self.assertIn('版本：`' + version_match[1] + '`', readme)
        self.assertNotIn('其余为 4 GiB', readme)

    def main_defaults_and_mocks(self):
        # Only reviewed scalar/array declarations, never source top-level code.
        preamble = SOURCE.split('\nlog() {', 1)[0]
        declarations = '\n'.join(re.findall(
            r'^[A-Za-z_][A-Za-z_0-9]*=(?:"[^"\n]*"|true|false|\([^\n]*\))$', preamble, re.M))
        steps = ['pre_flight_checks', 'install_packages', 'configure_hostname', 'configure_timezone',
                 'configure_time_sync', 'configure_bbr', 'configure_swap', 'configure_dns',
                 'configure_ssh', 'configure_fail2ban', 'system_update']
        mocks = '\n'.join(name + '() { printf "' + name + '\\n" >> "$ROOT/calls"; }' for name in steps)
        return declarations + '\n' + mocks + '\nhas_ipv6() { return 1; }\nreboot() { return 99; }\n'

    def test_interactive_eof_is_failure_for_conditional_helpers(self):
        for name in ('configure_hostname', 'configure_ssh'):
            with self.subTest(name=name):
                self.run_shell(['valid_ssh_port', name], r'''
non_interactive=false NEW_HOSTNAME='' NEW_SSH_PORT='' NEW_SSH_PASSWORD=''
hostname() { printf 'current\n'; }
''' + 'if ' + name + '; then exit 9; fi\n', interactive_input='')
                self.assertEqual((self.root / 'calls').read_text(), '')

    def test_output_helpers_preserve_operator_information(self):
        output = self.run_shell(['log', 'section_header', 'step_info', 'print_summary_row',
                                 'result_ok', 'result_warn'], r'''
log '保留原连接'
section_header 7 'DNS 配置'
step_info '静态接管，不重启网络'
print_summary_row '配置文件' '/fixture/resolv.conf'
result_ok 'IPv4 1.1.1.1 / 8.8.8.8'
result_warn '恢复不完整，保留备份' 2>&1
''')
        for text in ('保留原连接', '7. DNS 配置', '静态接管，不重启网络',
                     '配置文件：/fixture/resolv.conf', 'IPv4 1.1.1.1 / 8.8.8.8', '恢复不完整，保留备份'):
            self.assertIn(text, output)

    def test_helpers_disk_kernel_duration_and_address_boundaries(self):
        self.run_shell(['check_disk_space', 'is_kernel_version_ge', 'format_duration', 'valid_ipv4',
                        'valid_ipv6', 'valid_ssh_port', 'append_line_break'], r'''
df() { printf 'Filesystem 1M-blocks Used Available Use%% Mounted\nfixture 1000M 100M 900M 10%% /\n'; }
check_disk_space 900
if check_disk_space 901; then exit 9; fi
df() { return 1; }
if check_disk_space 1; then exit 9; fi
uname() { printf '6.12.1-fixture\n'; }
is_kernel_version_ge 4.9
if is_kernel_version_ge 6.13; then exit 9; fi
uname() { printf 'unparseable\n'; }
if is_kernel_version_ge 4.9; then exit 9; fi
[[ $(format_duration 0) = '0 秒' && $(format_duration 59) = '59 秒' ]]
[[ $(format_duration 60) = '1 分 0 秒' && $(format_duration 121) = '2 分 1 秒' ]]
for value in 0.0.0.0 255.255.255.255 192.0.2.1; do valid_ipv4 "$value"; done
for value in 256.0.0.1 01.2.3.4 1.2.3 1.2.3.4.5; do if valid_ipv4 "$value"; then exit 9; fi; done
for value in :: ::1 2001:DB8::abcd 1:2:3:4:5:6:7:8; do valid_ipv6 "$value"; done
for value in :1:2:3:4:5:6:7 1:2:3:4:5:6:7: 1:::2 1::2::3 1:2:3:4:5:6:7::8; do if valid_ipv6 "$value"; then exit 9; fi; done
for value in 1 65535; do valid_ssh_port "$value"; done
for value in 0 65536 022 999999999999; do if valid_ssh_port "$value"; then exit 9; fi; done
: > "$ROOT/empty"
append_line_break "$ROOT/empty"
[[ ! -s "$ROOT/empty" ]]
printf 'line' > "$ROOT/line"
append_line_break "$ROOT/line"
[[ $(wc -l < "$ROOT/line") = 1 ]]
append_line_break "$ROOT/line"
[[ $(wc -l < "$ROOT/line") = 1 ]]
''')

    def test_main_default_dispatch_and_explicit_skips(self):
        names = ['main', 'parse_args', 'usage', 'require_value', 'valid_ssh_port', 'valid_ipv4',
                 'valid_ipv6', 'format_duration', 'handle_error']
        expected = ['pre_flight_checks', 'install_packages', 'configure_hostname', 'configure_timezone',
                    'configure_time_sync', 'configure_bbr', 'configure_swap', 'configure_dns',
                    'configure_ssh', 'configure_fail2ban', 'system_update']
        for options in ('', '--no-fail2ban --no-bbr --swap 0 --upgrade --cleanup'):
            with self.subTest(options=options):
                (self.root / 'calls').write_text('')
                output = self.run_shell(names, self.main_defaults_and_mocks() +
                                        'main --non-interactive ' + options + '\n')
                wanted = expected if not options else [x for x in expected if x != 'configure_fail2ban']
                self.assertEqual((self.root / 'calls').read_text().splitlines(), wanted)
                self.assertIn('VPS 初始化配置全部完成', output)
                if options:
                    for message in ('跳过配置（保持已有服务）', '切换为 cubic（保留 qdisc）', '禁用全部（含分区）'):
                        self.assertIn(message, output)

    def test_main_help_errors_no_tty_and_failure_abort_before_later_steps(self):
        names = ['main', 'parse_args', 'usage', 'require_value', 'valid_ssh_port', 'valid_ipv4',
                 'valid_ipv6', 'format_duration', 'handle_error']
        for args, status in (('--help', 0), ('--unknown', 2), ('--swap', 2), ('', 2)):
            with self.subTest(args=args):
                output = self.run_shell(names, self.main_defaults_and_mocks() + 'main ' + args + '\n',
                                        expected_returncode=status)
                self.assertEqual((self.root / 'calls').read_text(), '')
                self.assertFalse(list((self.root / 'var/log').glob('*')))
                if not args:
                    self.assertIn('没有可用终端', output)
        output = self.run_shell(names, self.main_defaults_and_mocks() + r'''
configure_bbr() { printf 'failed-bbr\n' >> "$ROOT/calls"; return 37; }
main --non-interactive
''', expected_returncode=37)
        calls = (self.root / 'calls').read_text().splitlines()
        self.assertEqual(calls[-1], 'failed-bbr')
        self.assertNotIn('configure_swap', calls)
        self.assertIn('退出码: 37', output)
        self.assertNotIn('全部完成', output)
        log = next((self.root / 'var/log').glob('*')).read_text()
        self.assertIn('退出码：37', log)

    def test_main_interactive_decline_and_keep_existing_settings(self):
        names = ['main', 'parse_args', 'usage', 'require_value', 'format_duration', 'handle_error']
        self.run_shell(names, self.main_defaults_and_mocks() + 'main\n', interactive_input='n\n')
        self.assertEqual((self.root / 'calls').read_text(), '')
        self.assertFalse(list((self.root / 'var/log').glob('*')))
        for name in ('configure_hostname', 'configure_ssh'):
            output = self.run_shell(['valid_ssh_port', name], r'''
non_interactive=false NEW_HOSTNAME='' NEW_SSH_PORT='' NEW_SSH_PASSWORD=''
hostname() { printf 'current\n'; }
hostnamectl() { return 99; }
''' + name + '\n', interactive_input='\n\n')
            self.assertNotIn('OK', output)
            self.assertEqual((self.root / 'calls').read_text(), '')

    def test_interactive_eof_after_completion_skips_optional_reboot(self):
        names = ['main', 'parse_args', 'usage', 'format_duration', 'handle_error']
        output = self.run_shell(names, self.main_defaults_and_mocks() + 'main\n',
                                interactive_input='y\n')
        self.assertIn('VPS 初始化配置全部完成', output)
        self.assertNotIn('脚本在第', output)

    def test_preflight_supported_versions_and_rejected_environments(self):
        names = ['pre_flight_checks']
        path = self.root / 'etc/os-release'
        for distro, versions in [('debian', ['10', '11', '12', '13']),
                                 ('ubuntu', ['20.04', '22.04', '24.04', '26.04'])]:
            for version in versions:
                with self.subTest(distro=distro, version=version):
                    path.write_text(f'ID={distro}\nVERSION_ID={version}\n')
                    self.run_shell(names, 'non_interactive=true\nis_container() { return 1; }\npre_flight_checks\n')
        path.write_text('ID=other\nVERSION_ID=1\n')
        output = self.run_shell(names, 'non_interactive=true\nis_container() { return 1; }\npre_flight_checks\n', expected_returncode=1)
        self.assertIn('不支持当前系统', output)
        output = self.run_shell(names, 'non_interactive=true\nis_container() { return 0; }\npre_flight_checks\n', expected_returncode=1)
        self.assertIn('不支持在容器环境', output)
        path.unlink()
        output = self.run_shell(names, 'non_interactive=true\nis_container() { return 1; }\npre_flight_checks\n', expected_returncode=1)
        self.assertIn('系统信息缺失', output)

    def test_update_and_cleanup_explicit_selection_and_skip(self):
        for upgrade, cleanup in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(upgrade=upgrade, cleanup=cleanup):
                (self.root / 'calls').write_text('')
                output = self.run_shell(['system_update'], f'UPGRADE_SYSTEM={str(upgrade).lower()} CLEAN_SYSTEM={str(cleanup).lower()}\n' + r'''
APT_LOCK_WAIT=(-o DPkg::Lock::Timeout=600)
system_update
''')
                calls = (self.root / 'calls').read_text().splitlines()
                self.assertEqual(len(calls), int(upgrade) + 2 * int(cleanup))
                if not upgrade and not cleanup:
                    self.assertIn('跳过', output)
                if upgrade:
                    self.assertIn('apt -o DPkg::Lock::Timeout=600 full-upgrade -y -o Dpkg::Options::=--force-confold', calls)

    def test_time_sync_missing_provider_fallback_and_failure_warning(self):
        for success in (True, False):
            with self.subTest(success=success):
                output = self.run_shell(['configure_time_sync'], f'SUCCESS={str(success).lower()}\n' + r'''
systemctl() {
    printf '%s\n' "$*" >> "$ROOT/calls"
    case "$1" in
        cat|is-active) return 1;;
        unmask) return 0;;
        enable) [[ "$SUCCESS" = true ]] && touch "$ROOT/ntp-started"; return;;
        *) return 99;;
    esac
}
timedatectl() {
    case "$1" in
        status) [[ ! -f "$ROOT/ntp-started" ]] || printf 'NTP service: active\n';;
        set-ntp) return 1;;
        *) return 99;;
    esac
}
configure_time_sync
''')
                if success:
                    self.assertIn('OK 时间同步服务已启用', output)
                else:
                    self.assertIn('WARN 时间同步服务未确认激活', output)
                    self.assertNotIn('OK 时间同步服务已启用', output)
                (self.root / 'ntp-started').unlink(missing_ok=True)

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
printf '/dev/mock1\n/dev/mock2\n' > "$ROOT/active-list"
swapon() {
    case "$*" in
        --show=NAME,PRIO*) awk '{print $0, ($0 == "/dev/mock1" ? 10 : 100)}' "$ROOT/active-list";;
        --show=NAME\ --*) cat "$ROOT/active-list";;
        --show=NAME,SIZE*) printf '/dev/mock1 1048576\n/dev/mock2 1048576\n';;
        *) printf 'swapon %s\n' "$*" >> "$ROOT/calls"; printf '%s\n' "${@: -1}" >> "$ROOT/active-list";;
    esac
}
swapoff() {
    [[ "$1" != /dev/mock2 ]] || return 1
    grep -Fxv "$1" "$ROOT/active-list" > "$ROOT/active-list.new" || :
    mv "$ROOT/active-list.new" "$ROOT/active-list"
}
if configure_swap; then exit 9; fi
cmp "$ROOT/original" "$ROOT/etc/fstab"
grep -Fxq 'swapon --priority 10 /dev/mock1' "$ROOT/calls"
''')
        parsers = ['require_value', 'usage', 'valid_ipv4', 'valid_ipv6', 'valid_ssh_port', 'parse_args']
        for args in ['--unknown', '--swap', '--ssh-port 022', "--ip-dns '1.1.1.1 999.1.1.1'", "--ip6-dns ':1:2:3:4:5:6:7:8 2001::1'", "--ip-dns $'1.1.1.1 8.8.8.8\\ngarbage'", "--ip-dns '010.1.1.1 8.8.8.8'"]:
            with self.subTest(args=args):
                self.run_shell(parsers, f'if (parse_args {args}) >/dev/null 2>&1; then exit 9; else [[ $? = 2 ]]; fi\n')

    def test_dns_failure_restores_file_link_attributes_and_service(self):
        path = self.root / 'etc/resolv.conf'
        unit = self.root / 'etc/systemd/system/systemd-resolved.service'
        unit.parent.mkdir(parents=True)
        for kind in ['file', 'link', 'dangling', 'absent', 'immutable']:
            for fault in ['write', 'rename', 'lock', 'lock-missing', 'mask', 'verify', 'active']:
                with self.subTest(kind=kind, fault=fault):
                    path.unlink(missing_ok=True)
                    unit.unlink(missing_ok=True)
                    (self.root / 'dns-immutable').unlink(missing_ok=True)
                    unit.symlink_to('/usr/lib/systemd/system/systemd-resolved.service')
                    if kind in ['file', 'immutable']: path.write_text('nameserver 10.0.0.53\nsearch old.internal\n')
                    elif kind in ['link', 'dangling']: path.symlink_to(self.root / ('run/systemd/resolve/stub-resolv.conf' if kind == 'link' else 'missing'))
                    if kind == 'immutable': (self.root / 'dns-immutable').write_text('yes')
                    before = os.readlink(path) if path.is_symlink() else path.read_text() if path.exists() else None
                    body = r'''
ACTIVE=true
systemctl() {
    case "$1" in
        show) printf 'LoadState=%s\nActiveState=%s\n' "$(resolved_load)" "$([[ "$ACTIVE" = true ]] && printf active || printf inactive)";;
        is-active) [[ "$ACTIVE" = true ]];;
        mask) ln -sf /dev/null "$ROOT/etc/systemd/system/systemd-resolved.service"; ACTIVE=false; [[ "$FAULT" != mask ]] || return 1; [[ "$FAULT" != active ]] || ACTIVE=true;;
        start) ACTIVE=true;;
        daemon-reload) :;;
        *) return 99;;
    esac
}
sed() { [[ "$FAULT" != write ]] || return 1; command sed "$@"; }
mv() { [[ "$FAULT" != rename ]] || return 1; command mv "$@"; }
chattr() {
    case "$1" in
        +i) if [[ ! -f "$ROOT/lock-attempted" ]]; then
                touch "$ROOT/lock-attempted"
                [[ "$FAULT" != lock ]] || return 1
                [[ "$FAULT" != lock-missing ]] || return 0
            fi
            printf yes > "$ROOT/dns-immutable";;
        -i) rm -f "$ROOT/dns-immutable";;
    esac
}
awk() { if [[ "$FAULT" = verify && "$1" = *nameserver* ]]; then printf '9.9.9.9\n'; else command awk "$@"; fi; }
if configure_dns; then exit 9; fi
[[ "$ACTIVE" = true ]]
'''
                    # A missing file has nothing to filter, so generation failure isn't applicable.
                    if fault == 'write' and kind in ['absent', 'dangling']: continue
                    (self.root / 'lock-attempted').unlink(missing_ok=True)
                    output = self.run_shell(['configure_dns'], self.dns_defaults() + f'\nFAULT={fault}\n' + body)
                    self.assertNotIn('OK DNS', output)
                    self.assertEqual(path.is_symlink(), kind in ['link', 'dangling'])
                    self.assertEqual(os.readlink(path) if path.is_symlink() else path.read_text() if path.exists() else None, before)
                    self.assertEqual(os.readlink(unit), '/usr/lib/systemd/system/systemd-resolved.service')
                    self.assertEqual((self.root / 'dns-immutable').exists(), kind == 'immutable')

    def test_dns_existing_unit_and_active_mask(self):
        path = self.root / 'etc/resolv.conf'
        unit = self.root / 'etc/systemd/system/systemd-resolved.service'
        unit.parent.mkdir(parents=True)
        for kind in ['file', 'vendor-link', 'mask', 'runtime-mask']:
            for fail in [False, True]:
                with self.subTest(kind=kind, fail=fail):
                    unit.unlink(missing_ok=True)
                    path.unlink(missing_ok=True)
                    (self.root / 'dns-immutable').unlink(missing_ok=True)
                    path.write_text('nameserver 10.0.0.53\n')
                    if kind == 'file': unit.write_text('[Service]\nExecStart=/usr/lib/systemd/systemd-resolved\n')
                    else: unit.symlink_to('/dev/null' if kind == 'mask' else '/usr/lib/systemd/system/systemd-resolved.service')
                    runtime_unit = self.root / 'run/systemd/system/systemd-resolved.service'
                    runtime_unit.parent.mkdir(parents=True, exist_ok=True)
                    runtime_unit.unlink(missing_ok=True)
                    if kind == 'runtime-mask': runtime_unit.symlink_to('/dev/null')
                    original = os.readlink(unit) if unit.is_symlink() else unit.read_text()
                    output = self.run_shell(['configure_dns'], self.dns_defaults() + f'\nFAIL={str(fail).lower()}\n' + r'''
ACTIVE=true
systemctl() {
    case "$1" in
        show) printf 'LoadState=%s\nActiveState=%s\n' "$(resolved_load)" "$([[ "$ACTIVE" = true ]] && printf active || printf inactive)";;
        mask) [[ ! -e "$ROOT/etc/systemd/system/systemd-resolved.service" && ! -L "$ROOT/etc/systemd/system/systemd-resolved.service" ]] || return 1
            ln -s /dev/null "$ROOT/etc/systemd/system/systemd-resolved.service"; ACTIVE=false;;
        start) [[ "$(readlink "$ROOT/etc/systemd/system/systemd-resolved.service" || true)" != /dev/null && "$(readlink "$ROOT/run/systemd/system/systemd-resolved.service" || true)" != /dev/null ]] || return 1; ACTIVE=true;;
        stop) ACTIVE=false;;
        daemon-reload) :;;
        *) return 99;;
    esac
}
awk() { if [[ "$FAIL" = true && "$1" = *nameserver* ]]; then printf '9.9.9.9\n'; else command awk "$@"; fi; }
if [[ "$FAIL" = true ]]; then
    if configure_dns; then exit 9; fi
    [[ "$ACTIVE" = true ]]
else configure_dns; fi
''')
                    if fail:
                        self.assertEqual(os.readlink(unit) if unit.is_symlink() else unit.read_text(), original)
                        self.assertEqual(path.read_text(), 'nameserver 10.0.0.53\n')
                        self.assertNotIn('恢复不完整', output)
                    else:
                        self.assertEqual(os.readlink(unit), '/dev/null')
                        self.assertIn('OK DNS', output)

    def test_dns_service_query_failure_is_not_success(self):
        path = self.root / 'etc/resolv.conf'
        path.write_text('nameserver 10.0.0.53\n')
        unit = self.root / 'etc/systemd/system/systemd-resolved.service'
        unit.parent.mkdir(parents=True)
        unit.symlink_to('/dev/null')
        (self.root / 'dns-immutable').write_text('yes')
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
systemctl() { return 1; }
if configure_dns; then exit 9; fi
''')
        self.assertNotIn('OK DNS', output)
        self.assertEqual(path.read_text(), 'nameserver 10.0.0.53\n')

    def test_dns_file_attribute_read_failure_is_not_success(self):
        path = self.root / 'etc/resolv.conf'
        path.write_text('nameserver 10.0.0.53\n')
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
lsattr() { return 1; }
if configure_dns; then exit 9; fi
''')
        self.assertEqual(path.read_text(), 'nameserver 10.0.0.53\n')
        self.assertNotIn('OK DNS', output)

    def test_dns_failed_restore_retains_backup(self):
        path = self.root / 'etc/resolv.conf'
        path.write_text('nameserver 10.0.0.53\n')
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
chattr() { [[ "$1" != +i ]]; }
cp() { [[ "$*" != *--remove-destination* ]] || return 1; command cp "$@"; }
if configure_dns; then exit 9; fi
''')
        self.assertNotIn('OK DNS', output)
        self.assertIn('恢复不完整', output)
        backups = list(path.parent.glob('resolv.conf.backup.*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / 'resolv.conf').read_text(), 'nameserver 10.0.0.53\n')

    def test_dns_repeat_and_custom_dual_stack(self):
        path = self.root / 'etc/resolv.conf'
        self.run_shell(['configure_dns'], self.dns_defaults() + r'''
configure_dns
mktemp() { [[ "$*" != *.backup.* ]] || return 99; command mktemp "$@"; }
configure_dns
''')
        self.assertEqual(len(list(path.parent.glob('resolv.conf.backup.*'))), 1)
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
PRIMARY_DNS_V4=9.9.9.9 SECONDARY_DNS_V4=149.112.112.112
PRIMARY_DNS_V6=2620:fe::fe SECONDARY_DNS_V6=2620:fe::9
has_ipv6() { return 0; }
configure_dns
''')
        self.assertEqual(path.read_text(), 'nameserver 9.9.9.9\nnameserver 149.112.112.112\nnameserver 2620:fe::fe\nnameserver 2620:fe::9\n')
        self.assertIn('2620:fe::fe / 2620:fe::9', output)

    def test_dns_reloads_mask_already_on_disk(self):
        unit = self.root / 'etc/systemd/system/systemd-resolved.service'
        unit.parent.mkdir(parents=True)
        unit.symlink_to('/dev/null')
        (self.root / 'etc/resolv.conf').write_text('nameserver 1.1.1.1\nnameserver 8.8.8.8\n')
        (self.root / 'dns-immutable').touch()
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
LOAD=loaded
systemctl() {
    case "$1" in
        show) printf 'LoadState=%s\nActiveState=inactive\n' "$LOAD";;
        daemon-reload) LOAD=masked; touch "$ROOT/reloaded";;
        *) return 99;;
    esac
}
configure_dns
''')
        self.assertTrue((self.root / 'reloaded').exists())
        self.assertIn('OK DNS', output)

    def test_dns_resolved_is_replaced_and_masked(self):
        path = self.root / 'etc/resolv.conf'
        path.symlink_to(self.root / 'run/systemd/resolve/stub-resolv.conf')
        output = self.run_shell(['configure_dns'], self.dns_defaults() + r'''
ACTIVE=true
systemctl() {
    printf '%s\n' "$*" >> "$ROOT/calls"
    case "$1" in
        show) printf 'LoadState=%s\nActiveState=%s\n' "$(resolved_load)" "$([[ "$ACTIVE" = true ]] && printf active || printf inactive)";;
        is-active) [[ "$ACTIVE" = true ]];;
        mask) ACTIVE=false; mkdir -p "$ROOT/etc/systemd/system"; ln -sf /dev/null "$ROOT/etc/systemd/system/systemd-resolved.service";;
        daemon-reload|start) return 0;;
        *) return 99;;
    esac
}
configure_dns
''')
        self.assertFalse(path.is_symlink())
        self.assertEqual(path.read_text(), 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n')
        self.assertIn('mask --now systemd-resolved.service', (self.root / 'calls').read_text())
        self.assertIn('OK DNS', output)

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
systemctl() { if [[ "$1" = show ]]; then printf '123\n'; else [[ "${@: -1}" != *.socket ]]; fi; }
''' + f'''ss() {{ if [[ $(< "$ROOT/etc/ssh/sshd_config.d/99-vps-setup.conf") = 'Port 2222' ]]; then printf 'LISTEN 0 128 {endpoint} *:* ino:100 users:(("sshd",pid=123,fd=3))\\n'; fi; }}
if configure_ssh; then exit 9; fi
''')
                self.assertEqual(dropin.read_text(), 'Port 22\n# old\n')

    def test_ssh_config_conflict_does_not_restart_running_service(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\nPort 22\n')
        output = self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
ss() { :; }
systemctl() { printf '%s\n' "$*" >> "$ROOT/calls"; [[ "${@: -1}" != *.socket ]]; }
if configure_ssh; then exit 9; fi
''')
        self.assertIn('Port / ListenAddress 冲突', output)
        self.assertFalse(dropin.exists())
        self.assertNotIn('restart', (self.root / 'calls').read_text())

    def test_ssh_readback_excludes_other_processes(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        output = self.run_shell(['valid_ssh_port', 'ssh_remote_listener', 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
dpkg() { return 0; }
systemctl() {
    case "$1" in
        show) printf '123\n';;
        restart) touch "$ROOT/restarted";;
        *) [[ "${@: -1}" != *.socket ]];;
    esac
}
ss() {
    [[ ! -e "$ROOT/restarted" ]] || printf '%s\n' \
        'LISTEN 0 128 [::]:2222 *:* ino:100 users:(("sshd",pid=123,fd=3))' \
        'LISTEN 0 128 0.0.0.0:2222 *:* ino:555 users:(("other,pid=123,",pid=1234,fd=3))'
}
if configure_ssh; then exit 9; fi
''')
        self.assertIn('未监听新端口', output)
        self.assertTrue((self.root / 'restarted').exists())
        self.assertFalse(dropin.exists())

    def test_ssh_same_port_still_checks_existing_ownership(self):
        config = self.root / 'etc/ssh/sshd_config'
        dropin = self.root / 'etc/ssh/sshd_config.d/99-vps-setup.conf'
        config.write_text(f'Include {dropin.parent}/*.conf\n')
        dropin.write_text('Port 2222\n# old\n')
        output = self.run_shell(['valid_ssh_port', 'configure_ssh'], r'''
non_interactive=true NEW_SSH_PORT=2222 NEW_SSH_PASSWORD=''
sshd() { /usr/sbin/sshd "$@" -f "$ROOT/etc/ssh/sshd_config"; }
systemctl() {
    case "$1" in
        show) printf '123\n';;
        restart) touch "$ROOT/restarted";;
        *) [[ "${@: -1}" != *.socket ]];;
    esac
}
ss() { printf '%s\n' 'LISTEN 0 128 0.0.0.0:2222 *:* ino:555' \
    'LISTEN 0 128 [::]:2222 *:* ino:100 users:(("sshd",pid=123,fd=3))'; }
if configure_ssh; then exit 9; fi
''')
        self.assertIn('已被其他服务占用', output)
        self.assertFalse((self.root / 'restarted').exists())
        self.assertEqual(dropin.read_text(), 'Port 2222\n# old\n')

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
        --show=NAME,PRIO*) [[ ! -f "$ROOT/active" ]] || printf '%s -2\n' "$ROOT/swapfile";;
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
