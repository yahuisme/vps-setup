#!/usr/bin/env python3
"""Extracted Swap/DNS transactions; all mutators private/mocked, real signals.
Run under hermes-vps-audit.slice with PYTHONDONTWRITEBYTECODE=1.
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
        self.assertIn('hermes-vps-audit.slice/', Path('/proc/self/cgroup').read_text())
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
