#!/usr/bin/env python3
"""Read-only daemon mock derived from the REAL merged parser dump.
No connection to Fail2ban's socket or execution of firewall actions.
"""
import ast
import subprocess
import sys

config, *args = sys.argv[1:]
dump = subprocess.check_output(['/usr/bin/fail2ban-client', '-c', config, '-d'], text=True)
commands = [ast.literal_eval(line) for line in dump.splitlines()]
if ['start', 'sshd'] not in commands:
    sys.exit(1)
if args == ['status', 'sshd']:
    print('Status for the jail: sshd')
elif args[:2] == ['get', 'sshd']:
    key = args[2]
    if key == 'actions':
        print('The jail sshd has the following actions:')
        print(', '.join(x[3] for x in commands if x[:3] == ['set', 'sshd', 'addaction']))
    elif key == 'action':
        for x in commands:
            if x[:4] == ['multi-set', 'sshd', 'action', args[3]]:
                print(dict(x[4])[args[4]])
                break
        else: sys.exit(1)
    else:
        if key == 'journalmatch' and ['add', 'sshd', 'systemd'] not in commands:
            print('No journal match filter for jail sshd')
            sys.exit(0)
        lookup = 'addjournalmatch' if key == 'journalmatch' else key
        for x in commands:
            if x[:3] == ['set', 'sshd', lookup]:
                print(' '.join(map(str, x[3:])))
                break
        else: sys.exit(1)
else:
    sys.exit(99)
