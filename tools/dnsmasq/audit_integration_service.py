#!/usr/bin/env python3
"""Audit real image init/procd/ujail management in a disposable namespace.

Run under run_isolated.sh. The synthetic profile comes from m2_lifecycle;
no image init script is patched and no physical router is accessed. This
exercises the boot hook and an explicit service event, not a complete boot.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import traceback

from m2_lifecycle import Scenario
from m2_rootfs import sha256


class Audit(Scenario):
    def live(self):
        """Identify the main ELF from the outer namespace, not jail PID 1."""
        expected = sha256(self.root / 'usr/sbin/dnsmasq')
        candidates = []
        for executable in Path('/proc').glob('[0-9]*/exe'):
            try:
                if (os.readlink(executable).endswith('/usr/sbin/dnsmasq')
                        and sha256(executable) == expected):
                    candidates.append(int(executable.parent.name))
            except OSError:
                pass
        return min(candidates) if candidates else None

    def snapshot(self):
        pid = self.live()
        pidfile = self.root / 'var/run/dnsmasq/dnsmasq.m2.pid'
        return {
            'pid': pid,
            'pidfile': pidfile.read_text() if pidfile.exists() else None,
            'service': self.bus('service', 'list', {'name': 'dnsmasq', 'verbose': True}),
            'elf_sha256': sha256(Path('/proc') / str(pid) / 'exe') if pid else None,
        }

    def save(self):
        (self.out / 'result.json').write_text(json.dumps(self.result, indent=2) + '\n')

    def step(self, name, operation):
        started = time.monotonic()
        try:
            value = operation()
            row = {'ok': True, 'value': value}
        except Exception:
            row = {'ok': False, 'error': traceback.format_exc()}
        row['seconds'] = round(time.monotonic() - started, 3)
        self.result['steps'][name] = row
        self.save()
        return row

    def dns_matches(self, name, address):
        return any(record.get('data') == address for record in self.dns(name)['records'])

    def execute(self):
        self.result = {
            'implementation': self.args.implementation,
            'init_unmodified': True,
            'boot_scope': 'boot hook before netifd, then explicit service.event; not complete boot',
            'steps': {},
        }
        self.start('/sbin/ubusd')
        self.wait(lambda: self.run('/bin/ubus', 'list', check=False).returncode == 0, 'ubusd')
        for executable, obj in [('/sbin/logd', 'log'), ('/sbin/procd', 'service')]:
            self.start(executable)
            self.wait(lambda obj=obj: self.run('/bin/ubus', 'list', obj, check=False).returncode == 0, obj)

        self.run('/etc/init.d/dnsmasq', 'boot')
        self.step('boot_before_netifd', lambda: self.expect_dns('lifecycle.lan', '192.0.2.51'))
        self.result['boot_config'] = (self.root / 'var/etc/dnsmasq.conf.m2').read_text()
        self.start('/sbin/netifd')
        self.wait(lambda: self.bus('network.interface.lan', 'status', check=False).get('up'), 'netifd')
        self.bus('service', 'event', {'type': 'interface.update', 'data': {'interface': 'lan'}})
        self.step('explicit_interface_event_after_boot', lambda: self.wait(
            lambda: 'dhcp-range=' in (self.root / 'var/etc/dnsmasq.conf.m2').read_text(),
            'DHCP range after service event'))
        self.step('init_start', lambda: self.expect_dns('lifecycle.lan', '192.0.2.51'))
        self.result['initial'] = self.snapshot()
        self.result['generated_config'] = (self.root / 'var/etc/dnsmasq.conf.m2').read_text()
        first = self.live()
        if first is None:
            raise RuntimeError('daemon not started')
        proc = Path('/proc') / str(first)
        self.result['identity'] = {
            'elf_sha256': sha256(proc / 'exe'),
            'init_sha256': sha256(self.root / 'etc/init.d/dnsmasq'),
            'root': os.readlink(proc / 'root'),
            'proc_mounted': (proc / 'root/proc/self').exists(),
            'nspid': [line for line in (proc / 'status').read_text().splitlines() if line.startswith('NSpid')],
        }
        hosts = '127.0.0.1 localhost\n192.0.2.52 lifecycle.lan\n'
        (self.root / 'etc/hosts').write_text(hosts)
        (self.root / 'tmp/hosts/dhcp').write_text('192.0.2.52 lifecycle.lan\n')
        self.run('/etc/init.d/dnsmasq', 'reload')
        self.step('init_reload_hosts', lambda: self.expect_dns('lifecycle.lan', '192.0.2.52'))
        self.result['reload_keeps_actual_pid'] = first == self.live()

        self.run('/sbin/uci', 'add_list', 'dhcp.m2.address=/edit.audit/192.0.2.60')
        self.run('/sbin/uci', 'commit', 'dhcp')
        self.run('/etc/init.d/dnsmasq', 'reload')
        self.step('changed_config_reload', lambda: self.expect_dns('edit.audit', '192.0.2.60'))
        self.result['config_change_restarts_actual_pid'] = first != self.live()
        for name in ['SIGKILL', 'SIGTERM']:
            pid = self.live()
            os.kill(pid, getattr(signal, name))
            self.step(name + '_recovery', lambda pid=pid: self.wait(
                lambda: self.live() and self.live() != pid and self.dns_matches('edit.audit', '192.0.2.60'),
                'respawn', seconds=12))
            self.result[name + '_after'] = self.snapshot()

        pid = self.live()
        os.kill(pid, signal.SIGSTOP)
        time.sleep(6)
        try:
            self.dns('edit.audit')
            answered = True
        except OSError:
            answered = False
        self.result['SIGSTOP_after_6s'] = {
            'same_pid': self.live() == pid,
            'dns_responded': answered,
            'service': self.bus('service', 'list', {'name': 'dnsmasq'}),
        }
        os.kill(pid, signal.SIGCONT)
        self.step('SIGCONT_health', lambda: self.expect_dns('edit.audit', '192.0.2.60'))
        self.run('/etc/init.d/dnsmasq', 'stop')
        self.step('init_stop', lambda: self.wait(
            lambda: self.live() is None and not self.bus('service', 'list', {'name': 'dnsmasq'}),
            'stopped', seconds=12))
        self.result['after_stop'] = self.snapshot()

        # A new procd instance resets its rapid-exit counter.
        self.run('/etc/init.d/dnsmasq', 'start')
        self.expect_dns('edit.audit', '192.0.2.60')
        self.result['rapid_kills'] = []
        for index in range(6):
            pid = self.live()
            os.kill(pid, signal.SIGKILL)
            started = time.monotonic()
            while time.monotonic() - started < 7:
                replacement = self.live()
                if replacement and replacement != pid:
                    break
                time.sleep(.1)
            self.result['rapid_kills'].append({
                'n': index + 1,
                'restarted': bool(replacement and replacement != pid),
                'seconds': round(time.monotonic() - started, 3),
                'pid': replacement,
            })
        self.result['after_crash_loop'] = self.snapshot()
        self.result['logread'] = self.run('/sbin/logread', check=False).stdout
        self.result['passed_management_steps'] = all(row['ok'] for row in self.result['steps'].values())
        self.save()
        return self.result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image-root', type=Path, required=True)
    parser.add_argument('--rust-binary', type=Path, required=True)
    parser.add_argument('--implementation', choices=['c', 'rust'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('DNSMASQ_TEST_ISOLATED') != '1' or os.geteuid() != 0:
        parser.error('run under sudo -n sh tools/dnsmasq/run_isolated.sh')
    args.jail_procfs, args.skip_odhcpd = False, True
    for command in [
        ['ip', 'link', 'add', 'br-lan', 'type', 'bridge'],
        ['ip', 'addr', 'add', '192.168.1.1/24', 'dev', 'br-lan'],
        ['ip', 'link', 'set', 'br-lan', 'up'],
    ]:
        subprocess.run(command, check=True)
    scenario = Audit(args)
    try:
        result = scenario.execute()
    except Exception:
        result = getattr(scenario, 'result', {})
        result['fatal'] = traceback.format_exc()
        result['passed_management_steps'] = False
    finally:
        scenario.close()
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'passed_management_steps': result['passed_management_steps'], 'fatal': result.get('fatal')}))
    return 0 if result['passed_management_steps'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
