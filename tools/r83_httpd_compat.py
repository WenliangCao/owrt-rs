#!/usr/bin/env python3
"""R81 F20 differential: auth/options/SSE, queues, slow headers and TLS relay.

Only disposable rootfs copies and loopback ports are used. TLS keys, raw
captures and process observations are temporary and must not be committed.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
import r14_httpd_check as base


RUNNER = r'''
set -eu
root=$1; impl=$2; port=$3
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
trap 'umount "$root/dev" "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh -s "$impl" "$port" <<'INNER'
set -eu
impl=$1; port=$2
mkdir -p /var/run/ubus /var/lock /var/state /tmp/out
pids=''
cleanup() { kill $pids 2>/dev/null || true; }
trap cleanup EXIT
/sbin/ubusd >/tmp/out/bus.log 2>&1 & pids="$pids $!"
sleep 1
/sbin/rpcd >/tmp/out/rpcd.log 2>&1 & pids="$pids $!"
sleep 1
if [ "$impl" = c ]; then server=/usr/sbin/uhttpd; else server=/tmp/httpd-rs; fi
start() {
    name=$1; shift
    "$server" -f -h /www -x /cgi-bin -k 20 "$@" >"/tmp/out/$name.log" 2>&1 &
    pid=$!; pids="$pids $pid"; echo "$pid" >"/tmp/out/$name.pid"
}
start flags -p "127.0.0.1:$port" -u /ubus -X -e 1500 -c /etc/r83-httpd.conf -r R83 \
    -I home.txt -i .cli=/bin/sh -y /alias=/cgi-bin -b ISO-8859-1 -n 1 -S -A 2 -T 4 -t 5
start cap -p "127.0.0.1:$((port+1))" -N 2 -T 2 -t 5
start unlimited -p "127.0.0.1:$((port+2))" -N 0 -T 2 -t 5
start zero -p "127.0.0.1:$((port+3))" -t 0 -T 2
start events -p "127.0.0.1:$((port+4))" -u /ubus -a -X -e 1500 -T 4
start tls -s "127.0.0.1:$((port+5))" -p "127.0.0.1:$((port+6))" -q \
    -C /tmp/r83-cert.der -K /tmp/r83-key.der -P TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256 -T 4 -t 10
start queued -p "127.0.0.1:$((port+7))" -n 0 -T 2
# Invalid TLS setup must fail startup, including when HTTP is also configured.
"$server" -f -h /www -p "127.0.0.1:$((port+8))" -s "127.0.0.1:$((port+9))" \
    -C /tmp/missing-cert -K /tmp/missing-key >/tmp/out/invalid-tls.log 2>&1 &
bad=$!
sleep 1
if kill -0 "$bad" 2>/dev/null; then
    echo alive >/tmp/out/invalid-tls-result
    kill "$bad" 2>/dev/null || true
else
    echo exited >/tmp/out/invalid-tls-result
fi
touch /tmp/out/ready
while [ ! -f /tmp/out/stop ]; do sleep 1; done
INNER
'''


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def sudo(*args):
    return subprocess.run(['sudo', '-n', *map(str, args)], capture_output=True, check=True)


def put(root, name, data, executable=False):
    path = root / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o755 if executable else 0o644)
    os.utime(path, (1600000000, 1600000000))


def fixtures(temp, root, notifier):
    secret_hash = subprocess.check_output(['openssl', 'passwd', '-6', '-salt', 'r83fixture', 'secret']).decode().strip()
    config = ('/private:user:secret\n/hashed:user:' + secret_hash + '\n'
              '/locked:locked:$p$r83locked\n/missing:nope:$p$r83nosuch\n/empty:empty:$p$r83empty\n'
              'I:default.foo\nE404:/cgi-bin/error\n*.run:/bin/sh\n')
    put(root, '/etc/r83-httpd.conf', config)
    with (root / 'etc/passwd').open('a') as f:
        f.write('r83locked:x:1234:1234::/tmp:/bin/sh\nr83empty:x:1235:1235::/tmp:/bin/sh\n')
    with (root / 'etc/shadow').open('a') as f:
        f.write('r83locked:*:0:0:99999:7:::\nr83empty::0:0:99999:7:::\n')
    for path in ('plain.txt', 'private/secret.txt', 'hashed/secret.txt', 'locked/secret.txt',
                 'missing/secret.txt', 'empty/secret.txt', 'list/a.txt'):
        put(root, '/www/' + path, 'r83-content\n')
    put(root, '/www/home.txt', 'custom-index\n')
    put(root, '/www/config-index/default.foo', 'config-index\n')
    script = "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'\n"
    env = script + "printf 'user=%s pass=%s redirect=%s https=%s\\n' \"${HTTP_AUTH_USER-unset}\" \"${HTTP_AUTH_PASS-unset}\" \"$REDIRECT_STATUS\" \"${HTTPS-unset}\"\n"
    for path in ('cgi-bin/env', 'private/auth.cli', 'interpreted.run', 'cli.cli', 'cgi-bin/alias/test'):
        put(root, '/www/' + path, env, executable=path.startswith('cgi-bin'))
    put(root, '/www/cgi-bin/error', "#!/bin/sh\nprintf 'Status: 404 Not Found\\r\\nContent-Type: text/plain\\r\\n\\r\\nredirect=%s\\n' \"$REDIRECT_STATUS\"\n", True)
    put(root, '/www/cgi-bin/slow', "#!/bin/sh\nsleep 1\nprintf 'Content-Type: text/plain\\r\\n\\r\\nslow\\n'\n", True)
    put(root, '/www/cgi-bin/large', script + 'dd if=/dev/zero bs=65536 count=2048 2>/dev/null\n', True)
    put(root, '/tmp/outside', 'outside\n')
    (root / 'www/inside').symlink_to('/www/plain.txt')
    (root / 'www/outside').symlink_to('/tmp/outside')
    put(root, '/tmp/notifier', notifier.read_bytes(), True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=r83-fixture', '-keyout', str(temp / 'key.pem'), '-out', str(temp / 'cert.pem')],
                   check=True, capture_output=True)
    subprocess.run(['openssl', 'x509', '-in', str(temp / 'cert.pem'), '-outform', 'DER', '-out', str(root / 'tmp/r83-cert.der')], check=True)
    subprocess.run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(temp / 'key.pem'), '-outform', 'DER',
                    '-out', str(root / 'tmp/r83-key.der')], check=True)
    # The listing includes its parent directory's mtime; freeze the fixture
    # directories after creating their children, as well as the files above.
    for directory in [root / 'www', *(root / 'www').rglob('*')]:
        if not directory.is_symlink() and directory.is_dir():
            os.utime(directory, (1600000000, 1600000000))


def request(port, path='/plain.txt', headers=None, context=None):
    conn = (http.client.HTTPSConnection('127.0.0.1', port, timeout=6, context=context) if context
            else http.client.HTTPConnection('127.0.0.1', port, timeout=6))
    try:
        conn.request('GET', path, headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        selected = {k.lower(): v for k, v in response.getheaders() if k.lower() in
                    ('content-type', 'location', 'www-authenticate', 'access-control-allow-origin')}
        return response.status, selected, body
    finally:
        conn.close()


def raw_connect(port, request_bytes):
    sock = socket.create_connection(('127.0.0.1', port), timeout=5)
    sock.sendall(request_bytes)
    return sock


GET = b'GET /plain.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'


def fd_count(pid):
    return len(sudo('ls', '-1', f'/proc/{pid}/fd').stdout.splitlines())


def unix_sockets(pid):
    links = sudo('ls', '-l', f'/proc/{pid}/fd').stdout.decode()
    sockets = set(re.findall(r'socket:\[(\d+)\]', links))
    unix = {line.split()[6] for line in Path('/proc/net/unix').read_text().splitlines()[1:]}
    return sockets & unix


def rss(pid):
    text = Path(f'/proc/{pid}/status').read_text()
    return int(next(line.split()[1] for line in text.splitlines() if line.startswith('VmRSS:')))


def ubus(root, obj, method, args):
    output = sudo('chroot', root, '/bin/ubus', '-S', 'call', obj, method, json.dumps(args)).stdout
    return json.loads(output) if output.strip() else None


def notifier_start(root):
    provider = subprocess.Popen(['sudo', '-n', 'chroot', str(root), '/tmp/notifier', 'r83.events', 'update', 'value=hello'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        result = subprocess.run(['sudo', '-n', 'chroot', str(root), '/bin/ubus', 'list', 'r83.events'], capture_output=True)
        if result.returncode == 0 and b'r83.events' in result.stdout:
            return provider
        time.sleep(.03)
    provider.wait(timeout=6)
    raise AssertionError('notification provider did not register')


def sse(root, port, auth=None):
    provider = notifier_start(root)
    try:
        headers = {'Origin': 'https://fixture.invalid'}
        if auth:
            headers['Authorization'] = 'Bearer ' + auth
        result = request(port, '/ubus/subscribe/r83.events', headers)
        require(result[0] == 200 and result[1].get('content-type') == 'text/event-stream', 'SSE registration failed')
        require(result[1].get('access-control-allow-origin') == 'https://fixture.invalid', 'SSE CORS header missing')
        require(result[2] == b'retry: 1500\nevent: update\ndata: {"value":"hello"}\n\n', 'SSE event/retry payload differs')
        return result
    finally:
        provider.wait(timeout=6)


def run_side(rootfs, binary, notifier, side, port):
    with base.disposable_rootfs(rootfs, binary) as (temp, root):
        fixtures(temp, root, notifier)
        (root / 'tmp/out').mkdir(exist_ok=True)
        script = temp / 'run.sh'
        script.write_text(RUNNER)
        log = temp / 'runner.log'
        with log.open('w') as output:
            proc = subprocess.Popen(['sudo', '-n', 'unshare', '--mount', '--fork', 'sh', str(script), str(root), side, str(port)],
                                    stdout=output, stderr=subprocess.STDOUT)
        results = {}
        try:
            for _ in range(80):
                if (root / 'tmp/out/ready').exists():
                    break
                time.sleep(.1)
            require((root / 'tmp/out/ready').exists(), 'sandbox startup failed: ' + log.read_text()[-800:])
            auth = 'Basic ' + base64.b64encode(b'user:secret').decode()
            cases = [('custom-index', '/', None, 200), ('config-index', '/config-index/', None, 200),
                     ('auth-denied', '/private/secret.txt', None, 401),
                     ('auth-ok', '/private/secret.txt', {'Authorization': auth}, 200),
                     ('hash-auth', '/hashed/secret.txt', {'Authorization': auth}, 200),
                     ('locked-account', '/locked/secret.txt', {'Authorization': 'Basic ' + base64.b64encode(b'locked:*').decode()}, 401),
                     ('missing-account', '/missing/secret.txt', None, 401), ('empty-account', '/empty/secret.txt', None, 200),
                     ('auth-cgi', '/private/auth.cli', {'Authorization': auth}, 200),
                     ('forged-auth-env', '/cgi-bin/env', {'Http-Auth-User': 'forged', 'Http-Auth-Pass': 'forged'}, 200),
                     ('config-interpreter', '/interpreted.run', None, 200), ('cli-interpreter', '/cli.cli', None, 200),
                     ('alias', '/alias/test', None, 200), ('charset', '/list/', None, 200),
                     ('inside-symlink', '/inside', None, 200), ('outside-symlink', '/outside', None, 404),
                     ('error-handler', '/does-not-exist?x=1', None, 404), ('sse-denied', '/ubus/subscribe/r83.events', None, 200)]
            for name, path, headers, status in cases:
                results[name] = request(port, path, headers)
                require(results[name][0] == status, f'{side} {name}: status {results[name][0]}, expected {status}')
            require(b'user=user pass=secret' in results['auth-cgi'][2], 'CGI authenticated credentials missing')
            require(results['charset'][1].get('content-type') == 'text/html; charset=ISO-8859-1', '-b was ignored')
            require(results['sse-denied'][2] == b'{"code":-13,"message":"Permission denied"}',
                    'SSE ACL denial differs: ' + repr(results['sse-denied']))
            require((root / 'tmp/out/invalid-tls-result').read_text().strip() == 'exited', 'invalid TLS configuration did not fail startup')
            results['invalid-tls'] = 'startup failed as expected'

            # CGI execution slots must serialize scripts while static files stay responsive.
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                start = time.monotonic()
                jobs = [pool.submit(request, port, '/cgi-bin/slow') for _ in range(2)]
                time.sleep(.15)
                fast = time.monotonic()
                require(request(port)[0] == 200 and time.monotonic() - fast < 1, 'CGI blocked static serving')
                require(all(job.result()[2] == b'slow\n' for job in jobs), 'queued CGI failed')
                require(1.8 <= time.monotonic() - start < 5, '-n 1 did not serialize CGI')
            results['cgi-slots'] = 'two scripts serialized; static request served'
            require(request(port + 3, '/cgi-bin/slow')[2] == b'slow\n', '-t 0 did not disable the script timeout')
            results['zero-script-timeout'] = 'script completed with timeout disabled'

            holders = [raw_connect(port + 1, b'GET /') for _ in range(2)]
            queued = raw_connect(port + 1, GET)
            try:
                queued.settimeout(.25)
                try:
                    early = queued.recv(1)
                    raise AssertionError('connection cap accepted/dropped a queued request: ' + repr(early))
                except socket.timeout:
                    pass
                holders.pop().close()
                queued.settimeout(3)
                require(b'200 OK' in queued.recv(4096), 'backlog request not served after a slot freed')
            finally:
                queued.close()
                for sock in holders: sock.close()
            results['connection-cap'] = 'backlog preserved and resumed'
            holders = [raw_connect(port + 2, b'GET /') for _ in range(4)]
            try:
                require(request(port + 2)[0] == 200, '-N 0 refused clients')
            finally:
                for sock in holders: sock.close()
            results['unlimited'] = 'four partial clients plus a served request'

            time.sleep(.3)
            holders = [raw_connect(port + 1, b'GET /') for _ in range(2)]
            stop = threading.Event()
            def drip():
                while not stop.wait(.35):
                    for sock in holders:
                        try: sock.sendall(b'x')
                        except OSError: pass
            thread = threading.Thread(target=drip)
            thread.start()
            start = time.monotonic()
            try:
                require(request(port + 1)[0] == 200 and time.monotonic() - start < 3.5, 'slow headers extended the overall deadline')
            finally:
                stop.set(); thread.join()
                for sock in holders: sock.close()
            results['head-deadline'] = 'dribbling clients expired within deadline'

            queued_pid = int((root / 'tmp/out/queued.pid').read_text())
            before = fd_count(queued_pid)
            sock = raw_connect(port + 7, b'GET /cgi-bin/slow HTTP/1.1\r\nHost: localhost\r\n\r\n')
            time.sleep(.15); sock.close(); time.sleep(.6)
            require(fd_count(queued_pid) <= before, '-n 0 leaked a disconnected queued client')
            results['queued-disconnect'] = 'slot and fd released'

            results['sse-noauth'] = sse(root, port + 4)
            sid = ubus(root, 'session', 'create', {})['ubus_rpc_session']
            ubus(root, 'session', 'grant', {'ubus_rpc_session': sid, 'scope': 'ubus', 'objects': [['r83.events', ':subscribe']]})
            results['sse-bearer'] = sse(root, port, sid)

            events_pid = int((root / 'tmp/out/events.pid').read_text())
            require('login' in json.loads(request(port + 4, '/ubus/list/session')[2]), 'ubus lookup failed')
            time.sleep(.1)
            sockets = unix_sockets(events_pid)
            require(sockets, 'no persistent ubus connection after lookup')
            for _ in range(20):
                require('login' in json.loads(request(port + 4, '/ubus/list/session')[2]), 'repeated ubus lookup failed')
                require(unix_sockets(events_pid) == sockets, 'sequential requests did not reuse the ubus connection')
            results['ubus-reuse'] = '20 requests reused the same Unix socket'

            baseline_fds = fd_count(events_pid)
            provider = notifier_start(root)
            try:
                for _ in range(12):
                    sock = raw_connect(port + 4, b'GET /ubus/subscribe/r83.events HTTP/1.1\r\nHost: localhost\r\n\r\n')
                    try:
                        reply = b''
                        while b'\r\n\r\n' not in reply:
                            part = sock.recv(4096)
                            require(part, 'SSE closed before sending headers')
                            reply += part
                        require(b'text/event-stream' in reply.lower(), 'SSE disconnect fixture did not subscribe')
                        sock.shutdown(socket.SHUT_RDWR)
                    finally:
                        sock.close()
                time.sleep(.3)
                require(provider.poll() is None, 'SSE provider exited before disconnect cleanup was checked')
                # The reference retains clients until its subscribed object
                # disappears. The candidate must also release idle streams
                # on HTTP disconnect, while that object is still alive.
                if side == 'rs':
                    require(fd_count(events_pid) <= baseline_fds, 'disconnected SSE clients leaked descriptors')
                    require(unix_sockets(events_pid) == sockets, 'disconnected SSE clients leaked ubus connections')
            finally:
                provider.wait(timeout=6)
            time.sleep(.3)
            retained = fd_count(events_pid) - baseline_fds
            if side == 'rs':
                require(retained <= 0, 'SSE descriptors remained after object removal')
                require(unix_sockets(events_pid) == sockets, 'SSE ubus connections remained after object removal')
            results['sse-disconnect-fds'] = retained

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            context.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')
            results['tls-static'] = request(port + 5, context=context)
            results['tls-redirect'] = request(port + 6, '/plain.txt?x=1', {'Host': 'fixture.invalid'})
            require(results['tls-static'][0] == 200 and results['tls-static'][2] == b'r83-content\n', 'TLS static response failed')
            require(results['tls-redirect'][0] == 307 and results['tls-redirect'][1]['location'] ==
                    f'https://fixture.invalid:{port+5}/plain.txt?x=1', '-q redirect differs')
            tls_pid = int((root / 'tmp/out/tls.pid').read_text())
            baseline = rss(tls_pid)
            raw = socket.socket()
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            raw.settimeout(5)
            raw.connect(('127.0.0.1', port + 5))
            sock = context.wrap_socket(raw, server_hostname='fixture.invalid')
            try:
                require(sock.cipher()[0] == 'ECDHE-RSA-AES128-GCM-SHA256', '-P cipher selection ignored')
                sock.sendall(b'GET /cgi-bin/large HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n')
                head = sock.recv(4096)
                require(b'200 OK' in head, 'large TLS CGI did not start')
                samples = []
                for _ in range(10):
                    time.sleep(.2)
                    samples.append(rss(tls_pid))
                growth = max(samples) - baseline
                require(growth < 8 * 1024, f'TLS slow client buffered too much: RSS +{growth} KiB')
            finally:
                sock.close()
            require(request(port + 5, context=context)[0] == 200, 'TLS server failed after slow client left')
            results['tls-backpressure'] = '128 MiB CGI, slow reader, RSS growth below 8 MiB'
            print(f'{side}: {len(results)} checks passed, TLS slow-reader RSS growth {growth} KiB', flush=True)
            return results
        except Exception:
            for path in sorted((root / 'tmp/out').glob('*.log')):
                print(path.name, path.read_text(errors='replace')[-700:], file=os.sys.stderr)
            raise
        finally:
            (root / 'tmp/out/stop').touch()
            try: proc.wait(timeout=15)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rootfs', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('notifier', type=Path)
    parser.add_argument('--port', type=int, default=28400)
    args = parser.parse_args()
    a = run_side(args.rootfs.resolve(), args.candidate.resolve(), args.notifier.resolve(), 'c', args.port)
    b = run_side(args.rootfs.resolve(), args.candidate.resolve(), args.notifier.resolve(), 'rs', args.port)
    # A resource gate on the candidate, separate from wire compatibility:
    # the exact C reference retains disconnected subscriptions in this case.
    c_retained, rs_retained = a.pop('sse-disconnect-fds'), b.pop('sse-disconnect-fds')
    print(f'SSE disconnect resource gate: C retained {c_retained} fds; Rust retained {rs_retained} fds')
    differences = [key for key in a if a[key] != b.get(key)]
    for key in differences:
        print(key, 'C:', a[key], 'Rust:', b.get(key))
    require(not differences, 'httpd compatibility differences: ' + ', '.join(differences))
    print(f'r83 httpd extended compatibility: {len(a)}/{len(a)} PASS')
    print('r83 httpd disconnected SSE cleanup: PASS')


if __name__ == '__main__':
    main()
