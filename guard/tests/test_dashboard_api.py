"""Real dashboard integration; no fixtures impersonate successful protection."""
import http.client
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

BASE = '127.0.0.1:9417'
ORIGIN = 'http://' + BASE
TOKEN_PATH = Path('/etc/quiet-guard/dashboard/access-token')
TOKEN = TOKEN_PATH.read_text()


def request(path='/api/state', body=None, *, token=TOKEN, headers=None, method=None):
    data = json.dumps(body) if isinstance(body, dict) else body
    h = {'Host': BASE, 'Origin': ORIGIN, 'Content-Type': 'application/json'}
    if token is not None:
        h['Authorization'] = 'Bearer ' + token
    if headers:
        for key, value in headers.items():
            if value is None:
                h.pop(key, None)
            else:
                h[key] = value
    conn = http.client.HTTPConnection('127.0.0.1', 9417, timeout=8)
    conn.request(method or ('POST' if body is not None else 'GET'), path, data, h)
    reply = conn.getresponse()
    status, raw, fields = reply.status, reply.read(), {k.lower(): v for k, v in reply.getheaders()}
    conn.close()
    # Never include raw bodies/headers in failures: they can contain secrets.
    return status, raw, fields


def state():
    status, raw, _ = request()
    assert status == 200, ('state HTTP status', status)
    assert TOKEN.encode() not in raw
    return json.loads(raw)


def job(action, limit=80):
    status, raw, _ = request('/api/actions', action)
    assert status == 202, ('start action HTTP status', status)
    job_id = json.loads(raw)['id']
    end = time.monotonic() + limit
    while time.monotonic() < end:
        current = next(j for j in state()['jobs'] if j['id'] == job_id)
        if current['status'] != 'running':
            if current['status'] != 'succeeded':
                # Emit bounded sanitized diagnostics, never an access token.
                print(current.get('output', '').replace(TOKEN, '[redacted]')[:4000])
            assert current['status'] == 'succeeded', (action['action'], current['status'])
            return current
        time.sleep(.3)
    raise AssertionError('Administrative job did not finish within test budget')


def main():
    if len(sys.argv) > 1:
        old = Path('/root/quiet-guard-test-old-token').read_text()
        assert old != TOKEN and request(token=old)[0] == 401
        Path('/root/quiet-guard-test-old-token').unlink()
        assert state()['configured']['exposure']
        return
    assert request(token=None)[0] == 401
    assert request(token='0' * 64)[0] == 401
    assert request(headers={'Host': 'evil.example'})[0] == 403
    assert request(headers={'Origin': 'https://evil.example'})[0] == 403
    assert request(headers={'Sec-Fetch-Site': 'cross-site'})[0] == 403
    assert request('/api/actions', {'action': 'exposure_enable'}, headers={'Origin': None})[0] == 403
    assert request('/api/actions', {'action': 'agent_restart', 'command': 'touch /tmp/bypass'})[0] == 422
    assert request('/api/actions', {'action': 'ssh_disable', 'confirmed': False})[0] == 400
    assert request('/api/actions', {'action': 'not_an_action'})[0] == 422
    assert request('/api/actions', ' ' * 33000)[0] == 413
    assert not Path('/tmp/bypass').exists()
    status, raw, fields = request('/', token=None)
    assert status == 200 and b'Quiet Guard' in raw
    assert fields['cache-control'] == 'no-store'
    assert "frame-ancestors 'none'" in fields['content-security-policy']
    assert request('/app.js', token=None)[0] == 200
    assert request('/fonts/suit.woff2', token=None)[0] == 200
    assert request('/etc/quiet-guard/dashboard/access-token', token=None)[0] == 404
    assert request('/api/state?access=' + TOKEN, token=None)[0] == 401
    pid = subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', 'quiet-guard-dashboard.service'], text=True).strip()
    proc = Path('/proc/' + pid + '/status').read_text()
    assert int(next(x for x in proc.splitlines() if x.startswith('Uid:')).split()[1]) != 0
    assert int(next(x for x in proc.splitlines() if x.startswith('CapEff:')).split()[1], 16) == 0
    listeners = subprocess.check_output(['ss', '-lntp'], text=True)
    assert '127.0.0.1:9417' in listeners and '0.0.0.0:9417' not in listeners and '[::]:9417' not in listeners
    assert subprocess.run(['runuser', '-u', 'nobody', '--', 'cat', str(TOKEN_PATH)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
    # The world-connectable local socket still requires authentication.
    for payload in [b'{', json.dumps({'token': '0' * 64, 'request': {'operation': 'snapshot'}}).encode()]:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect('/run/quiet-guard-control/control.sock')
            client.sendall(struct.pack('!I', len(payload)) + payload)
            assert client.recv(4) == b''
    assert state()['agent']['protection'] != 'protected'
    # Cold package preparation uses the same bounded privileged path as the UI.
    job({'action': 'prepare_dependencies'}, 850)
    assert all(state()['prerequisites'].values())
    assert not state()['configured']['ssh'] and not state()['configured']['waf']
    job({'action': 'exposure_enable'})
    job({'action': 'exposure_check'})
    assert state()['listeners'] and state()['configured']['exposure']
    job({'action': 'agent_restart'})
    saved = Path('/var/lib/quiet-guard/dashboard/jobs.json').read_text()
    assert TOKEN not in saved and all(not j['output'] for j in json.loads(saved))
    job({'action': 'exposure_disable'})
    job({'action': 'exposure_enable'})
    Path('/root/quiet-guard-test-old-token').write_text(TOKEN)
    os.chmod('/root/quiet-guard-test-old-token', 0o600)
    print('PASS: real authenticated administrative API; no request can select a program or shell')


if __name__ == '__main__':
    main()
