"""Embedded, root-only SSH setup/control. Never edits the default CrowdSec instance.

The Rust agent stays unprivileged. Only these fixed paths and two owned units
are managed here; neither log content nor engine credentials enter public state.
"""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path('/etc/quiet-guard/ssh')
STATE = pathlib.Path('/var/lib/quiet-guard/ssh')
PROGRAM = pathlib.Path('/usr/local/lib/quiet-guard/quiet-guard')
RECORD = ROOT / 'ownership.json'
PUBLIC = STATE / 'public.json'
HEALTH = pathlib.Path('/run/quiet-guard-ssh/health.json')
ENGINE = 'quiet-guard-ssh-engine.service'
ENFORCER = 'quiet-guard-ssh-enforcer.service'
UNIT_ROOT = pathlib.Path('/etc/systemd/system')
MARKER = 'quiet-guard-ssh-v1'
ASSETS = {}
TRANSACTION = None


def read(path, maximum=262144):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or meta.st_size > maximum:
            raise ValueError('Untrusted owned file: ' + str(path))
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('File grew beyond limit')
        return data


def directory(path, mode):
    if not path.exists():
        path.mkdir(mode=mode)
        path.chmod(mode)
        if TRANSACTION is not None:
            TRANSACTION['directories'].append(path)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('Untrusted directory: ' + str(path))


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.ssh-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if TRANSACTION is not None:
            TRANSACTION['files'][path] = hashlib.sha256(data).hexdigest()
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def save(path, value, mode=0o600):
    atomic(path, json.dumps(value, separators=(',', ':')).encode(), mode)


def command(*args, check=True):
    # Never print captured cscli output: it can contain newly generated keys.
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=40,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root'})
    if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
        raise ValueError('Command output exceeded limit: ' + str(args[0]))
    if check and result.returncode:
        raise RuntimeError('Command failed: ' + str(args[0]) + ' ' + ' '.join(str(x) for x in args[1:2]))
    return result


def system(*args, check=True):
    return command('/usr/bin/systemctl', *args, check=check)


def cscli(*args):
    return command('/usr/bin/cscli', '-c', str(ROOT / 'config.yaml'), *args)


def supported():
    platform = dict(line.split('=', 1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os.uname().machine != 'x86_64' or platform.get('ID', '').strip('"') != 'ubuntu' or platform.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('SSH setup currently supports Ubuntu 24.04 x86_64 only')


def prerequisites():
    for path in ['/usr/bin/crowdsec', '/usr/bin/cscli', '/usr/bin/curl', '/usr/sbin/nft', '/usr/sbin/sshd']:
        if not os.access(path, os.X_OK):
            raise ValueError('Missing prerequisite ' + path + '; see scripts/install_ssh_dependencies.sh')
    version = command('/usr/bin/dpkg-query', '-W', '-f=${Version}', 'crowdsec').stdout.decode().strip()
    if not (version == '1.8.2' or version.startswith('1.8.2-')):
        raise ValueError('This validated SSH rule set requires CrowdSec 1.8.2; existing packages were not changed')


def unit_path(name):
    return UNIT_ROOT / name


def expected_files():
    return {ROOT / 'rules' / name for name in ASSETS if not name.endswith('.service')} | {
        ROOT / name for name in ['config.yaml', 'policy.json', 'local_api_credentials.yaml', 'api.curl',
                                 'acquis.yaml', 'profiles.yaml', 'simulation.yaml', 'console.yaml']
    } | {unit_path(ENGINE), unit_path(ENFORCER)}


def owned():
    record = json.loads(read(RECORD))
    files = record.get('files', {})
    if record.get('marker') != MARKER or set(files) != {str(p) for p in expected_files()}:
        raise ValueError('Unrecognized SSH ownership record; preserving the installation')
    for path, expected in files.items():
        if hashlib.sha256(read(pathlib.Path(path))).hexdigest() != expected:
            raise ValueError('Owned file was changed; preserving it: ' + path)
    return record


def record_files():
    return {str(path): hashlib.sha256(read(path)).hexdigest() for path in sorted(expected_files())}


def policy():
    return json.loads(read(ROOT / 'policy.json', 65536))


def revision():
    value = command(str(PROGRAM), 'ssh-policy', str(ROOT / 'policy.json')).stdout
    return json.loads(value)['revision']


def publish(enabled):
    save(PUBLIC, {'schema': 1, 'marker': MARKER, 'enabled': enabled,
                  'policy_revision': revision()}, 0o644)


def table_exists():
    value = json.loads(command('/usr/sbin/nft', '-j', 'list', 'tables').stdout)
    return any(row.get('table', {}).get('family') == 'inet' and row.get('table', {}).get('name') == 'quiet_guard_ssh'
               for row in value['nftables'])


def wait_ready():
    deadline = time.monotonic() + 25
    started = int(time.clock_gettime(time.CLOCK_BOOTTIME))
    boot_id = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    expected = revision()
    while time.monotonic() < deadline:
        if system('is-active', '--quiet', ENGINE, check=False).returncode == 0 and system('is-active', '--quiet', ENFORCER, check=False).returncode == 0:
            try:
                health = json.loads(read(HEALTH, 65536))
                if health['phase'] == 'verified' and health['policy_revision'] == expected and health['boot_id'] == boot_id and started <= health['boot_seconds'] <= int(time.clock_gettime(time.CLOCK_BOOTTIME)):
                    return
            except (OSError, ValueError, KeyError):
                pass
        time.sleep(0.25)
    raise RuntimeError('SSH engine/firewall did not verify; inspect journalctl -u ' + ENGINE + ' -u ' + ENFORCER)


def start():
    publish(True)
    try:
        system('enable', '--now', ENGINE)
        system('enable', '--now', ENFORCER)
        wait_ready()
    except Exception:
        # Roll back the attempted ON; keep configuration and evidence for retry.
        stop()
        raise


def stop():
    system('disable', '--now', ENFORCER)
    system('disable', '--now', ENGINE)
    if table_exists():
        raise RuntimeError('SSH table remains after stopping; preserving state for inspection')
    publish(False)


def archive_database():
    archive = STATE.parent / ('ssh-archive-' + secrets.token_hex(8))
    directory(archive, 0o700)
    for name in ['crowdsec.db', 'crowdsec.db-shm', 'crowdsec.db-wal', 'crowdsec.db-journal']:
        path = STATE / name
        if os.path.lexists(path):
            meta = path.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
                raise ValueError('Untrusted database file; preserving it: ' + str(path))
            path.rename(archive / name)
    try: STATE.rmdir()
    except OSError: pass  # Keep any files added by the operator at their original path.
    return str(archive)


def ensure_foundation():
    install = json.loads(read(ROOT.parent / 'install.json', 65536))
    digest = hashlib.sha256(read(PROGRAM, 128 * 1024 * 1024)).hexdigest()
    if install.get('marker') != 'quiet-guard-foundation-v1' or install.get('hashes', {}).get('quiet-guard') != digest:
        raise ValueError('Install the verified Quiet Guard foundation before configuring SSH')
    if pathlib.Path(os.environ['QG_POLICY_REVISION_BINARY']).resolve() != PROGRAM:
        raise ValueError('Use the installed Quiet Guard command for privileged setup')


def fresh(args):
    global TRANSACTION
    TRANSACTION = {'files': {}, 'directories': []}
    try:
        create_fresh(args)
    except Exception:
        # Before ON there are no live decisions to retain. Remove only paths
        # created by this attempt whose bytes still match; preserve user edits.
        for path, digest in reversed(list(TRANSACTION['files'].items())):
            try:
                if hashlib.sha256(read(path)).hexdigest() == digest:
                    path.unlink()
            except OSError:
                pass
        if STATE in TRANSACTION['directories']:
            for name in ['crowdsec.db', 'crowdsec.db-shm', 'crowdsec.db-wal', 'crowdsec.db-journal']:
                path = STATE / name
                try:
                    read(path, 128 * 1024 * 1024)
                    path.unlink()
                except OSError:
                    pass
        for path in reversed(TRANSACTION['directories']):
            try: path.rmdir()
            except OSError: pass
        system('daemon-reload', check=False)
        raise
    finally:
        TRANSACTION = None


def create_fresh(args):
    if not args.direct or not args.management_ip:
        raise ValueError('First enable requires --direct and --management-ip IP; shared/jump-host SSH is not supported')
    ports = sorted(set(args.port or [22]))
    ssh_config = command('/usr/sbin/sshd', '-T').stdout.decode()
    ssh_ports = {int(line.split()[1]) for line in ssh_config.splitlines() if line.startswith('port ')}
    if not set(ports).issubset(ssh_ports):
        raise ValueError('Selected ports must be actual ports reported by sshd -T')
    management = sorted({str(ipaddress.ip_address(ip)) for ip in args.management_ip})
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if connection and str(ipaddress.ip_address(connection[0])) not in management:
        raise ValueError('The current SSH client must be included in --management-ip')
    value = {'schema': 1, 'direct_ssh_confirmed': True, 'ports': ports,
             'management_ips': management, 'allow_ips': []}
    # Refuse collisions before creating anything, including an inactive foreign unit.
    if os.path.lexists(ROOT) or os.path.lexists(STATE) or table_exists():
        raise ValueError('Existing unowned SSH paths/table found; preserving them')
    for name in [ENGINE, ENFORCER]:
        if system('show', '--property=FragmentPath', '--value', name).stdout.strip():
            raise ValueError('Existing unowned service: ' + name)
    with socket.socket() as test:
        test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test.bind(('127.0.0.1', 17423))
    directory(ROOT, 0o700)
    directory(STATE, 0o755)
    directory(ROOT / 'rules', 0o700)
    for name in ['parsers', 'parsers/s00-raw', 'parsers/s01-parse', 'parsers/s02-enrich',
                 'scenarios', 'patterns', 'postoverflows', 'contexts', 'hub', 'data']:
        directory(ROOT / 'rules' / name, 0o700)
    for name, text in ASSETS.items():
        if name.endswith('.service'):
            path = unit_path(ENGINE if name == 'engine.service' else ENFORCER)
            atomic(path, text.encode(), 0o644)
        else:
            atomic(ROOT / 'rules' / name, text.encode())
    save(ROOT / 'policy.json', value)
    revision()  # Rust validates canonical addresses, policy limits and direct-path consent.
    save(ROOT / 'acquis.yaml', {'source': 'journalctl', 'journalctl_filter': ['SYSLOG_IDENTIFIER=sshd', 'SYSLOG_IDENTIFIER=sshd-session', '--output=cat'],
                               'labels': {'type': 'sshd'}})
    save(ROOT / 'profiles.yaml', {'name': 'quiet_guard_ssh',
        'filters': ["Alert.Remediation == true && Alert.GetScope() == 'Ip' && Alert.GetScenario() startsWith 'crowdsecurity/ssh-'"],
        'decisions': [{'type': 'ban', 'duration': '10m'}], 'on_success': 'break'})
    save(ROOT / 'simulation.yaml', {'simulation': False})
    save(ROOT / 'console.yaml', {'share_manual_decisions': False, 'share_tainted': False,
                                'share_custom': False, 'share_context': False})
    save(ROOT / 'config.yaml', {
        'common': {'daemonize': False, 'log_media': 'stdout', 'log_level': 'info'},
        'config_paths': {'config_dir': str(ROOT / 'rules'), 'data_dir': str(ROOT / 'rules/data'),
            'simulation_path': str(ROOT / 'simulation.yaml'), 'hub_dir': str(ROOT / 'rules/hub'),
            'index_path': str(ROOT / 'rules/hub/.index.json'), 'notification_dir': str(ROOT / 'rules/notifications'),
            'plugin_dir': str(ROOT / 'rules/plugins')},
        'crowdsec_service': {'acquisition_path': str(ROOT / 'acquis.yaml'), 'parser_routines': 1},
        'cscli': {'output': 'human', 'color': 'never'},
        'db_config': {'type': 'sqlite', 'db_path': str(STATE / 'crowdsec.db'),
                      'flush': {'max_items': 5000, 'max_age': '7d'}},
        'api': {'client': {'credentials_path': str(ROOT / 'local_api_credentials.yaml')},
                'server': {'enable': True, 'listen_uri': '127.0.0.1:17423',
                           'profiles_path': str(ROOT / 'profiles.yaml'), 'console_path': str(ROOT / 'console.yaml'),
                           'disable_remote_lapi_registration': True, 'disable_usage_metrics_export': True,
                           'trusted_ips': ['127.0.0.1', '::1']}},
        'prometheus': {'enabled': False}})
    cscli('machines', 'add', 'quiet-guard-ssh', '--auto', '--force')
    credentials = ROOT / 'local_api_credentials.yaml'
    TRANSACTION['files'][credentials] = hashlib.sha256(read(credentials)).hexdigest()
    token = cscli('bouncers', 'add', 'quiet-guard-ssh', '-o', 'raw').stdout.decode().strip()
    if not 16 <= len(token) <= 256 or not token.isascii() or not all(c.isalnum() or c in '-_+=/' for c in token):
        raise ValueError('Unexpected local API key format')
    atomic(ROOT / 'api.curl', ('header = "X-Api-Key: ' + token + '"\n').encode())
    validation = command('/usr/bin/crowdsec', '-t', '-c', str(ROOT / 'config.yaml'), check=False)
    if validation.returncode:
        diagnostic = (validation.stdout + validation.stderr).decode(errors='replace')[-4000:]
        diagnostic = diagnostic.replace(token, '[redacted]')
        for line in read(ROOT / 'local_api_credentials.yaml').decode().splitlines():
            if line.startswith(('password:', 'login:')):
                secret = line.split(':', 1)[1].strip().strip('\"\'')
                if secret: diagnostic = diagnostic.replace(secret, '[redacted]')
        diagnostic = re.sub(r'(?im)^.*(?:password|api.key).*$','[credential line redacted]',diagnostic)
        raise RuntimeError('CrowdSec configuration validation failed: ' + diagnostic)
    save(RECORD, {'marker': MARKER, 'files': record_files()})
    publish(False)
    system('daemon-reload')


def main():
    global ASSETS
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('Linux root privileges required')
    os.umask(0o077)
    ASSETS = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
    supported()
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['enable', 'disable', 'remove', 'status', 'allow', 'remove-allow', 'unblock'])
    parser.add_argument('ip', nargs='?')
    parser.add_argument('--direct', action='store_true')
    parser.add_argument('--management-ip', action='append')
    parser.add_argument('--port', type=int, action='append')
    args = parser.parse_args()
    lock = os.open('/run/lock/quiet-guard-deploy.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock, 'w') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise ValueError('Untrusted deployment lock')
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ensure_foundation()
        directory(STATE.parent, 0o755)
        prerequisites()
        if args.operation == 'enable' and not RECORD.exists():
            fresh(args)
        owned()  # Verify every owned immutable file before any service mutation.
        if args.operation == 'enable':
            current = policy()
            if args.port and sorted(set(args.port)) != current['ports']:
                raise ValueError('Remove the existing SSH configuration before changing its ports')
            if args.management_ip and sorted({str(ipaddress.ip_address(ip)) for ip in args.management_ip}) != current['management_ips']:
                raise ValueError('Remove the existing SSH configuration before changing management IPs')
            start()
        elif args.operation == 'disable':
            stop()
        elif args.operation == 'status':
            public = json.loads(read(PUBLIC, 65536))
            print(json.dumps({'registered': True, 'enabled': public['enabled'],
                'engine_active': system('is-active', '--quiet', ENGINE, check=False).returncode == 0,
                'enforcer_active': system('is-active', '--quiet', ENFORCER, check=False).returncode == 0,
                'observation': json.loads(read(HEALTH, 65536)) if HEALTH.exists() else None}))
            return
        elif args.operation == 'remove':
            stop()
            record = owned()
            for path in record['files']:
                pathlib.Path(path).unlink()
            RECORD.unlink()
            PUBLIC.unlink()
            archive = archive_database()
            print(json.dumps({'incident_database_archive': archive}))
            system('daemon-reload')
            # Keep the private incident DB archive for inspection; never recursively delete.
            for parent in sorted((p for p in ROOT.rglob('*') if p.is_dir()), reverse=True):
                try: parent.rmdir()
                except OSError: pass
            try: ROOT.rmdir()
            except OSError: pass
        else:
            if not args.ip:
                raise ValueError('An exact IP address is required')
            ip = str(ipaddress.ip_address(args.ip))
            current = policy()
            if args.operation == 'unblock':
                if not json.loads(read(PUBLIC, 65536))['enabled']:
                    raise ValueError('SSH protection is off; unblock never starts it implicitly')
                cscli('decisions', 'delete', '-i', ip)
                system('restart', ENFORCER)
                wait_ready()
            else:
                if args.operation == 'allow':
                    current['allow_ips'] = sorted(set(current['allow_ips']) | {ip})
                else:
                    if ip in current['management_ips']:
                        raise ValueError('Management IP protection cannot be removed with remove-allow')
                    current['allow_ips'] = [entry for entry in current['allow_ips'] if entry != ip]
                was_enabled = json.loads(read(PUBLIC, 65536))['enabled']
                stop()
                old = read(ROOT / 'policy.json')
                save(ROOT / 'policy.json', current)
                try: revision()
                except Exception:
                    atomic(ROOT / 'policy.json', old)
                    raise
                save(RECORD, {'marker': MARKER, 'files': record_files()})
                publish(False)
                if was_enabled: start()
        print(json.dumps({'operation': args.operation, 'completed': True,
                          'scope': 'configured SSH ports only; WAF/exposure checks are not connected'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('SSH setup/control failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
