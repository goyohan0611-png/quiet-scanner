#!/usr/bin/env python3
"""Root bootstrap. Verify using system OpenSSL BEFORE running a downloaded binary.

Only fixed product paths are mutated. Keys supplied at first installation must
come from an independently trusted source; never trust a key from the bundle.
"""
import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import time

PROGRAM = pathlib.Path('/usr/local/lib/quiet-guard/quiet-guard')
UNIT = pathlib.Path('/etc/systemd/system/quiet-guard.service')
LINK = pathlib.Path('/usr/local/bin/quiet-guard')
CONFIG = pathlib.Path('/etc/quiet-guard')
RECORD = CONFIG / 'install.json'
KEY = CONFIG / 'release-public.pem'
MARKER = 'quiet-guard-foundation-v1'
PAYLOADS = {'quiet-guard': PROGRAM, 'quiet-guard.service': UNIT}
MAX_FILE = 128 * 1024 * 1024

def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result

def read_regular(path, maximum, root_owned=False):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_size > maximum:
        raise ValueError('Not a bounded regular file: ' + str(path))
    if root_owned and (meta.st_uid != 0 or meta.st_mode & 0o022):
        raise ValueError('Invalid root ownership/permissions: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (meta.st_dev, meta.st_ino):
            raise ValueError('File changed during open')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('File grew beyond limit')
        return data

def mkdir_owned(path, mode):
    if not path.exists():
        path.mkdir(mode=mode)
        path.chmod(mode)  # umask 077 must not make the executable parent 0700.
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('Untrusted product directory: ' + str(path))

def atomic(path, data, mode):
    fd, name = tempfile.mkstemp(prefix='.qg-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def command(*args, check=True):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=check, timeout=40,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})

def verify_release(directory, public_key):
    # Copy just bounded regular files to a root-private staging directory first.
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Bundle root must be a real directory')
    expected_names = set(PAYLOADS) | {'manifest.json', 'signature.bin'}
    if {p.name for p in directory.iterdir()} != expected_names:
        raise ValueError('Unexpected/missing release files')
    with tempfile.TemporaryDirectory(prefix='verify-', dir=CONFIG) as temporary:
        stage = pathlib.Path(temporary)
        for name in expected_names:
            maximum = 1024 * 1024 if name == 'manifest.json' else 64 if name == 'signature.bin' else MAX_FILE
            (stage / name).write_bytes(read_regular(directory / name, maximum))
        (stage / 'public.pem').write_bytes(public_key)
        der = command('/usr/bin/openssl', 'pkey', '-pubin', '-in', str(stage / 'public.pem'), '-outform', 'DER').stdout
        if len(der) != 44 or not der.startswith(bytes.fromhex('302a300506032b6570032100')):
            raise ValueError('Trust anchor must be an Ed25519 public key')
        command('/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(stage / 'public.pem'),
                '-rawin', '-in', str(stage / 'manifest.json'), '-sigfile', str(stage / 'signature.bin'))
        manifest = json.loads((stage / 'manifest.json').read_bytes(), object_pairs_hook=unique_pairs)
        if set(manifest) != {'schema', 'kind', 'sequence', 'version', 'target', 'files'} or manifest['schema'] != 1 or manifest['kind'] != 'release' or manifest['target'] != 'linux-x86_64':
            raise ValueError('Wrong manifest schema/kind/target')
        if type(manifest['sequence']) is not int or manifest['sequence'] < 1:
            raise ValueError('Invalid release sequence')
        if not isinstance(manifest['version'], str) or not 1 <= len(manifest['version']) <= 64:
            raise ValueError('Invalid version')
        entries = manifest['files']
        if not isinstance(entries, list) or len(entries) != 2 or {e.get('path') for e in entries} != set(PAYLOADS):
            raise ValueError('Wrong release file list')
        payload = {}
        for entry in entries:
            if set(entry) != {'path', 'size', 'sha256'}:
                raise ValueError('Unexpected file metadata')
            data = (stage / entry['path']).read_bytes()
            if type(entry['size']) is not int or len(data) != entry['size'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
                raise ValueError('Payload hash/size mismatch')
            payload[entry['path']] = data
        # System OpenSSL did the bootstrap verification; no payload has executed.
        if not payload['quiet-guard'].startswith(b'\x7fELF'):
            raise ValueError('Expected Linux ELF executable')
        if not payload['quiet-guard.service'].startswith(b'# Managed by Quiet Guard foundation v1\n'):
            raise ValueError('Wrong service marker')
        return manifest, payload

def owned_install():
    if any(os.path.lexists(CONFIG / name) for name in ['ssh','waf','exposure']):
        raise ValueError('Remove SSH/WAF/exposure integrations with quiet-guard ssh remove, quiet-guard waf remove and quiet-guard exposure remove before updating/removing the foundation; preserving integrations')
    if not RECORD.exists():
        for path in [PROGRAM, UNIT, LINK, KEY]:
            if os.path.lexists(path):
                raise ValueError('Existing unowned installation path: ' + str(path))
        return None
    record = json.loads(read_regular(RECORD, 65536, True), object_pairs_hook=unique_pairs)
    if record.get('marker') != MARKER or set(record.get('hashes', {})) != set(PAYLOADS):
        raise ValueError('Unrecognized ownership record')
    for name, path in PAYLOADS.items():
        data = read_regular(path, MAX_FILE, True)
        if hashlib.sha256(data).hexdigest() != record['hashes'][name]:
            raise ValueError('Installed file was modified; preserving it: ' + str(path))
    if hashlib.sha256(read_regular(KEY, 4096, True)).hexdigest() != record.get('key_sha256'):
        raise ValueError('Installed trust anchor was modified; preserving it')
    if not LINK.is_symlink() or LINK.lstat().st_uid != 0 or os.readlink(LINK) != str(PROGRAM):
        raise ValueError('Command link was modified; preserving it')
    return record

def wait_ready():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = command(str(PROGRAM), 'status', check=False)
        if result.returncode == 0:
            state = json.loads(result.stdout)
            if state['agent'] == 'running' and state['protection'] == 'not_configured':
                return
        time.sleep(0.25)
    raise RuntimeError('Foundation agent did not become ready')

def install(directory, key_path):
    old = owned_install()
    public_key = read_regular(key_path, 4096)
    if old and public_key != read_regular(KEY, 4096, True):
        raise ValueError('Signing authority change requires a separate reviewed migration')
    manifest, payload = verify_release(directory, public_key)
    if old and manifest['sequence'] <= old['sequence']:
        raise ValueError('Refusing replay/downgrade: sequence must increase')
    mkdir_owned(PROGRAM.parent, 0o755)
    backup = {name: read_regular(path, MAX_FILE, True) for name, path in PAYLOADS.items()} if old else {}
    was_active = old and command('/usr/bin/systemctl', 'is-active', '--quiet', 'quiet-guard.service', check=False).returncode == 0
    was_enabled = old and command('/usr/bin/systemctl', 'is-enabled', '--quiet', 'quiet-guard.service', check=False).returncode == 0
    old_key = read_regular(KEY, 4096, True) if old else None
    old_record = read_regular(RECORD, 65536, True) if old else None
    try:
        if old:
            command('/usr/bin/systemctl', 'stop', 'quiet-guard.service')
        atomic(PROGRAM, payload['quiet-guard'], 0o755)
        if command(str(PROGRAM), '--version').stdout.decode().strip() != 'quiet-guard ' + manifest['version']:
            raise ValueError('Signed version and binary version differ')
        atomic(UNIT, payload['quiet-guard.service'], 0o644)
        atomic(KEY, public_key, 0o600)
        if not old:
            LINK.symlink_to(PROGRAM)
        command('/usr/bin/systemctl', 'daemon-reload')
        command('/usr/bin/systemctl', 'enable', '--now', 'quiet-guard.service')
        wait_ready()
        record = {'marker': MARKER, 'sequence': manifest['sequence'], 'version': manifest['version'],
                  'hashes': {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()},
                  'key_sha256': hashlib.sha256(public_key).hexdigest()}
        atomic(RECORD, json.dumps(record).encode(), 0o600)
    except Exception:
        command('/usr/bin/systemctl', 'disable', '--now', 'quiet-guard.service', check=False)
        if old:
            for name, path in PAYLOADS.items():
                atomic(path, backup[name], 0o755 if path == PROGRAM else 0o644)
            atomic(KEY, old_key, 0o600)
            atomic(RECORD, old_record, 0o600)
        else:
            for path in [LINK, PROGRAM, UNIT, KEY]:
                if os.path.lexists(path): path.unlink()
            try: PROGRAM.parent.rmdir()
            except OSError: pass
        command('/usr/bin/systemctl', 'daemon-reload', check=False)
        if was_enabled: command('/usr/bin/systemctl', 'enable', 'quiet-guard.service', check=False)
        if was_active:
            command('/usr/bin/systemctl', 'start', 'quiet-guard.service')
            wait_ready()
        raise
    print(json.dumps({'installed': manifest['version'], 'sequence': manifest['sequence'],
                      'protection': 'not_configured', 'message': 'Foundation installed; protection engines are not connected yet.'}))

def uninstall():
    record = owned_install()
    if record is None:
        raise ValueError('No owned Quiet Guard installation')
    # All ownership checks happen before stopping/removing anything.
    command('/usr/bin/systemctl', 'disable', '--now', 'quiet-guard.service')
    for path in [LINK, PROGRAM, UNIT, KEY, RECORD]:
        path.unlink()
    command('/usr/bin/systemctl', 'daemon-reload')
    for directory in [PROGRAM.parent, CONFIG]:
        try: directory.rmdir()
        except OSError: pass  # Never recursively remove user additions.
    print('Quiet Guard foundation removed. No CrowdSec/Nginx/firewall settings were changed.')

def main():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('Linux root privileges required')
    platform = dict(line.split('=', 1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os.uname().machine != 'x86_64' or platform.get('ID', '').strip('"') != 'ubuntu' or platform.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('This foundation installer currently supports Ubuntu 24.04 x86_64 only')
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['install', 'uninstall'])
    parser.add_argument('--bundle', type=pathlib.Path)
    parser.add_argument('--trusted-key', type=pathlib.Path)
    args = parser.parse_args()
    mkdir_owned(CONFIG, 0o700)
    import fcntl
    lock = os.open('/run/lock/quiet-guard-deploy.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    meta = os.fstat(lock)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
        os.close(lock)
        raise ValueError('Untrusted deployment lock')
    with os.fdopen(lock, 'w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.operation == 'install':
            if not args.bundle or not args.trusted_key: parser.error('--bundle and independently trusted --trusted-key required')
            install(args.bundle, args.trusted_key)
        else: uninstall()
    # The runtime lock is never unlinked: waiters must share the same inode.

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # No command stderr or signing material is exposed to the dashboard.
        print('Deployment failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
