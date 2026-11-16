# Managed by Quiet Scanner protection v1
"""Installation-only configuration inspection; never parses network packets."""
import glob
import json
import os
import pathlib
import sys
import yaml

ROOT = pathlib.Path('/etc/quiet-scanner/protection')
CONFIG_ROOT = pathlib.Path('/etc/crowdsec')
MARKER = '# Managed by Quiet Scanner protection v1'

def read_json(path):
    with open(path, encoding='utf-8') as stream:
        return json.load(stream)

def atomic_json(name, value):
    path = ROOT / name
    temp = path.with_suffix(f'.{os.getpid()}.tmp')
    with open(temp, 'x', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)

def documents(path):
    if not path.is_file():
        return []
    if path.stat().st_size > 512 * 1024:
        raise ValueError('Acquisition configuration exceeds safe inspection size')
    return list(yaml.safe_load_all(path.read_text(encoding='utf-8')))

def merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge(base[key], value)
        else:
            base[key] = value
    return base

def configure():
    owner = read_json(ROOT / 'setup-owner.json')
    local = CONFIG_ROOT / 'config.yaml.local'
    if owner['managedEngine']:
        # Preserve user-written overrides, including their privacy policy.
        if not local.exists() or local.read_text(encoding='utf-8').startswith(MARKER):
            with open(local, 'w', encoding='utf-8') as stream:
                stream.write(MARKER + '\napi:\n  server:\n    online_client:\n      sharing: false\n      pull:\n        community: false\n        blocklists: false\n')
            local.chmod(0o600)
    config = documents(CONFIG_ROOT / 'config.yaml')[0] or {}
    overrides = documents(local)
    if overrides:
        config = merge(config, overrides[0] or {})
    credentials = config.get('api', {}).get('client', {}).get('credentials_path', '/etc/crowdsec/local_api_credentials.yaml')
    api = documents(pathlib.Path(credentials))[0] or {}
    if api.get('url', '').rstrip('/') != 'http://127.0.0.1:8080':
        raise ValueError('Only the local CrowdSec API at 127.0.0.1:8080 is supported; existing remote settings are preserved')
    acquisition = config.get('crowdsec_service', {})
    files = []
    legacy = acquisition.get('acquisition_path', '/etc/crowdsec/acquis.yaml')
    if legacy:
        files.append(pathlib.Path(legacy))
    directory = acquisition.get('acquisition_dir', '/etc/crowdsec/acquis.d')
    if directory:
        files.extend(pathlib.Path(p) for p in sorted(glob.glob(str(pathlib.Path(directory) / '*.yaml'))))
    if len(files) > 128:
        raise ValueError('Too many acquisition files to inspect automatically')
    inputs = []
    seen = set()
    for path in files:
        for doc in documents(path):
            if not isinstance(doc, dict):
                continue
            kind = (doc.get('labels') or {}).get('type')
            source = doc.get('source') or ('file' if doc.get('filenames') or doc.get('filename') else '')
            if not kind or not source:
                continue
            identity = (str(path), str(kind), str(source))
            if identity not in seen:
                seen.add(identity)
                inputs.append({'kind': str(kind)[:80], 'source': str(source)[:80], 'configuration': str(path)[:240]})
    if not inputs:
        raise ValueError('No supported log acquisition was configured; protection will not start')
    atomic_json('sources.json', {'managedEngine': owner['managedEngine'], 'packageBouncers': owner.get('packageBouncers', []), 'inputs': inputs[:64]})

if __name__ == '__main__':
    if sys.argv[1] == 'remember-bouncers':
        owner = read_json(ROOT / 'setup-owner.json')
        before = {row['name'] for row in read_json(sys.argv[2])}
        after = {row['name'] for row in read_json(sys.argv[3])}
        owner['packageBouncers'] = sorted(set(owner.get('packageBouncers', [])) | (after - before))
        atomic_json('setup-owner.json', owner)
    elif sys.argv[1] == 'configure':
        configure()
    else:
        raise ValueError('Unsupported setup operation')
