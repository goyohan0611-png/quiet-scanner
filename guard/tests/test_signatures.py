"""Portable CLI signing compatibility and malicious bundle regression tests."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()
openssl = os.environ.get('OPENSSL', 'openssl')
def run(*args, ok=True):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True)
    if (result.returncode == 0) != ok:
        raise AssertionError(result.stderr)
    return result

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    key = root / 'private.pem'
    public = root / 'public.pem'
    run(openssl, 'genpkey', '-algorithm', 'ED25519', '-out', key)
    run(openssl, 'pkey', '-in', key, '-pubout', '-out', public)
    bundle = root / 'bundle'
    (bundle / 'rules').mkdir(parents=True)
    (bundle / 'rules' / 'test.yaml').write_text('name: fixture\n')
    run(binary, 'bundle', 'manifest', bundle, 'rules', 1, 'rules-1')
    run(openssl, 'pkeyutl', '-sign', '-inkey', key, '-rawin', '-in', bundle / 'manifest.json', '-out', bundle / 'signature.bin')
    run(binary, 'bundle', 'verify', bundle, public)
    run(binary, 'rules', 'stage', bundle, public, root / 'snapshots')
    (bundle / 'rules' / 'test.yaml').write_text('changed\n')
    run(binary, 'bundle', 'verify', bundle, public, ok=False)
    snapshots = list((root / 'snapshots').iterdir())
    assert len(snapshots) == 1
    run(binary, 'bundle', 'verify', snapshots[0], public)
    policy = root / 'policy.json'
    policy.write_text(json.dumps({'web': 'unknown', 'web_verified': False, 'suspicious_peer_concentration': True, 'ssh': 'direct', 'ssh_verified': True}))
    decision = json.loads(run(binary, 'policy', policy).stdout)
    assert decision == {'web_ip_ban_allowed': False, 'ssh_ip_ban_allowed': True, 'applied': False}
print('PASS: OpenSSL/Rust signature compatibility, detached snapshots, tamper rejection, independent ingress policies')
