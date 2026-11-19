#!/usr/bin/env python3
"""Run OUTSIDE the protected host. No CrowdSec API key is needed.

The credential file is private: it authorizes diagnostic interception, not server
administration. Copy /etc/quiet-guard/waf/probe-client.json securely to this host.
"""
import argparse
import json
import os
import secrets
import stat
import time
import urllib.error
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def run(config):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    good = True
    for target in config['targets']:
        for kind in ['get', 'post', 'block']:
            headers = {'X-Quiet-Guard-Probe-Auth': config['probe_token'],
                       'X-Quiet-Guard-Probe-Nonce': secrets.token_hex(16),
                       'X-Quiet-Guard-Probe-Kind': kind}
            data = None
            if kind != 'get':
                data = json.dumps({'quiet_guard_probe': 'QuietGuardBodyInspectionMarker'} if kind == 'block' else {'message': 'quiet guard benign check'}).encode()
                headers['Content-Type'] = 'application/json'
            request = urllib.request.Request(target['url'], data=data, headers=headers)
            try:
                response = opener.open(request, timeout=5)
            except urllib.error.HTTPError as error:
                response = error
            except (OSError, urllib.error.URLError):
                print(target['id'], kind, 'connection_failed', flush=True);good = False;continue
            with response:
                expected = 403 if kind == 'block' else 204
                outcome = 'blocked' if kind == 'block' else 'inspected'
                matched = response.code == expected and response.headers.get('X-Quiet-Guard-Probe-Result') == outcome
                print(target['id'], kind, 'PASS' if matched else 'UNVERIFIED', flush=True)
                good &= matched
    return good


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('credentials')
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    fd = os.open(args.credentials, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 262144:
            parser.error('Use a private regular credential file (chmod 600)')
        config = json.load(stream)
    while True:
        passed = run(config)
        if args.once:
            raise SystemExit(0 if passed else 1)
        time.sleep(60)


if __name__ == '__main__':
    main()
