"""CI failure diagnostics with private generated values redacted."""
import json
import pathlib
import re
import subprocess
secrets=[]
root=pathlib.Path('/etc/quiet-guard/waf')
try:secrets.append(json.loads((root/'settings.json').read_text())['probe_token'])
except (OSError,ValueError):pass
for name in ['bouncer.conf','local_api_credentials.yaml']:
    try:
        for line in (root/name).read_text().splitlines():
            if line.startswith(('API_KEY=','password:','login:')):secrets.append(re.split('[:=]',line,maxsplit=1)[1].strip().strip('\"\''))
    except OSError:pass
for command in [['journalctl','-u','quiet-guard-waf-engine','-u','quiet-guard-waf-monitor','--no-pager','-n','35'],['cat','/var/lib/quiet-guard/waf/health.json'],['curl','--silent','--max-time','3','--unix-socket','/run/quiet-guard-waf-status/nginx.sock','http://localhost/'],['tail','-n','12','/var/log/nginx/error.log']]:
    output=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).stdout.decode(errors='replace')
    for secret in secrets:
        if secret:output=output.replace(secret,'[redacted]')
    print(output)
