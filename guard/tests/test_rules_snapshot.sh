#!/usr/bin/env bash
# Feasibility experiment in a fresh disposable VM, not a production installer.
set -euo pipefail
test "${QUIET_GUARD_DISPOSABLE_VM:-}" = YES
test "$(id -u)" = 0
binary=$(realpath "${1:?compiled binary}")
test ! -x /usr/bin/cscli
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
umask 077
apt-get update -qq
apt-get install -y --no-install-recommends curl gnupg python3-yaml
curl --proto '=https' --fail --silent --show-error --location https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$temporary/key.asc"
gpg --batch --dearmor --output "$temporary/repository.gpg" "$temporary/key.asc"
install -m 644 "$temporary/repository.gpg" /etc/apt/keyrings/quiet-guard-research.gpg
printf 'deb [signed-by=/etc/apt/keyrings/quiet-guard-research.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main\n' > /etc/apt/sources.list.d/quiet-guard-research.list
printf 'crowdsec crowdsec/lapi boolean true\ncrowdsec crowdsec/capi boolean false\n' | debconf-set-selections
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends crowdsec
systemctl stop crowdsec.service

python3 - "$temporary" <<'PY'
import pathlib, shutil, sys
root=pathlib.Path(sys.argv[1]) / 'bundle'
(root/'rules').mkdir(parents=True)
(root/'data').mkdir()
config=pathlib.Path('/etc/crowdsec')
for name in ['collections','parsers','scenarios','postoverflows','appsec-configs','appsec-rules','patterns','contexts']:
    source=config/name
    if source.is_dir(): shutil.copytree(source,root/'rules'/name,symlinks=False)
for name in ['simulation.yaml','profiles.yaml']:
    if (config/name).is_file(): shutil.copyfile(config/name,root/'rules'/name)
index=config/'hub/.index.json'
if index.is_file(): shutil.copyfile(index,root/'rules/hub-index.json')
for file in pathlib.Path('/var/lib/crowdsec/data').glob('*'):
    if file.is_file() and file.suffix not in {'.db','.sqlite','.sqlite3'} and not file.name.startswith('.'):
        shutil.copyfile(file,root/'data'/file.name)
assert list((root/'rules/parsers').rglob('*.yaml'))
PY
openssl genpkey -algorithm ED25519 -out "$temporary/private.pem"
openssl pkey -in "$temporary/private.pem" -pubout -out "$temporary/public.pem"
"$binary" bundle manifest "$temporary/bundle" rules 1 research-1
openssl pkeyutl -sign -inkey "$temporary/private.pem" -rawin -in "$temporary/bundle/manifest.json" -out "$temporary/bundle/signature.bin"
"$binary" rules stage "$temporary/bundle" "$temporary/public.pem" "$temporary/snapshots"
active=$(find "$temporary/snapshots" -mindepth 1 -maxdepth 1 -type d)
python3 - "$temporary" "$active" <<'PY'
import pathlib, sys, yaml
work=pathlib.Path(sys.argv[1]); active=pathlib.Path(sys.argv[2])
config=yaml.safe_load(pathlib.Path('/etc/crowdsec/config.yaml').read_text())
def rewrite(value):
    if isinstance(value,dict): return {k:rewrite(v) for k,v in value.items()}
    if isinstance(value,list): return [rewrite(v) for v in value]
    if isinstance(value,str): return value.replace('/etc/crowdsec',str(active/'rules')).replace('/var/lib/crowdsec/data',str(active/'data'))
    return value
config=rewrite(config)
config['common']['log_media']='stdout'
config['common']['log_dir']=str(work)
config['config_paths']['hub_dir']=str(work/'hub-cache')
config['config_paths']['index_path']=str(active/'rules/hub-index.json')
(work/'hub-cache').mkdir()
(work/'runtime').mkdir()
config.setdefault('db_config', {})['db_path']=str(work/'runtime/crowdsec.db')
(work/'acquis').mkdir()
(work/'empty.log').touch()
(work/'acquis/input.yaml').write_text(yaml.safe_dump({'source':'file','filenames':[str(work/'empty.log')],'labels':{'type':'syslog'}}))
config['crowdsec_service']['acquisition_path']=''
config['crowdsec_service']['acquisition_dir']=str(work/'acquis')
config['api']={'server':{'enable':False},'client':{'credentials_path':str(work/'credentials.yaml')}}
(work/'credentials.yaml').write_text('url: http://127.0.0.1:8080/\nlogin: snapshot-test\npassword: test-only-not-a-live-credential\n')
config['prometheus']={'enabled':False}
(work/'engine.yaml').write_text(yaml.safe_dump(config))
PY
timeout 60 crowdsec -t -c "$temporary/engine.yaml" -no-api
cscli hub update >/dev/null
"$binary" bundle verify "$active" "$temporary/public.pem" >/dev/null
# Deliberately corrupt the old, live source AFTER the detached snapshot exists.
source_rule=$(find -L /etc/crowdsec/parsers -type f -name '*.yaml' | head -n 1)
cp "$source_rule" "$temporary/original-rule"
printf '[invalid yaml\n' > "$source_rule"
timeout 60 crowdsec -t -c "$temporary/engine.yaml" -no-api
"$binary" bundle verify "$active" "$temporary/public.pem" >/dev/null
cp "$temporary/original-rule" "$source_rule"
echo 'PASS: actual CrowdSec loads the detached signed rule snapshot; catalog/source changes do not alter it'
echo 'Package maintenance jobs (research only, not modified):'
systemctl cat crowdsec-hubupdate.service crowdsec-hubupdate.timer || true
