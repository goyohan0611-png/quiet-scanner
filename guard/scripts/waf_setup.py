"""Embedded root controller. nginx_config.py is prepended by the Rust binary.

Only the direct, apt Nginx Ubuntu 24.04 profile is accepted. Website bytes are
backed up before modification. Operator edits cause a refusal, never overwrite.
"""
import argparse
import base64
import fcntl
import http.client
import ipaddress
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path('/etc/quiet-guard/waf')
STATE = pathlib.Path('/var/lib/quiet-guard/waf')
CODE = pathlib.Path('/usr/local/lib/quiet-guard/waf')
PROGRAM = pathlib.Path('/usr/local/lib/quiet-guard/quiet-guard')
RECORD = ROOT / 'ownership.json'
INCLUDE = pathlib.Path('/etc/nginx/conf.d/00-quiet-guard-waf.conf')
SOCKET_DIR = pathlib.Path('/run/quiet-guard-waf-status')
SOCKET = str(SOCKET_DIR / 'nginx.sock')
ENGINE = 'quiet-guard-waf-engine.service'
MONITOR = 'quiet-guard-waf-monitor.service'
MARKER = 'quiet-guard-waf-v1'
ASSETS = {}


def read(path, limit=4*1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or meta.st_size > limit:
            raise ValueError('Untrusted file: ' + str(path))
        raw = stream.read(limit + 1)
        if len(raw) > limit: raise ValueError('File exceeded limit')
        return raw


def directory(path, mode=0o700):
    if not path.exists():
        path.mkdir(mode=mode);path.chmod(mode)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('Untrusted directory: ' + str(path))


def atomic(path, data, mode=0o600, gid=0):
    fd, temporary = tempfile.mkstemp(prefix='.qg-waf-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode);os.fchown(stream.fileno(), 0, gid)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)


def save(path, value, mode=0o600):
    atomic(path, json.dumps(value, separators=(',', ':')).encode(), mode)


def command(*args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=40, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','HOME':'/root'})
    if len(result.stdout)+len(result.stderr)>4*1024*1024: raise ValueError('Command output exceeded limit')
    if check and result.returncode:
        diagnostic=result.stderr.decode(errors='replace')[-3000:]
        try: diagnostic=diagnostic.replace(json.loads(read(ROOT/'settings.json'))['probe_token'],'[redacted]')
        except (OSError,ValueError,KeyError):pass
        for path in [ROOT/'bouncer.conf',ROOT/'local_api_credentials.yaml']:
            try:
                for line in read(path).decode().splitlines():
                    if line.startswith(('API_KEY=','password:','login:')):
                        secret=re.split('[:=]',line,maxsplit=1)[1].strip().strip('\"\'')
                        if secret:diagnostic=diagnostic.replace(secret,'[redacted]')
            except (OSError,ValueError):pass
        raise RuntimeError('Command failed: '+str(args[0])+': '+diagnostic)
    return result


def system(*args, check=True): return command('/usr/bin/systemctl', *args, check=check)
def cscli(*args): return command('/usr/bin/cscli','-c',str(ROOT/'config.yaml'),*args)
def sha(raw): return hashlib.sha256(raw).hexdigest()


def private_status(body=None):
    class UnixHTTP(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(3);self.sock.connect(SOCKET)
    connection = UnixHTTP('localhost', timeout=3)
    try:
        connection.request('POST' if body else 'GET','/',body=json.dumps(body).encode() if body else None,
                           headers={'Host':'localhost','Content-Type':'application/json'})
        response = connection.getresponse()
        data = response.read(262145)
        if response.status != 200 or len(data)>262144: raise ValueError('Invalid private Nginx response')
        return json.loads(data)
    finally: connection.close()


def public(enabled, config):
    save(STATE/'public.json', {'schema':1,'enabled':enabled,'generation':config['generation']},0o644)


def owned():
    record = json.loads(read(RECORD))
    if record.get('marker') != MARKER or not isinstance(record.get('files'),dict): raise ValueError('Unknown WAF installation')
    # This record is private root state, but constrain paths even if it is damaged.
    for name,digest in record['files'].items():
        path = pathlib.Path(name)
        if '..' in path.parts or not (path.is_relative_to(ROOT) or path.is_relative_to(CODE) or path.parent==STATE/'data' or str(path) in ['/etc/systemd/system/'+ENGINE,'/etc/systemd/system/'+MONITOR]):
            raise ValueError('Unrecognized WAF owned path')
        if sha(read(path)) != digest: raise ValueError('WAF file changed; preserving it: '+name)
    return record


def verify_active(record):
    if sha(read(INCLUDE)) != record['include_hash'] or nginx_inventory()['digest'] != record['active_digest']:
        raise ValueError('Nginx configuration changed; external proof is invalid and original files will not be overwritten')


def supported():
    platform = dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if os.uname().machine!='x86_64' or platform.get('ID','').strip('"')!='ubuntu' or platform.get('VERSION_ID','').strip('"')!='24.04':
        raise ValueError('WAF currently supports Ubuntu 24.04 x86_64 apt Nginx only')


def prerequisites():
    for package,prefix in [('crowdsec','1.8.2'),('nginx','1.24.0'),('libnginx-mod-http-lua',None)]:
        version = command('/usr/bin/dpkg-query','-W','-f=${Version}',package).stdout.decode().strip()
        if prefix and not (version==prefix or version.startswith(prefix+'-')):
            raise ValueError('Unsupported '+package+' version; no packages were changed')
    command('/usr/sbin/nginx','-t')
    system('is-active','--quiet','nginx.service')


def package_revision():
    return command('/usr/bin/dpkg-query','-W','-f=${Package}=${Version}\n','crowdsec','nginx','libnginx-mod-http-lua','lua-cjson').stdout.decode()


def fresh(args):
    if not args.direct or not args.probe_peer or not args.site:
        raise ValueError('First enable requires --direct --probe-peer EXTERNAL_IP --site https://site.example')
    peer = ipaddress.ip_address(args.probe_peer)
    assigned = json.loads(command('/usr/sbin/ip','-j','address','show').stdout)
    local = {entry['local'] for row in assigned for entry in row.get('addr_info',[])}
    if peer.is_loopback or peer.is_multicast or peer.is_unspecified or str(peer) in local:
        raise ValueError('Probe peer must be outside this server, including outside its loopback addresses')
    foundation = json.loads(read(ROOT.parent/'install.json'))
    if foundation.get('marker')!='quiet-guard-foundation-v1' or foundation['hashes']['quiet-guard']!=sha(read(PROGRAM,128*1024*1024)) or pathlib.Path(os.environ['QG_BINARY']).resolve()!=PROGRAM:
        raise ValueError('Use the signed, installed Quiet Guard foundation command')
    prerequisites()
    inventory = nginx_inventory();plan = nginx_plan(inventory,args.site)
    if any(not t['url'].startswith('https://') for t in plan['targets']) and not args.allow_insecure_probe:
        raise ValueError('External diagnostic credentials require HTTPS; --allow-insecure-probe is for isolated tests only')
    for path in [ROOT,STATE,CODE,INCLUDE]:
        if os.path.lexists(path): raise ValueError('Existing unowned WAF path: '+str(path))
    for unit in [ENGINE,MONITOR]:
        if system('show','--property=FragmentPath','--value',unit).stdout.strip(): raise ValueError('Unowned WAF unit exists')
    for port in [17425,17426,17427]:
        with socket.socket() as test: test.bind(('127.0.0.1',port))
    config = {'schema':1,'generation':secrets.token_hex(16),'probe_peer':str(peer),'probe_token':secrets.token_hex(32),
              'targets':plan['targets'],'scopes':plan['scopes'],'failure_action':args.failure_action,'body_action':args.body_action,
              'max_inspect_bytes':args.max_inspect_bytes,'insecure_probe':args.allow_insecure_probe}
    directories = [];created = {}
    def mkdir(path,mode):
        if not path.exists(): directory(path,mode);directories.append(path)
    def put(path,data,mode=0o600):
        mkdir(path.parent,0o755 if path.is_relative_to(CODE) else 0o700)
        atomic(path,data,mode);created[str(path)]=sha(data)
    try:
        mkdir(ROOT,0o700);mkdir(STATE,0o755);mkdir(CODE,0o755)
        for folder in ['data','data/trace']: mkdir(STATE/folder,0o700)
        for folder in ['rules','rules/parsers','rules/scenarios','rules/postoverflows','rules/contexts','rules/patterns','rules/hub','rules/appsec-configs','rules/appsec-rules']: mkdir(ROOT/folder,0o700)
        for name,text in ASSETS.items():
            if name.endswith('.service'):
                put(pathlib.Path('/etc/systemd/system')/(ENGINE if name=='engine.service' else MONITOR),text.encode(),0o644)
            elif name.startswith(('lua/','nginx/','licenses/')):
                # Create each ancestor without following foreign writable directories.
                parent=CODE
                for piece in pathlib.Path(name).parts[:-1]: parent/=piece;mkdir(parent,0o755)
                put(CODE/name,text.encode(),0o644)
            elif name.startswith('data/'):
                put(STATE/name,text.encode())
            elif name.startswith('rules/'):
                put(ROOT/name,text.encode())
            else: put(ROOT/name,text.encode())
        def cfg(name,value): put(ROOT/name,json.dumps(value).encode())
        cfg('settings.json',config)
        command(str(PROGRAM),'waf-policy',str(ROOT/'settings.json'))
        cfg('probe-client.json',{'probe_token':config['probe_token'],'targets':config['targets']})
        cfg('rules/hub/.index.json',{})
        cfg('simulation.yaml',{'simulation':False})
        cfg('console.yaml',{'share_manual_decisions':False,'share_tainted':False,'share_custom':False,'share_context':False})
        put(ROOT/'profiles.yaml',b'')
        cfg('acquis.yaml',{'source':'appsec','listen_addr':'127.0.0.1:17426','appsec_config_path':str(ROOT/'rules/appsec-configs/quiet-guard.yaml'),'body_read_timeout':'1s','labels':{'type':'appsec'}})
        cfg('rules/appsec-configs/quiet-guard.yaml',{'name':'quiet-guard/waf','default_remediation':'ban','inband_rules':['crowdsecurity/crs','crowdsecurity/vpatch-env-access','quiet-guard/body-proof'],
             'on_match':[{'filter':'true','apply':['CancelAlert()']}], 'on_load':[{'apply':['SetMaxBodySize('+str(args.max_inspect_bytes)+')']}]})
        canary = 'SecRule REQUEST_HEADERS:X-Quiet-Guard-Diagnostic "@streq '+config['probe_token']+'" "id:1999991,phase:2,deny,status:403,nolog,noauditlog,chain"\n SecRule ARGS:quiet_guard_probe "@streq QuietGuardBodyInspectionMarker" "t:none"'
        cfg('rules/appsec-rules/quiet-guard.yaml',{'name':'quiet-guard/body-proof','seclang_rules':[canary,'SecAuditEngine Off','SecDebugLogLevel 0']})
        cfg('config.yaml',{'common':{'daemonize':False,'log_media':'stdout','log_level':'warning'},
            'config_paths':{'config_dir':str(ROOT/'rules'),'data_dir':str(STATE/'data'),'simulation_path':str(ROOT/'simulation.yaml'),
                'hub_dir':str(ROOT/'rules/hub'),'index_path':str(ROOT/'rules/hub/.index.json'),'notification_dir':str(ROOT/'rules/notifications'),'plugin_dir':str(ROOT/'rules/plugins')},
            'crowdsec_service':{'acquisition_path':str(ROOT/'acquis.yaml'),'parser_routines':1},
            'cscli':{'output':'human','color':'never'},'db_config':{'type':'sqlite','db_path':str(STATE/'crowdsec.db'),'flush':{'max_items':5000,'max_age':'7d'}},
            'api':{'client':{'credentials_path':str(ROOT/'local_api_credentials.yaml')},'server':{'enable':True,'listen_uri':'127.0.0.1:17425',
                'profiles_path':str(ROOT/'profiles.yaml'),'console_path':str(ROOT/'console.yaml'),'disable_remote_lapi_registration':True,'disable_usage_metrics_export':True,'trusted_ips':['127.0.0.1','::1']}},
            'prometheus':{'enabled':True,'level':'full','listen_addr':'127.0.0.1','listen_port':17427}})
        cscli('machines','add','quiet-guard-waf','--auto','--force')
        created[str(ROOT/'local_api_credentials.yaml')]=sha(read(ROOT/'local_api_credentials.yaml'))
        token=cscli('bouncers','add','quiet-guard-waf','-o','raw').stdout.decode().strip()
        if not re.fullmatch(r'[a-zA-Z0-9_+=/-]{16,256}',token): raise ValueError('Invalid local API credential format')
        put(ROOT/'bouncer.conf',('API_URL=\nAPI_KEY='+token+'\nAPPSEC_URL=http://127.0.0.1:17426\nAPPSEC_FAILURE_ACTION=passthrough\nAPPSEC_PROCESS_TIMEOUT=1000\nAPPSEC_CONNECT_TIMEOUT=100\nAPPSEC_SEND_TIMEOUT=100\n').encode())
        validation=command('/usr/bin/crowdsec','-t','-c',str(ROOT/'config.yaml'),check=False)
        if validation.returncode:
            diagnostic=(validation.stdout+validation.stderr).decode(errors='replace')[-4000:]
            for secret in [token,config['probe_token']]: diagnostic=diagnostic.replace(secret,'[redacted]')
            for line in read(ROOT/'local_api_credentials.yaml').decode().splitlines():
                if line.startswith(('password:','login:')):
                    secret=line.split(':',1)[1].strip().strip('\"\'')
                    if secret:diagnostic=diagnostic.replace(secret,'[redacted]')
            raise RuntimeError('Inspection engine validation failed: '+diagnostic)
        patched=nginx_patched(inventory,plan)
        backups={path:{'raw':base64.b64encode(inventory['texts'][path].encode()).decode(),'mode':stat.S_IMODE(inventory['metas'][path].st_mode),'gid':inventory['metas'][path].st_gid,'patched_hash':sha(raw)} for path,raw in patched.items()}
        include=('lua_package_path "'+str(CODE)+'/lua/?.lua;;";\nlua_shared_dict crowdsec_cache 10m;\nlua_shared_dict quiet_guard_waf 16m;\ninit_by_lua_file '+str(CODE)+'/nginx/init.lua;\naccess_by_lua_file '+str(CODE)+'/nginx/access.lua;\nlog_by_lua_file '+str(CODE)+'/nginx/log.lua;\nserver { listen unix:'+SOCKET+'; server_name localhost; access_log off; set $quiet_guard_scope_id ""; location / { content_by_lua_file '+str(CODE)+'/nginx/status.lua; } }\n').encode()
        record={'marker':MARKER,'enabled':False,'files':created,'backups':backups,'include':base64.b64encode(include).decode(),'include_hash':sha(include),'baseline_digest':inventory['digest'],'active_digest':None,'packages':package_revision()}
        save(RECORD,record);public(False,config);system('daemon-reload')
    except Exception:
        for extra in [RECORD,STATE/'public.json']:
            if extra.exists(): read(extra);extra.unlink()
        for path,digest in reversed(list(created.items())):
            try:
                if sha(read(path))==digest: pathlib.Path(path).unlink()
            except OSError: pass
        for name in ['crowdsec.db','crowdsec.db-shm','crowdsec.db-wal','crowdsec.db-journal']:
            path=STATE/name
            if path.exists(): read(path,128*1024*1024);path.unlink()
        for path in reversed(directories):
            try: path.rmdir()
            except OSError: pass
        system('daemon-reload',check=False)
        raise


def start(record):
    if record['enabled']:
        verify_active(record)
        system('enable','--now',ENGINE);system('enable','--now',MONITOR)
        return
    if nginx_inventory()['digest']!=record['baseline_digest'] or os.path.lexists(INCLUDE):
        raise ValueError('Nginx changed since the backup; preserving it. Remove and configure a new WAF installation.')
    config=json.loads(read(ROOT/'settings.json'))
    directory(SOCKET_DIR,0o700)
    system('enable','--now',ENGINE)
    changed=[]
    try:
        inv=nginx_inventory()
        origins=sorted({t['url'][:-len(t['path'])] for t in config['targets']})
        plan=nginx_plan(inv,origins)
        for name,raw in nginx_patched(inv,plan).items():
            item=record['backups'][name]
            if sha(raw)!=item['patched_hash']: raise ValueError('Nginx scope plan no longer matches backup')
            atomic(pathlib.Path(name),raw,item['mode'],item['gid']);changed.append(name)
        atomic(INCLUDE,base64.b64decode(record['include']),0o644)
        command('/usr/sbin/nginx','-t');system('reload','nginx.service')
        deadline=time.monotonic()+12
        while True:
            try:
                snap=private_status()
                if snap['generation']==config['generation']: break
            except (OSError,ValueError,http.client.HTTPException): pass
            if time.monotonic()>deadline: raise RuntimeError('New Nginx integration did not respond')
            time.sleep(.2)
        record['active_digest']=nginx_inventory()['digest'];record['enabled']=True
        save(RECORD,record);public(True,config)
        system('enable','--now',MONITOR)
    except Exception:
        if INCLUDE.exists() and sha(read(INCLUDE))==record['include_hash']: INCLUDE.unlink()
        for name in changed:
            item=record['backups'][name]
            if sha(read(name))==item['patched_hash']: atomic(pathlib.Path(name),base64.b64decode(item['raw']),item['mode'],item['gid'])
        try:
            command('/usr/sbin/nginx','-t');system('reload','nginx.service')
        finally:
            system('disable','--now',MONITOR,check=False);system('disable','--now',ENGINE,check=False)
            record['enabled']=False;save(RECORD,record);public(False,config)
        raise


def stop(record):
    if not record['enabled']: return
    verify_active(record)
    # Fail-open is explicit before engine stop, including old workers still draining.
    private_status({'enabled':False})
    patched={name:read(name) for name in record['backups']}
    try:
        for name,item in record['backups'].items(): atomic(pathlib.Path(name),base64.b64decode(item['raw']),item['mode'],item['gid'])
        INCLUDE.unlink();command('/usr/sbin/nginx','-t');system('reload','nginx.service')
    except Exception:
        for name,raw in patched.items():
            item=record['backups'][name];atomic(pathlib.Path(name),raw,item['mode'],item['gid'])
        atomic(INCLUDE,base64.b64decode(record['include']),0o644)
        command('/usr/sbin/nginx','-t');system('reload','nginx.service')
        raise
    system('disable','--now',MONITOR);system('disable','--now',ENGINE)
    record['enabled']=False;record['active_digest']=None;save(RECORD,record)
    public(False,json.loads(read(ROOT/'settings.json')))


def check():
    record=owned();config=json.loads(read(ROOT/'settings.json'))
    if not record['enabled']: raise ValueError('WAF is explicitly off')
    verify_active(record)
    if package_revision()!=record['packages']: raise ValueError('Web inspection dependency versions changed; revalidation is required')
    system('is-active','--quiet',ENGINE)
    epoch=system('show','--property=InvocationID','--value',ENGINE).stdout.decode().strip()
    if not re.fullmatch('[a-f0-9]{32}',epoch): raise ValueError('Engine epoch unavailable')
    with socket.create_connection(('127.0.0.1',17426),2): pass
    snapshot=private_status({'epoch':epoch})
    return {'config':config,'snapshot':snapshot,'engine_epoch':epoch}


def main():
    global ASSETS
    if sys.platform!='linux' or os.geteuid()!=0: raise ValueError('Linux root privileges required')
    os.umask(0o077)
    ASSETS=json.loads(sys.stdin.buffer.read(2*1024*1024+1))
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['enable','disable','remove','status','check'])
    parser.add_argument('--direct',action='store_true');parser.add_argument('--probe-peer')
    parser.add_argument('--site',action='append');parser.add_argument('--allow-insecure-probe',action='store_true')
    parser.add_argument('--failure-action',choices=['passthrough','deny'],default='passthrough')
    parser.add_argument('--body-action',choices=['passthrough','deny'],default='passthrough')
    parser.add_argument('--max-inspect-bytes',type=int,default=1048576)
    args=parser.parse_args();supported()
    # Checks are read-only with one bounded private epoch synchronization. Avoid
    # holding the deployment lock during monitor checks or service shutdown.
    if args.action=='check': print(json.dumps(check()));return
    fd=os.open('/run/lock/quiet-guard-deploy.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as lock:
        meta=os.fstat(lock.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077:
            raise ValueError('Untrusted deployment lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        directory(STATE.parent,0o755)
        if args.action=='enable' and not ROOT.exists(): fresh(args)
        record=owned()
        if args.action=='enable': start(record);print('WAF connected. External GET/POST/body-block proofs are still required; use the private probe-client.json on the configured external peer.')
        elif args.action in ['disable','remove']:
            stop(record)
            if args.action=='remove':
                archive=STATE.parent/('waf-archive-'+secrets.token_hex(8));directory(archive,0o700)
                for path in STATE.iterdir():
                    if path.name in ['crowdsec.db','crowdsec.db-wal','crowdsec.db-shm','crowdsec.db-journal','events.jsonl','events.previous.jsonl','health.json','public.json']: path.rename(archive/path.name)
                for name,digest in reversed(list(record['files'].items())):
                    if sha(read(name))!=digest: raise ValueError('Changed WAF file preserved')
                    pathlib.Path(name).unlink()
                trace=STATE/'data/trace'
                if trace.exists():
                    meta=trace.lstat()
                    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022: raise ValueError('Untrusted WAF trace preserved')
                    trace.rename(archive/'trace')
                for path in [STATE/'data',STATE]:
                    try:path.rmdir()
                    except OSError:pass
                RECORD.unlink()
                for root in [ROOT,CODE]:
                    for path in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
                        if path.is_dir() and not path.is_symlink():
                            try:path.rmdir()
                            except OSError:pass
                    try:root.rmdir()
                    except OSError:pass
                system('daemon-reload')
            print('WAF off; original website configuration restored.')
        else:
            print(json.dumps({'enabled':record['enabled'],'external_verifier_required':True}))


try:
    main()
except Exception as error:
    # Never surface raw engine diagnostics, credentials, or request payloads.
    print('WAF control: '+str(error),file=sys.stderr)
    sys.exit(1)
