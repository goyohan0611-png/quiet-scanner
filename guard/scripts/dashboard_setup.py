"""Install only the signed local UI/broker units; never publish a network listener."""
import fcntl,hashlib,json,os,pathlib,secrets,socket,stat,subprocess,sys,tempfile,time
ROOT=pathlib.Path('/etc/quiet-guard/dashboard')
DATA=pathlib.Path('/var/lib/quiet-guard/dashboard')
PROGRAM=pathlib.Path('/usr/local/lib/quiet-guard/quiet-guard')
SOCKET='quiet-guard-control.socket'
BROKER='quiet-guard-control.service'
WEB='quiet-guard-dashboard.service'

def read(path,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        m=os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022 or m.st_size>limit:raise ValueError('Untrusted dashboard file')
        raw=stream.read(limit+1)
        if len(raw)>limit:raise ValueError('Dashboard file exceeded limit')
        return raw

def directory(path,mode):
    if not path.exists():path.mkdir(mode=mode);path.chmod(mode)
    m=path.lstat()
    if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:raise ValueError('Untrusted dashboard directory')

def atomic(path,data,mode=0o600):
    fd,name=tempfile.mkstemp(prefix='.dashboard-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.lexists(name):os.unlink(name)

def system(*args,check=True):
    result=subprocess.run(['/usr/bin/systemctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=40,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if check and result.returncode:raise RuntimeError('Dashboard service control failed: '+args[0])
    return result

def save(record):atomic(ROOT/'ownership.json',json.dumps(record).encode())
def owned(assets):
    record=json.loads(read(ROOT/'ownership.json'))
    expected={str(pathlib.Path('/etc/systemd/system')/name):hashlib.sha256(data.encode()).hexdigest() for name,data in assets.items()}
    if record.get('marker')!='quiet-guard-dashboard-v1' or record.get('files')!=expected:raise ValueError('Unknown dashboard installation; preserving it')
    for name,digest in expected.items():
        if hashlib.sha256(read(name)).hexdigest()!=digest:raise ValueError('Dashboard service changed; preserving operator edits')
    token=read(ROOT/'access-token',128)
    if len(token)!=64 or any(c not in b'0123456789abcdef' for c in token):raise ValueError('Invalid dashboard access key')
    return record

def stop(record):
    if (DATA/'jobs.json').exists():
        for job in json.loads(read(DATA/'jobs.json',262144)):
            job_id=job.get('id','')
            if len(job_id)==24 and all(c in '0123456789abcdef' for c in job_id) and system('is-active','--quiet','quiet-guard-task-'+job_id+'.service',check=False).returncode==0:
                raise RuntimeError('An administrative task is still running; finish it before stopping or rotating dashboard access')
    system('disable','--now',WEB);system('stop',BROKER);system('disable','--now',SOCKET)
    record['enabled']=False;save(record)

def start(record):
    system('daemon-reload')
    try:
        system('enable','--now',SOCKET);system('enable','--now',WEB)
        end=time.monotonic()+12
        while time.monotonic()<end:
            try:
                with socket.create_connection(('127.0.0.1',9417),1):break
            except OSError:time.sleep(.2)
        else:raise RuntimeError('Local dashboard did not become ready; inspect its service log')
        record['enabled']=True;save(record)
    except Exception:stop(record);raise

def main():
    if os.geteuid()!=0:raise ValueError('Use sudo for dashboard setup/login')
    os.umask(0o077)
    assets=json.loads(sys.stdin.buffer.read(65537))
    if len(sys.argv)!=2 or sys.argv[1] not in ['enable','disable','remove','login','rotate-token','status']:raise ValueError('Use dashboard enable|disable|remove|login|rotate-token|status')
    operation=sys.argv[1]
    lock=os.open('/run/lock/quiet-guard-deploy.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock,'w') as stream:
        m=os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o077:raise ValueError('Untrusted deployment lock')
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        install=json.loads(read(ROOT.parent/'install.json'))
        if pathlib.Path(os.environ['QG_BINARY']).resolve()!=PROGRAM or install.get('marker')!='quiet-guard-foundation-v1' or install['hashes']['quiet-guard']!=hashlib.sha256(read(PROGRAM,128*1024*1024)).hexdigest():raise ValueError('Use the signed, installed foundation command')
        if operation=='enable' and not ROOT.exists():
            if os.path.lexists(ROOT) or os.path.lexists(DATA):raise ValueError('Unowned dashboard paths found; preserving them')
            for name in assets:
                if system('show','--property=FragmentPath','--value',name).stdout.strip() or os.path.lexists(pathlib.Path('/etc/systemd/system')/name):raise ValueError('Unowned dashboard unit found')
            with socket.socket() as test:test.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);test.bind(('127.0.0.1',9417))
            directory(ROOT,0o700);directory(DATA.parent,0o755);directory(DATA,0o700)
            created={}
            try:
                for name,data in assets.items():
                    path=pathlib.Path('/etc/systemd/system')/name;atomic(path,data.encode(),0o644);created[path]=hashlib.sha256(data.encode()).hexdigest()
                atomic(ROOT/'access-token',secrets.token_hex(32).encode())
                record={'marker':'quiet-guard-dashboard-v1','enabled':False,'files':{str(p):d for p,d in created.items()}};save(record)
            except Exception:
                for path,digest in created.items():
                    if hashlib.sha256(read(path)).hexdigest()==digest:path.unlink()
                for path in [ROOT/'access-token',ROOT/'ownership.json']:
                    if path.exists():path.unlink()
                for path in [ROOT,DATA]:
                    try:path.rmdir()
                    except OSError:pass
                raise
        record=owned(assets)
        if operation=='enable':start(record);print('Dashboard ready on server loopback. Run sudo quiet-guard dashboard login for your private access link.')
        elif operation=='login':
            if not record['enabled']:raise ValueError('Enable the dashboard before requesting a login link')
            print('http://127.0.0.1:9417/#access='+read(ROOT/'access-token',128).decode())
        elif operation=='rotate-token':
            was_enabled=record['enabled'];stop(record);atomic(ROOT/'access-token',secrets.token_hex(32).encode())
            if was_enabled:start(record)
            print('Access key replaced. Retrieve a new link with dashboard login.')
        elif operation in ['disable','remove']:
            stop(record)
            if operation=='remove':
                archive=DATA.parent/('dashboard-archive-'+secrets.token_hex(8));directory(archive,0o700)
                if (DATA/'jobs.json').exists():read(DATA/'jobs.json',262144);(DATA/'jobs.json').rename(archive/'jobs.json')
                for name in record['files']:pathlib.Path(name).unlink()
                (ROOT/'access-token').unlink();(ROOT/'ownership.json').unlink()
                for path in [ROOT,DATA]:
                    try:path.rmdir()
                    except OSError:pass
                system('daemon-reload')
            print('Dashboard stopped. SSH/WAF/exposure components keep their current settings.')
        else:print(json.dumps({'enabled':record['enabled'],'listen':'127.0.0.1:9417','authentication_required':True}))

try:main()
except Exception as error:print('Dashboard setup: '+str(error),file=sys.stderr);sys.exit(1)
