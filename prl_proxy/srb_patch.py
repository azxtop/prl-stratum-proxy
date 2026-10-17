"""Start an owned test process and apply one validated in-memory branch change."""
import ctypes,hashlib,json,os,signal,subprocess,time
from pathlib import Path
EXPECTED_SHA='0c3353a74c1107ac340fef9b77749f634c988c552d9f446d6da3d23a43c25a15'
PATCH=0x1cca63f
CONTEXT=bytes.fromhex('0fb60348c78790000000000000004c8b6310888798000000')
REPLACEMENT=b'\x31\xc0\x90'
READY_VA=0x1ccb1eb
READY=bytes.fromhex('e8903e180085c075d24189ece913ffffff')
libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
def trace(req,pid,addr=0,data=0):
    r=libc.ptrace(req,pid,ctypes.c_void_p(addr),ctypes.c_void_p(data))
    if r==-1:raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))
    return r
def start(args,run,out=None):
    if os.name!='posix' or not Path('/proc/self/maps').exists():raise RuntimeError('SRB process patch requires Linux')
    binary=Path(args[0]).resolve();run=Path(run);run.mkdir(parents=True,exist_ok=True,mode=0o700)
    args=[str(binary),*args[1:]]
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=EXPECTED_SHA:raise ValueError('Unexpected executable hash')
    # SRB 3.7.6 rejects exported terminal dimensions even in an otherwise valid environment.
    child_env=os.environ.copy()
    removed_terminal_dimensions=[key for key in ('COLUMNS','LINES') if key in child_env]
    for key in removed_terminal_dimensions:child_env.pop(key)
    p=subprocess.Popen(args,cwd=binary.parent,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,
        start_new_session=True,env=child_env,preexec_fn=lambda:trace(0,0))
    mem=None;stopped=False
    try:
        (run/'srb-process.json').write_text(json.dumps({'pid':p.pid,'start_ticks':Path(f'/proc/{p.pid}/stat').read_text().split()[21]}))
        _,status=os.waitpid(p.pid,0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGTRAP:raise RuntimeError('Missing exec stop '+str(status))
        maps=Path(f'/proc/{p.pid}/maps').read_text()
        line=next(x for x in maps.splitlines() if str(binary) in x and x.split()[2]=='00000000')
        base=int(line.split('-')[0],16)
        mem=os.open(f'/proc/{p.pid}/mem',os.O_RDWR)
        trace(17,p.pid)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            try:context=os.pread(mem,len(CONTEXT),base+PATCH)
            except OSError:context=b''
            if context==CONTEXT and os.pread(mem,len(READY),base+READY_VA)==READY:break
            time.sleep(.0005)
        else:raise RuntimeError('Validated patch context was not observed')
        os.kill(p.pid,signal.SIGSTOP);os.waitpid(p.pid,os.WUNTRACED);stopped=True
        if os.pread(mem,len(CONTEXT),base+PATCH)!=CONTEXT:raise RuntimeError('Patch context changed')
        if os.pwrite(mem,REPLACEMENT,base+PATCH)!=len(REPLACEMENT):raise RuntimeError('Short patch write')
        if os.pread(mem,len(REPLACEMENT),base+PATCH)!=REPLACEMENT:raise RuntimeError('Patch readback failed')
        info={'time':time.time(),'pid':p.pid,'image_base':hex(base),'virtual_address':hex(PATCH),
              'original':CONTEXT[:3].hex(),'replacement':REPLACEMENT.hex(),'context':CONTEXT.hex(),'binary_sha256':EXPECTED_SHA,'file_modified':False,
              'scope':'TLS socket validation mode is disabled in this test process only',
              'isolated_ca_bundle':None,'system_trust_modified':False,
              'removed_terminal_dimensions':removed_terminal_dimensions}
        (run/'runtime-patch.json').write_text(json.dumps(info,indent=2))
        os.kill(p.pid,signal.SIGCONT);stopped=False
        return p
    except BaseException:
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:pass
        raise
    finally:
        if mem is not None:os.close(mem)
