"""Start an owned test process and apply one validated in-memory branch change."""
import ctypes,hashlib,json,os,signal,subprocess,time
from experimental.srb378.live_output import popen as live_popen
from pathlib import Path
EXPECTED_SHA='59d71614ac508f77b4b6a338564db18e5163119059badf43175549d94634821e'
PATCH=0x1b490ff
CONTEXT=bytes.fromhex('0fb60348c78790000000000000004c8b6310888798000000')
REPLACEMENT=b'\x31\xc0\x90'
READY_VA=0x1b49177
READY=bytes.fromhex('4c8b63304c2b63280f1185c000000048c785d000000000000000')
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
    # SRB process startup clears exported terminal dimensions even in an otherwise valid environment.
    child_env=os.environ.copy()
    removed_terminal_dimensions=[key for key in ('COLUMNS','LINES','LD_PRELOAD','LD_AUDIT') if key in child_env]
    for key in removed_terminal_dimensions:child_env.pop(key)
    p=live_popen(args,cwd=binary.parent,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,
        start_new_session=True,env=child_env,preexec_fn=lambda:trace(0,0))
    mem=None;stopped=False
    try:
        (run/'srb-process.json').write_text(json.dumps({'pid':p.pid,'ticks':Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()[19],'argument':str(binary)}))
        _,status=os.waitpid(p.pid,0)
        if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=signal.SIGTRAP:raise RuntimeError('Missing exec stop '+str(status))
        maps=Path(f'/proc/{p.pid}/maps').read_text()
        line=next(x for x in maps.splitlines() if str(binary) in x and x.split()[2]=='00000000')
        base=int(line.split('-')[0],16)
        mem=os.open(f'/proc/{p.pid}/mem',os.O_RDWR)
        trace(17,p.pid)
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            try:context=os.pread(mem,len(CONTEXT),base+PATCH)
            except OSError:context=b''
            if context==CONTEXT and os.pread(mem,len(READY),base+READY_VA)==READY and out is not None and os.fstat(out.fileno()).st_size>0:break
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
              'removed_terminal_dimensions':removed_terminal_dimensions,'startup_output_seen':os.fstat(out.fileno()).st_size}
        (run/'runtime-patch.json').write_text(json.dumps(info,indent=2))
        # Keep the already-authorized handle: SRB may make /proc/pid/mem
        # non-openable later during initialization. The controller only reads it.
        p._srb_validated_mem_fd=os.dup(mem)
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
