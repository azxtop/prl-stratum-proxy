"""Bounded standalone SRB 3.7.8 experiment; owns only its child process group."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from experimental.srb378.proxy import Proxy, LIMIT


def write(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)


def read(path, default=None):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


def identity(pid, argument):
    ticks = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]
    return dict(pid=pid, ticks=ticks, argument=str(argument))


def alive(info):
    try:
        p = Path('/proc', str(info['pid']))
        stat = (p / 'stat').read_text().rsplit(')', 1)[1].split()
        return stat[0] != 'Z' and stat[19] == str(info['ticks']) and info['argument'].encode() in (p / 'cmdline').read_bytes().split(b'\0')
    except (OSError, TypeError, KeyError, IndexError):
        return False


def stop_owned(info):
    if not alive(info):
        return
    if os.getpgid(info['pid']) != info['pid']:
        raise RuntimeError('Refusing to stop a process outside its recorded session')
    os.killpg(info['pid'], signal.SIGTERM)
    end = time.monotonic() + 15
    while alive(info) and time.monotonic() < end:
        time.sleep(.2)
    if alive(info):
        os.killpg(info['pid'], signal.SIGKILL)


def config(path):
    path = Path(path).resolve()
    c = read(path)
    if not isinstance(c, dict) or not isinstance(c.get('account'), str) or not c['account'] or c['account'] == 'YOUR_POOL_ACCOUNT':
        raise ValueError('Configure your own pool account')
    worker = c.get('worker', '')
    suffix = c.get('fee_suffix', 'dev')
    if not isinstance(worker, str) or not isinstance(suffix, str) or not re.fullmatch('[a-z0-9]{1,15}', worker) or not re.fullmatch('[a-z0-9]{1,15}', worker + suffix):
        raise ValueError('Normal and redirected worker names must each contain 1-15 lowercase letters/digits')
    c['fee_worker'] = worker + suffix
    if not isinstance(c.get('pools'), list) or not c['pools']:
        raise ValueError('At least one TLS PRL upstream is required')
    for p in c['pools']:
        if not isinstance(p, dict) or not isinstance(p.get('host'), str) or not p['host'] or p['host'].endswith('example.org'):
            raise ValueError('Replace example pool hosts')
        if type(p.get('port')) is not int or not 1 <= p['port'] <= 65535 or type(p.get('verify_tls', True)) is not bool:
            raise ValueError('Invalid upstream port or verify_tls')
    for key, default in (('socks_port', 25583), ('api_port', 25580)):
        c.setdefault(key, default)
        if type(c[key]) is not int or not 1 <= c[key] <= 65535:
            raise ValueError('Invalid local port')
    if c['socks_port'] == c['api_port']:
        raise ValueError('SOCKS and API ports must differ')
    for key in ('data_dir', 'certificate', 'key'):
        p = Path(c[key])
        c[key] = str((path.parent / p).resolve() if not p.is_absolute() else p)
    return c


def api(port):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:' + str(port), timeout=3) as r:
        return json.loads(r.read(2 * 1024**2))


def guard(run):
    """No recovery hooks: stop only the recorded SRB child if monitoring disappears."""
    info = read(run / 'run.json')
    while True:
        if (run / 'finished.json').exists():
            return
        lease = read(run / 'lease.json', {})
        now = time.monotonic()
        expired = now > lease.get('deadline_monotonic', 0) or now > info['hard_deadline_monotonic']
        if expired or not alive(info['controller']):
            stop_owned(read(run / 'srb-process.json'))
            write(run / 'guard-stopped.json', dict(time=time.time(),reason='lease_expired_or_controller_exited',other_miners_restored=False))
            return
        time.sleep(2)


async def experiment(args):
    import fcntl
    from experimental.srb378 import pin_launch
    c = config(args.config)
    binary = Path(args.binary).resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != pin_launch.EXPECTED_SHA:
        raise ValueError('Executable is not the verified SRB 3.7.8 Linux artifact')
    if not args.enable_process_tls_patch:
        raise ValueError('Read README.md and explicitly pass --enable-process-tls-patch')
    # This public entry point never stops an existing miner or CPU workload.
    gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid,process_name', '--format=csv,noheader'], capture_output=True, text=True, timeout=15, check=True)
    if gpu.stdout.strip():
        raise ValueError('GPU workload exists; stop it yourself before this isolated experiment')
    data = Path(c['data_dir']); data.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = (data / 'session.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Bind both ports before starting a native process.
    import socket
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', c['api_port']))
    run = data / ('run-' + time.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:8])
    run.mkdir(mode=0o700)
    proxy = Proxy(run, c)
    server = await asyncio.start_server(proxy.handle, '127.0.0.1', c['socks_port'], limit=LIMIT)
    script = Path(__file__).resolve()
    info = dict(time=time.time(),controller=identity(os.getpid(),script),hard_deadline_monotonic=time.monotonic()+args.seconds+90,limit_seconds=args.seconds)
    write(run / 'run.json', info)
    def pulse():
        write(run / 'lease.json', dict(time=time.time(),deadline_monotonic=time.monotonic()+45))
    pulse()
    result = dict(completed=False,complete_channel_coverage_proven=False,pool_dashboard_credit_verified=False,other_miners_restored=False)
    child = None; mem = None; guardian = None; last_good = time.monotonic(); previous = None
    stop = asyncio.Event(); loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    start = time.monotonic(); last_audit = 0
    try:
        with (run / 'guard-console.log').open('ab') as log:
            guardian = subprocess.Popen([sys.executable, str(script), '--guard', str(run)], stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        write(run / 'guard.json', identity(guardian.pid,script))
        p = c['pools'][0]; host = '['+p['host']+']' if ':' in p['host'] else p['host']
        command = [str(binary),'--disable-cpu','--disable-gpu-amd','--disable-gpu-intel','--disable-msr-tweaks','--algorithm','pearlhash','--pool',host+':'+str(p['port']),'--tls','true','--wallet',c['account'],'--worker',c['worker'],'--password','x','--gpu-disable-oc','--proxy','127.0.0.1:'+str(c['socks_port']),'--api-enable','--api-port',str(c['api_port']),'--api-rig-name',c['worker'],'--max-no-share-sent','3600','--extended-log']
        with (run / 'srb-console.log').open('ab') as log:
            child = await asyncio.to_thread(pin_launch.start,command,run,log)
        mem = child._srb_validated_mem_fd
        base = int(read(run / 'runtime-patch.json')['image_base'],16)
        print('Bounded SRB experiment running; Ctrl+C stops this child only. Logs: '+str(run),flush=True)
        while not stop.is_set() and time.monotonic()-start < args.seconds:
            pulse()
            if child.poll() is not None or guardian.poll() is not None:
                raise RuntimeError('Miner or independent guard exited')
            if os.pread(mem,3,base+pin_launch.PATCH) != pin_launch.REPLACEMENT:
                raise RuntimeError('Validated process-memory change is absent')
            snap = proxy.snapshot()
            if snap['uncovered_prl'] or snap['errors'] >= 8:
                raise RuntimeError('Uncovered PRL authorization or repeated proxy errors')
            if any(time.time()-x['submitted_at']>120 for pend in proxy.pending.values() for x in pend.values()):
                raise RuntimeError('Submission acknowledgement exceeded 120 seconds')
            if time.monotonic()-start>180 and not snap['roles']['main']['accepted']:
                raise RuntimeError('No real main share accepted within 180 seconds')
            row = dict(time=time.time(),elapsed=time.monotonic()-start,proxy=snap)
            try:
                a = await asyncio.to_thread(api,c['api_port']); algo=a['algorithms'][0]
                current=(a['mining_time'],algo['shares']['accepted'])
                if previous is not None and any(x<y for x,y in zip(current,previous)):
                    raise RuntimeError('Native uptime or accepted-share counter reset')
                previous=current
                rates=list(algo['hashrate']['gpu'].values())
                if rates and all(x>0 for x in rates):
                    last_good=time.monotonic()
                row.update(total_ths=sum(rates)/1e12,api=a)
            except (OSError, ValueError, KeyError, IndexError) as exc:
                row['api_error']=repr(exc)
            if time.monotonic()-last_good>120:
                raise RuntimeError('Positive GPU hashrate not observed for 120 seconds')
            write(run / 'state.json', row)
            with (run / 'samples.jsonl').open('a') as log:
                log.write(json.dumps(row)+'\n')
            if time.monotonic()-last_audit >= 15:
                try:
                    audit=await asyncio.to_thread(subprocess.run,['ss','-Hantup'],capture_output=True,text=True,timeout=10)
                    record=dict(time=time.time(),srb_pid=child.pid,stdout=audit.stdout,stderr=audit.stderr,returncode=audit.returncode)
                except (OSError,subprocess.SubprocessError) as exc:
                    record=dict(time=time.time(),error=repr(exc))
                record['limitations']='Polling can miss short connections; missing process ownership is unknown; no forced egress isolation'
                with (run / 'egress-samples.jsonl').open('a') as log:
                    log.write(json.dumps(record)+'\n')
                last_audit=time.monotonic()
            try:
                await asyncio.wait_for(stop.wait(),5)
            except asyncio.TimeoutError:
                pass
        result.update(completed=True,stop_reason='operator_stop' if stop.is_set() else 'bounded_duration_complete')
    except BaseException as exc:
        result['error']=repr(exc)
        raise
    finally:
        if mem is not None:
            os.close(mem)
        await asyncio.to_thread(stop_owned,read(run / 'srb-process.json'))
        if child is not None:
            await asyncio.to_thread(child.wait,20)
        server.close(); await server.wait_closed()
        await asyncio.sleep(.3)
        result.update(time=time.time(),runtime_seconds=time.monotonic()-start,proxy=proxy.snapshot())
        write(run / 'result.json',result)
        write(run / 'finished.json',dict(time=time.time(),child_stopped=not alive(read(run / 'srb-process.json')),other_miners_restored=False))
        if guardian is not None:
            await asyncio.to_thread(guardian.wait,5)
        print('Stopped owned SRB child; other miners were not managed. Result: '+str(run/'result.json'),flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config');p.add_argument('--binary');p.add_argument('--seconds',type=int,default=900)
    p.add_argument('--enable-process-tls-patch',action='store_true');p.add_argument('--guard',help=argparse.SUPPRESS)
    args=p.parse_args()
    if platform.system()!='Linux' or platform.machine().lower() not in ('x86_64','amd64'):
        p.error('Linux x86_64 is required')
    if args.guard:
        guard(Path(args.guard));return
    if not args.config or not args.binary or not 60<=args.seconds<=4200:
        p.error('--config, --binary and --seconds between 60 and 4200 are required')
    try:
        asyncio.run(experiment(args))
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        p.exit(1,'Error: '+str(exc)+'\n')


if __name__=='__main__':
    main()
