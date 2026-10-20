"""Preserve SRB startup diagnostics by giving only its output a pseudo-terminal."""
import errno
import fcntl
import os
import pty
import signal
import subprocess
import threading


def popen(*args, **kwargs):
    out = kwargs.get('stdout')
    if out is None or not hasattr(out, 'fileno'):
        raise ValueError('SRB live logging requires an open output file')
    master, slave = pty.openpty()
    output = os.dup(out.fileno())
    # Append also remains correct when the controller truncates a rotated log.
    flags = fcntl.fcntl(output, fcntl.F_GETFL)
    fcntl.fcntl(output, fcntl.F_SETFL, flags | os.O_APPEND)
    kwargs['stdout'] = slave
    kwargs['stderr'] = slave
    child = None
    try:
        child = subprocess.Popen(*args, **kwargs)
    except BaseException:
        os.close(master)
        os.close(output)
        raise
    finally:
        os.close(slave)
    errors = []

    def drain():
        try:
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not data:
                    break
                view = memoryview(data)
                while view:
                    count = os.write(output, view)
                    if count == 0:
                        raise OSError('Short SRB log write')
                    view = view[count:]
        except BaseException as error:
            errors.append(repr(error))
        finally:
            os.close(master)
            os.close(output)

    thread = threading.Thread(target=drain, name='srb-live-output', daemon=True)
    child._srb_output_thread = thread
    child._srb_output_errors = errors
    try:
        thread.start()
    except BaseException:
        os.close(master)
        os.close(output)
        try:
            if kwargs.get('start_new_session'):
                os.killpg(child.pid, signal.SIGKILL)
            else:
                child.kill()
            child.wait(timeout=3)
        except OSError:
            pass
        raise
    return child
