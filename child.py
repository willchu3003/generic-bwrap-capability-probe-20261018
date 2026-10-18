"""Fixed synthetic checks inside bubblewrap. No request-supplied input."""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import sys
import threading

MARKER = b'GENERIC_CAPABILITY_PROBE_V1\n'
NS = ('user', 'pid', 'net', 'ipc', 'uts', 'mnt')


def namespace_ids():
    return {name: os.readlink('/proc/self/ns/' + name) for name in NS}


def check_synthetic(mode, outside):
    checks = {}
    checks['allowed_read'] = Path('/fixture/input').read_bytes() == MARKER
    Path('/work/output').write_bytes(MARKER)
    checks['allowed_write'] = Path('/work/output').read_bytes() == MARKER
    try:
        Path('/fixture/input').write_bytes(b'UNEXPECTED_WRITE')
        checks['read_only_mount'] = False
    except OSError as exc:
        checks['read_only_mount'] = exc.errno == errno.EROFS
    try:
        Path(outside).read_bytes()
        checks['unmounted_synthetic_file_hidden'] = False
    except OSError as exc:
        checks['unmounted_synthetic_file_hidden'] = exc.errno == errno.ENOENT
    status = Path('/proc/self/status').read_text()
    caps = next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:'))
    checks['capabilities_dropped'] = int(caps, 16) == 0
    worked = []
    thread = threading.Thread(target=lambda: worked.append(True))
    thread.start(); thread.join(3)
    checks['thread_allowed'] = not thread.is_alive() and worked == [True]
    if mode == 'filtered':
        try:
            sock = socket.socket(); sock.close()
            checks['socket_denied'] = False
        except OSError as exc:
            checks['socket_denied'] = exc.errno == errno.EPERM
        try:
            pid = os.fork()
            if pid == 0: os._exit(0)
            os.waitpid(pid, 0)
            checks['fork_denied'] = False
        except OSError as exc:
            checks['fork_denied'] = exc.errno == errno.EPERM
        # libc's safe posix_spawn path exercises process creation; never call
        # vfork directly from a Python frame sharing its parent's address space.
        try:
            pid = os.posix_spawn('/probe/true', ['/probe/true'], {})
            os.waitpid(pid, 0)
            checks['spawn_denied'] = False
        except OSError as exc:
            checks['spawn_denied'] = exc.errno == errno.EPERM
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        for name, number, arguments in (
            ('setpgid_denied', 109, (0, 0)), ('setsid_denied', 112, ()),
            ('unshare_denied', 272, (0,)), ('setns_denied', 308, (-1, 0)),
            ('cross_process_read_denied', 310, (0, 0, 0, 0, 0, 0)),
            ('cross_process_write_denied', 311, (0, 0, 0, 0, 0, 0)),
            ('clone3_fallback', 435, (0, 0)),
        ):
            ctypes.set_errno(0)
            result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(x) for x in arguments))
            expected = errno.ENOSYS if number == 435 else errno.EPERM
            checks[name] = result == -1 and ctypes.get_errno() == expected
    return {'checks':checks, 'namespace_ids':namespace_ids()}


if __name__ == '__main__':
    # Arguments are fixed by the local parent, never by HTTP.
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in {'baseline','filtered'}:
            raise ValueError('INVALID_MODE')
        value = check_synthetic(sys.argv[1], sys.argv[2])
    except Exception:
        value = {'checks':{}, 'probe_error':'SYNTHETIC_CHILD_ERROR'}
    Path('/work/result.json').write_text(json.dumps(value, sort_keys=True))
    sys.exit(0 if value.get('checks') and all(value['checks'].values()) else 2)
