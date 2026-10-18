"""One bounded, local-only synthetic namespace/seccomp capability run."""
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

from contract import NAMESPACES, program

MARKER = b'GENERIC_CAPABILITY_PROBE_V1\n'
ROOT = Path(__file__).resolve().parent


def reply(outcome, code, **facts):
    return {'schema':'generic-bwrap-capability-v1', 'outcome':outcome, 'code':code, **facts}


def classify(stderr):
    """Return fixed codes only, never echo untrusted process text to HTTP/logs."""
    text = stderr.decode('utf-8', errors='replace').lower()
    if any(x in text for x in ('no space left', 'resource temporarily unavailable', 'out of memory', 'cannot allocate memory')):
        return 'INCONCLUSIVE', 'RUNTIME_RESOURCE_LIMIT'
    denied = ('operation not permitted' in text or 'permission denied' in text)
    if 'no permissions to create new namespace' in text or ('namespace' in text and denied):
        return 'INCOMPATIBLE_SCOPED', 'NAMESPACE_CREATION_DENIED'
    if 'seccomp' in text and denied:
        return 'INCOMPATIBLE_SCOPED', 'SECCOMP_ATTACH_DENIED'
    if ('mount' in text or 'pivot_root' in text) and denied:
        return 'INCOMPATIBLE_SCOPED', 'REQUIRED_MOUNT_DENIED'
    return 'INCONCLUSIVE', 'SANDBOX_SETUP_OR_EXECUTION_ERROR'


def command(directory, filtered):
    directory = Path(directory)
    args = ['/usr/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-net',
            '--unshare-ipc', '--unshare-uts', '--cap-drop', 'ALL',
            '--die-with-parent', '--clearenv', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    system = [Path(x) for x in ('/usr/lib','/usr/lib64','/lib','/lib64','/etc/ld.so.cache') if Path(x).exists()]
    binary = Path(sys.executable).resolve()
    library = Path(sys.base_prefix) / 'lib'
    required = [binary, library / f'python{sys.version_info.major}.{sys.version_info.minor}',
                *sorted(library.glob('libpython*.so*'))]
    for path in system + required:
        args += ['--ro-bind', str(path.resolve()), str(path)]
    args += ['--ro-bind', str(ROOT/'child.py'), '/probe/child.py',
             '--ro-bind', str(Path('/usr/bin/true').resolve()), '/probe/true',
             '--ro-bind', str(directory/'fixture'), '/fixture',
             '--bind', str(directory/'work'), '/work', '--chdir', '/work',
             '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
             '--setenv', 'PYTHONDONTWRITEBYTECODE', '1', '--setenv', 'TMPDIR', '/work']
    fd = None
    if filtered:
        fd = os.open(directory/'filter.bpf', os.O_RDONLY)
        args += ['--seccomp', str(fd)]
    args += ['--', str(binary), '-I', '/probe/child.py',
             'filtered' if filtered else 'baseline', str(directory/'outside')]
    return args, fd


def group_gone(pid):
    try: os.killpg(pid, 0)
    except ProcessLookupError: return True
    return False


def finish_owned(process):
    """Only the new session created for this synthetic child is signalled."""
    if process.poll() is None or not group_gone(process.pid):
        try: os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            process.wait(timeout=3)
    deadline = time.monotonic() + 2
    while not group_gone(process.pid) and time.monotonic() < deadline:
        time.sleep(.05)
    return group_gone(process.pid)


def run_stage(directory, filtered, cancel):
    args, fd = command(directory, filtered)
    process = None; timed_out = False; cancelled = False; cleaned = False
    started = time.monotonic()
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}, cwd=directory,
                start_new_session=True, pass_fds=() if fd is None else (fd,))
            if fd is not None: os.close(fd); fd = None
            deadline = time.monotonic() + 20
            while process.poll() is None:
                if cancel.is_set(): cancelled = True; break
                if time.monotonic() >= deadline: timed_out = True; break
                if os.fstat(stdout.fileno()).st_size > 65536 or os.fstat(stderr.fileno()).st_size > 65536:
                    timed_out = True; break
                cancel.wait(.05)
            cleaned = finish_owned(process)
            stderr.seek(0); error = stderr.read(65536)
    finally:
        if fd is not None: os.close(fd)
        if process is not None and not cleaned: cleaned = finish_owned(process)
    metadata = {'exit':process.returncode, 'elapsed_seconds':round(time.monotonic()-started,3),
                'owned_process_group_empty':cleaned,'stderr_sha256':hashlib.sha256(error).hexdigest()}
    if not cleaned: return reply('INCONCLUSIVE','CLEANUP_NOT_PROVEN',**metadata)
    if cancelled: return reply('INCONCLUSIVE','CANCELLED',**metadata)
    if timed_out: return reply('INCONCLUSIVE','TIME_OR_OUTPUT_LIMIT',**metadata)
    result = Path(directory)/'work/result.json'
    if not result.is_file():
        outcome, code = classify(error)
        if process.returncode is not None and process.returncode < 0:
            outcome, code = 'INCONCLUSIVE', 'PROCESS_SIGNALLED'
        return reply(outcome,code,**metadata)
    if result.stat().st_size > 16384: return reply('INCONCLUSIVE','CHILD_RESULT_LIMIT',**metadata)
    value = json.loads(result.read_text())
    expected = {'allowed_read','allowed_write','read_only_mount','unmounted_synthetic_file_hidden',
                'capabilities_dropped','thread_allowed'}
    if filtered:
        expected |= {'socket_denied','fork_denied','spawn_denied','setpgid_denied','setsid_denied',
                     'unshare_denied','setns_denied','cross_process_read_denied',
                     'cross_process_write_denied','clone3_fallback'}
    checks = value.get('checks',{})
    if set(checks) != expected or any(type(v) is not bool for v in checks.values()):
        return reply('INCONCLUSIVE','INVALID_CHILD_RESULT',**metadata)
    ids = value.get('namespace_ids',{})
    for name in NAMESPACES:
        checks['namespace_'+name] = bool(ids.get(name)) and ids[name] != os.readlink('/proc/self/ns/'+name)
    if process.returncode != 0 or not all(checks.values()):
        return reply('INCOMPATIBLE_SCOPED','CONTRACT_ASSERTION_FAILED',checks=checks,**metadata)
    return reply('PASS_SCOPED','STAGE_PASSED',checks=checks,**metadata)


def run_probe(cancel=None):
    cancel = cancel or threading.Event()
    if platform.system() != 'Linux' or platform.machine() not in {'x86_64','amd64'} or sys.byteorder != 'little':
        return reply('INCONCLUSIVE','LINUX_AMD64_REQUIRED')
    if os.geteuid() == 0: return reply('INCONCLUSIVE','NON_ROOT_IDENTITY_REQUIRED')
    binary = Path('/usr/bin/bwrap')
    if not binary.is_file(): return reply('INCONCLUSIVE','BWRAP_NOT_INSTALLED')
    if binary.stat().st_mode & (stat.S_ISUID | stat.S_ISGID):
        return reply('INCONCLUSIVE','UNPRIVILEGED_BWRAP_REQUIRED')
    if not Path('/usr/bin/true').is_file(): return reply('INCONCLUSIVE','SYNTHETIC_HELPER_MISSING')
    policy = program()
    facts = {'architecture':'linux/amd64','outer_uid_nonroot':True,
             'bwrap_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
             'policy_sha256':hashlib.sha256(policy).hexdigest()}
    stages = []
    with tempfile.TemporaryDirectory(prefix='generic-capability-') as temporary:
        directory = Path(temporary)
        (directory/'fixture').mkdir(); (directory/'work').mkdir()
        (directory/'fixture/input').write_bytes(MARKER)
        (directory/'fixture/input').chmod(0o644)  # Writable owner, RO must be enforced by mount.
        (directory/'outside').write_bytes(MARKER)
        (directory/'filter.bpf').write_bytes(policy)
        for filtered in (False,True):
            (directory/'work/result.json').unlink(missing_ok=True)
            stage = run_stage(directory,filtered,cancel)
            stage['stage'] = 'NAMESPACE_MOUNT_AND_SECCOMP' if filtered else 'NAMESPACE_AND_MOUNT'
            stages.append(stage)
            if stage['outcome'] != 'PASS_SCOPED':
                return reply(stage['outcome'],stage['code'],stages=stages,**facts)
    return reply('PASS_SCOPED','REQUIRED_CAPABILITIES_OBSERVED',stages=stages,**facts)
