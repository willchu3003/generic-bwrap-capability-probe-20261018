"""Fixed synthetic role program; never imports application or customer data."""
import ctypes as C
import errno
import fcntl
import json
import os
import resource
import stat
import sys
import threading
import time
from pathlib import Path
from common import (CODE, PUB, SUP, WORK, ROLES, atomic_json, identity_ok,
                    proc_status, read_json, remove_contents_fd, usage_fd)
from policy import accepts_result

RESULT = {"checks": []}


def check(name, passed, **evidence):
    RESULT["checks"].append({"name": name, "pass": bool(passed), **evidence})


def denied(name, operation):
    try:
        value = operation()
    except OSError as exc:
        check(name, exc.errno in (errno.EPERM, errno.EACCES), errno=exc.errno)
    else:
        if isinstance(value, int):
            os.close(value)
        check(name, False, observation="unexpected success")


def identities(role):
    data = proc_status()
    allowed = (10001, 10011, 10012, 10013) if role == "T" else (ROLES[role],)
    check("identity", identity_ok(data, ROLES[role], allowed), proc_status=data)
    allowed_env = {"PATH", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PROBE_SLOT"}
    check("environment_names", set(os.environ) == allowed_env,
          names=sorted(os.environ))


def setup():
    identities("T")
    secret = WORK / "trusted" / "dummy-secret"
    secret.write_bytes(b"synthetic-only-private-marker\n")
    secret.chmod(0o600)
    for role in "PVR":
        inp = WORK / "inputs" / role / "input"
        inp.write_bytes(b"synthetic-input-" + role.encode() + b"\n")
        inp.chmod(0o440)
        st = inp.stat()
        check("input_ownership_" + role,
              st.st_uid == ROLES["T"] and st.st_gid == ROLES[role]
              and stat.S_IMODE(st.st_mode) == 0o440,
              uid=st.st_uid, gid=st.st_gid, mode=oct(stat.S_IMODE(st.st_mode)))
        (WORK / "scratch" / role / "other-role-marker").write_text("synthetic\n")


def cleanup():
    identities("T")
    secret = WORK / "trusted" / "dummy-secret"
    size, files = (secret.stat().st_size, 1) if secret.exists() else (0, 0)
    quarantines = []
    for lane in ("inputs", "scratch"):
        for role in "PVR":
            path = WORK / lane / role
            try:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    subtotal, count = usage_fd(fd)
                    size, files = size + subtotal, files + count
                    remove_contents_fd(fd)
                finally:
                    os.close(fd)
                check("cleanup_" + lane + role, not any(path.iterdir()))
            except OSError as exc:
                path.chmod(0)
                quarantines.append({"lane": lane, "role": role, "errno": exc.errno})
                check("cleanup_" + lane + role, False, quarantine=True, errno=exc.errno)
    secret.unlink(missing_ok=True)
    RESULT["quarantines"] = quarantines
    RESULT.update(work_bytes_before_cleanup=size, work_files_before_cleanup=files,
                  work_measurement_complete=not quarantines)
    check("work_byte_bound", not quarantines and size <= 65536, bytes=size,
          measurement_complete=not quarantines)


def check_fds():
    found = []
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        try:
            target = os.readlink("/proc/self/fd/" + name)
            mode = os.fstat(fd).st_mode
            access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        except FileNotFoundError:
            continue
        found.append({"fd": fd, "target": target, "access": access,
                      "regular": stat.S_ISREG(mode), "char": stat.S_ISCHR(mode)})
    check("fd_whitelist", len(found) == 3 and {x["fd"] for x in found} == {0, 1, 2}
          and all((x["fd"] == 0 and x["char"] and x["access"] == os.O_RDONLY)
                  or (x["fd"] in (1, 2) and x["regular"]
                      and x["access"] == os.O_WRONLY) for x in found), fds=found)


def group_a(role):
    identities(role)
    check_fds()
    inp = WORK / "inputs" / role / "input"
    check("read_own_input", inp.read_bytes() == b"synthetic-input-" + role.encode() + b"\n")
    out = WORK / "scratch" / role / "positive-output"
    out.write_text("synthetic-output\n")
    check("write_own_scratch", out.read_text() == "synthetic-output\n")
    denied("cannot_regain_uid0", lambda: os.setuid(0))
    denied("cannot_regain_gid0", lambda: os.setgid(0))
    denied("cannot_read_T_secret", lambda: os.open(WORK / "trusted" / "dummy-secret", os.O_RDONLY))
    denied("cannot_write_input", lambda: os.open(inp, os.O_WRONLY))
    denied("cannot_chmod_T_input", lambda: os.chmod(inp, 0o600))
    denied("cannot_write_code", lambda: os.open(CODE / "role.py", os.O_WRONLY))
    denied("cannot_access_supervisor_control", lambda: os.open(SUP, os.O_RDONLY | os.O_DIRECTORY))
    denied("cannot_read_dispatch_token", lambda: os.open("/run/probe-auth/token", os.O_RDONLY))
    for other in "PVR":
        if other != role:
            denied("cannot_write_" + other, lambda other=other: os.open(
                WORK / "scratch" / other / "foreign-write", os.O_WRONLY | os.O_CREAT, 0o600))
            denied("cannot_read_" + other, lambda other=other: os.open(
                WORK / "scratch" / other / "other-role-marker", os.O_RDONLY))
    h = read_json(PUB / "http-identity.json")
    denied("cannot_read_T_proc_environ", lambda: os.open(f"/proc/{h['pid']}/environ", os.O_RDONLY))
    denied("cannot_read_T_proc_secret_fd", lambda: os.open(f"/proc/{h['pid']}/fd/{h['secret_fd']}", os.O_RDONLY))
    RESULT["platform_secret_file"] = "NOT_CONFIGURED_NOT_TESTED"


def syscall_observation(lib, libc, name):
    from linux_filter import syscall_number
    args = {
        "socket": (1, 1, 0), "socketpair": (1, 1, 0, C.c_void_p()),
        "connect": (-1, C.c_void_p(), 0), "sendto": (-1, C.c_void_p(), 0, 0, C.c_void_p(), 0),
        "sendmsg": (-1, C.c_void_p(), 0), "fork": (),
        "clone": (0, C.c_void_p(), C.c_void_p(), C.c_void_p(), 0),
        "clone3": (C.c_void_p(), 0), "setsid": (), "setpgid": (0, 0),
        "unshare": (0,), "setns": (-1, 0), "ptrace": (2, os.getpid(), 0, 0),
        "process_vm_readv": (os.getpid(), C.c_void_p(), 0, C.c_void_p(), 0, 0),
        "process_vm_writev": (os.getpid(), C.c_void_p(), 0, C.c_void_p(), 0, 0),
        "io_uring_setup": (0, C.c_void_p()), "io_uring_enter": (-1, 0, 0, 0, C.c_void_p(), 0),
        "io_uring_register": (-1, 0, C.c_void_p(), 0)}
    C.set_errno(0)
    ret = libc.syscall(syscall_number(lib, name), *args[name])
    error = C.get_errno() if ret == -1 else 0
    if name in ("fork", "clone") and ret == 0:
        os._exit(91)  # a single unexpected synthetic child; no recursive dispatch
    if name in ("fork", "clone") and ret > 0:
        os.waitpid(ret, 0)
    if name == "socket" and ret >= 0:
        os.close(ret)
    return {"return": ret, "errno": error}


def group_b(role):
    from linux_filter import install, library
    identities(role)
    lib = library()
    libc = C.CDLL(None, use_errno=True)
    libc.syscall.restype = C.c_long
    # Baselines never connect, send data, fork, create namespaces or alter a group.
    names = ("socket", "connect", "sendmsg", "io_uring_setup", "io_uring_enter", "io_uring_register", "clone3")
    baseline = {name: syscall_observation(lib, libc, name) for name in names}
    before = proc_status()
    RESULT["filter"] = install(WORK / "scratch" / role / "export.bpf")
    after = proc_status()
    check("filter_installed", after.get("Seccomp") == "2"
          and int(after.get("Seccomp_filters", "0")) > int(before.get("Seccomp_filters", "0")),
          before=before, after=after)
    check("read_after_filter", (WORK / "inputs" / role / "input").read_bytes().startswith(b"synthetic-input-"))
    thread_result = []
    thread = threading.Thread(target=lambda: thread_result.append("ok"))
    thread.start()
    thread.join(1)
    check("thread_after_filter", not thread.is_alive() and thread_result == ["ok"])
    tested = ("socket", "socketpair", "connect", "sendto", "sendmsg", "fork", "clone", "clone3",
              "setsid", "setpgid", "unshare", "setns", "ptrace", "process_vm_readv",
              "process_vm_writev", "io_uring_setup", "io_uring_enter", "io_uring_register")
    for name in tested:
        result = syscall_observation(lib, libc, name)
        expected = errno.ENOSYS if name == "clone3" else errno.EPERM
        prior = baseline.get(name)
        check("deny_" + name, result == {"return": -1, "errno": expected},
              observation=result, baseline=prior,
              attribution="outer_already_denied_or_same_errno" if prior == result
                          else "inner_filter_installed; see baseline where present")


def lifecycle(role, config):
    identities(role)
    if config["case"] in ("timeout", "old_job"):
        from linux_filter import install
        RESULT["filter"] = install(WORK / "scratch" / role / "export.bpf")
        if config["case"] == "old_job":
            atomic_json(WORK / "scratch" / role / "old-output.json",
                        {"generation": 0, "complete": False, "marker": "partial-synthetic"})
        print(json.dumps({"started": True, "generation": config["generation"],
                          "readiness": RESULT}), flush=True)
        time.sleep(10)
    elif config["case"] == "controller_old":
        denied("T_cannot_signal_P", lambda: os.kill(config["target_pid"], 0))
        print(json.dumps(RESULT), flush=True)
        time.sleep(10)
    elif config["case"] == "controller_rebuild":
        old = read_json(WORK / "scratch" / "P" / "old-output.json")
        check("old_output_rejected", not accepts_result(1, old["generation"], old["complete"]),
              expected_generation=1, observed_generation=old["generation"])
        new = WORK / "scratch" / "P" / "generation-1"
        new.mkdir(mode=0o2770)
        new.chmod(0o2770)
        check("new_generation_separate_path", new.is_dir())
    elif config["case"] == "new_job":
        from linux_filter import install
        RESULT["filter"] = install(WORK / "scratch" / role / "export.bpf")
        new = WORK / "scratch" / role / "generation-1" / "result.json"
        atomic_json(new, {"generation": 1, "complete": True, "synthetic": True})
        check("new_generation_output", new.is_file())
    elif config["case"] == "verify_generation":
        new = read_json(WORK / "scratch" / "P" / "generation-1" / "result.json")
        check("new_generation_accepted", accepts_result(1, new["generation"], new["complete"]))


def main():
    slot = os.environ["PROBE_SLOT"]
    config = read_json(PUB / ("slot-" + slot + ".json"))
    role = "T" if slot in ("T", "C") else slot
    os.chdir(WORK / "trusted" if role == "T" else WORK / "scratch" / role)
    RESULT.update(slot=slot, role=role, case=config["case"], generation=config["generation"], seq=config["seq"])
    gate = PUB / ("gate-" + slot + "-" + str(config["seq"]))
    deadline = time.monotonic() + 4
    while not gate.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("supervisor start gate not supplied")
        time.sleep(0.01)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_CPU, (4, 4))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if config["case"] == "setup":
        setup()
    elif config["case"] == "cleanup":
        cleanup()
    elif config["case"] == "A":
        group_a(role)
    elif config["case"] == "B":
        group_b(role)
    else:
        lifecycle(role, config)
    RESULT["pass"] = bool(RESULT["checks"]) and all(x["pass"] for x in RESULT["checks"])
    print(json.dumps(RESULT, sort_keys=True), flush=True)
    return 0 if RESULT["pass"] else 20


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(json.dumps({"error_type": type(exc).__name__, "error": str(exc)[:500],
                          "errno": getattr(exc, "errno", None),
                          "partial": RESULT}), file=sys.stderr, flush=True)
        sys.exit(21)
