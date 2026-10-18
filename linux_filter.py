"""Small ctypes adapter to maintained libseccomp. No import-time OS changes."""
import ctypes as C
import errno
import hashlib
import os
import platform
from pathlib import Path
from policy import DENY_EPERM, CLONE_THREAD, CLONE_PARENT, NAMESPACE_FLAGS, POLICY_SHA256


class Compare(C.Structure):
    _fields_ = [("arg", C.c_uint), ("op", C.c_int),
                ("datum_a", C.c_uint64), ("datum_b", C.c_uint64)]


def library():
    lib = C.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [C.c_uint32]
    lib.seccomp_init.restype = C.c_void_p
    lib.seccomp_release.argtypes = [C.c_void_p]
    lib.seccomp_attr_set.argtypes = [C.c_void_p, C.c_int, C.c_uint32]
    lib.seccomp_syscall_resolve_name.argtypes = [C.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = C.c_int
    lib.seccomp_rule_add_array.argtypes = [C.c_void_p, C.c_uint32, C.c_int,
                                         C.c_uint, C.POINTER(Compare)]
    lib.seccomp_export_bpf.argtypes = [C.c_void_p, C.c_int]
    lib.seccomp_load.argtypes = [C.c_void_p]
    lib.seccomp_version.restype = C.POINTER(C.c_uint)
    return lib


def syscall_number(lib, name):
    nr = lib.seccomp_syscall_resolve_name(name.encode())
    if nr < 0:
        raise RuntimeError("unresolved syscall " + name)
    return nr


def install(export_path):
    if platform.machine() != "x86_64":
        raise RuntimeError("only x86_64 approved")
    lib = library()
    ctx = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW; native architecture only
    if not ctx:
        raise RuntimeError("seccomp_init failed")

    def checked(rc):
        if rc < 0:
            raise OSError(-rc, os.strerror(-rc))

    def rule(name, error, comparison=None):
        checked(lib.seccomp_rule_add_array(ctx, 0x50000 | error,
            syscall_number(lib, name), int(comparison is not None),
            C.byref(comparison) if comparison is not None else None))

    try:
        checked(lib.seccomp_attr_set(ctx, 2, 0x80000000))  # ACT_BADARCH KILL_PROCESS
        for name in DENY_EPERM:
            rule(name, errno.EPERM)
        rule("clone3", errno.ENOSYS)
        rule("clone", errno.EPERM, Compare(0, 7, CLONE_THREAD, 0))  # MASKED_EQ
        for flag in (CLONE_PARENT, *NAMESPACE_FLAGS):
            rule("clone", errno.EPERM, Compare(0, 7, flag, flag))
        fd = os.open(export_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            checked(lib.seccomp_export_bpf(ctx, fd))
        finally:
            os.close(fd)
        bpf_sha = hashlib.sha256(Path(export_path).read_bytes()).hexdigest()
        os.unlink(export_path)
        version = lib.seccomp_version()
        result = {"policy_sha256": POLICY_SHA256, "bpf_sha256": bpf_sha,
                  "libseccomp_version": ".".join(str(version[i]) for i in range(3)),
                  "architecture": platform.machine(), "extra_architectures": []}
        checked(lib.seccomp_load(ctx))
        return result
    finally:
        lib.seccomp_release(ctx)
