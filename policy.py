"""Pure policy data. Importing this module does not install a filter."""
import hashlib
import json

CLONE_THREAD = 0x10000
CLONE_PARENT = 0x8000
NAMESPACE_FLAGS = (0x80, 0x20000, 0x2000000, 0x4000000,
                   0x8000000, 0x10000000, 0x20000000, 0x40000000)
DENY_EPERM = (
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg",
    "fork", "vfork", "setsid", "setpgid", "unshare", "setns", "ptrace",
    "process_vm_readv", "process_vm_writev", "pidfd_getfd", "kcmp",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "mount", "umount2", "pivot_root", "chroot", "bpf", "userfaultfd",
    "open_by_handle_at", "name_to_handle_at", "perf_event_open",
    "keyctl", "add_key", "request_key"
)
POLICY = {"architecture": "x86_64-only", "default": "ALLOW",
          "bad_arch": "KILL_PROCESS", "errno_EPERM": list(DENY_EPERM),
          "errno_ENOSYS": ["clone3"],
          "clone": {"require_thread": CLONE_THREAD,
                    "deny_flags": [CLONE_PARENT, *NAMESPACE_FLAGS]},
          "scope": "synthetic capability test; not a complete production sandbox"}
POLICY_SHA256 = hashlib.sha256(json.dumps(POLICY, sort_keys=True,
                            separators=(",", ":")).encode()).hexdigest()


def clone_permitted(flags):
    return bool(flags & CLONE_THREAD) and not any(
        flags & flag for flag in (CLONE_PARENT, *NAMESPACE_FLAGS))


STATUSES = frozenset({"ALL_REQUIRED_CAPABILITIES_OBSERVED", "PRECONDITION_NOT_MET",
    "CAPABILITY_DENIED_FOR_THIS_PROFILE", "ISOLATION_CHECK_FAILED",
    "INCONCLUSIVE", "CLEANUP_UNKNOWN"})


def accepts_result(expected_generation, result_generation, complete):
    return (type(expected_generation) is int and type(result_generation) is int
            and expected_generation >= 0 and complete is True
            and expected_generation == result_generation)


class DispatchLedger:
    """In-memory, boot-scoped guard only. No cross-restart once guarantee."""
    def __init__(self, run_id, boot_id):
        self.run_id, self.boot_id, self.used = run_id, boot_id, False

    def accept(self, body):
        if set(body) != {"run_id", "boot_id"}:
            return False
        if body != {"run_id": self.run_id, "boot_id": self.boot_id} or self.used:
            return False
        self.used = True
        return True
