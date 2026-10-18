"""Approved-container-only bootstrap. Never run by local preparation tests."""
import ctypes as C
import os
import platform
import sys
import uuid
from common import CODE, SUP, atomic_json, proc_status


def main():
    if os.environ.get("PROBE_EXECUTION_APPROVED") != "1":
        raise RuntimeError("PRECONDITION_NOT_MET: explicit execution approval missing")
    uuid.UUID(os.environ["PROBE_RUN_ID"])
    token = os.environ.get("PROBE_DISPATCH_TOKEN", "")
    if not token.isascii() or not 32 <= len(token) <= 128:
        raise RuntimeError("PRECONDITION_NOT_MET: ephemeral probe-only dispatch control missing")
    if os.getuid() != 0 or platform.machine() != "x86_64":
        raise RuntimeError("PRECONDITION_NOT_MET: approved root/x86_64 missing")
    initial = proc_status()
    forbidden = (1 << 12) | (1 << 19) | (1 << 21) | (1 << 24)
    if any(int(initial[k], 16) & forbidden for k in ("CapEff", "CapPrm")):
        raise RuntimeError("PRECONDITION_NOT_MET: forbidden active/permitted initial capability")
    if initial.get("NoNewPrivs") != "1":
        raise RuntimeError("PRECONDITION_NOT_MET: entry setpriv NNP missing")
    if int(initial["CapPrm"], 16) & 0xe0 != 0xe0:
        raise RuntimeError("PRECONDITION_NOT_MET: existing SETUID/SETGID/KILL missing")
    lib = C.CDLL("libcap.so.2", use_errno=True)
    lib.cap_from_text.argtypes = [C.c_char_p]
    lib.cap_from_text.restype = C.c_void_p
    lib.cap_set_proc.argtypes = [C.c_void_p]
    lib.cap_free.argtypes = [C.c_void_p]
    caps = lib.cap_from_text(b"cap_kill,cap_setgid,cap_setuid=ep")
    if not caps:
        raise RuntimeError("cap_from_text failed")
    try:
        if lib.cap_set_proc(caps) != 0:
            raise OSError(C.get_errno(), "cap_set_proc")
    finally:
        lib.cap_free(caps)
    reduced = proc_status()
    if not (all(int(reduced[k], 16) == 0xe0 for k in ("CapEff", "CapPrm"))
            and all(int(reduced[k], 16) == 0 for k in ("CapInh", "CapAmb"))):
        raise RuntimeError("PRECONDITION_NOT_MET: exact S capability reduction failed")
    atomic_json(SUP / "bootstrap-identity.json", {"initial": initial, "reduced": reduced,
                "other_initial_capabilities_exercised": False}, 0o600)
    # NNP prevents exec from regaining capabilities removed from the permitted set.
    os.execv(sys.executable, [sys.executable, "-B", str(CODE / "supervisor.py")])


if __name__ == "__main__":
    main()
