"""Own-process snapshots plus explicit one-way NNP restriction and ordinary exec.

This is a DIFFERENT control chain. It never executes setpriv and cannot replay
or attribute an earlier setpriv failure. There are no business inputs or tokens.
"""
import ctypes
import json
import os
import platform
import stat
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

FIELDS = ("Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs")
REQUIRED = {"CAP_KILL": 5, "CAP_SETGID": 6, "CAP_SETUID": 7}
STATE = Path("/tmp/generic-cap-observer-once.json")
MAX_JSON = 16384
PR_GET_SECUREBITS = 27
PR_SET_NO_NEW_PRIVS = 38
PR_GET_NO_NEW_PRIVS = 39


def parse_status(text):
    result = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in FIELDS:
            result[key] = value.strip()
    return result


def required_bits(hex_value):
    value = int(hex_value, 16)
    return {name: bool(value & (1 << bit)) for name, bit in REQUIRED.items()}


def prctl(option, value=0):
    lib = ctypes.CDLL(None, use_errno=True)
    lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    lib.prctl.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = lib.prctl(option, value, 0, 0, 0)
    return {"value": result, "errno": ctypes.get_errno() if result == -1 else 0}


def snapshot(stage):
    status = parse_status(Path("/proc/self/status").read_text())
    return {"stage": stage, "pid": os.getpid(), "ppid": os.getppid(),
            "status": status, "required_permitted_bits": required_bits(status["CapPrm"]),
            "pr_get_no_new_privs": prctl(PR_GET_NO_NEW_PRIVS),
            "pr_get_securebits": prctl(PR_GET_SECUREBITS)}


def restrict_nnp(initial_value, call):
    if initial_value == "1":
        return {"operation": "already_1_no_setter_called", "state_change_requested": False}
    if initial_value != "0":
        return {"operation": "not_attempted_unknown_initial_value", "state_change_requested": False}
    result = call(PR_SET_NO_NEW_PRIVS, 1)
    return {"operation": "PR_SET_NO_NEW_PRIVS_1", "state_change_requested": True, **result}


def encode(value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_JSON:
        raise ValueError("fixed result size exceeded")
    return data


def write_state(value, first=False):
    flags = os.O_WRONLY | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if first else 0)
    fd = os.open(STATE, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unexpected owned marker")
        data = encode(value)
        os.ftruncate(fd, 0)
        while data:
            count = os.write(fd, data)
            if count <= 0:
                raise OSError("short marker write")
            data = data[count:]
        os.fsync(fd)
    finally:
        os.close(fd)


def load_state():
    fd = os.open(STATE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("unexpected owned marker")
        data = os.read(fd, MAX_JSON + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_JSON:
        raise ValueError("marker bound exceeded")
    return json.loads(data)


def derive(phases):
    if len(phases) != 3 or [x["stage"] for x in phases] != ["docker_entry_observer", "after_nnp_before_exec", "after_ordinary_exec"]:
        return "INCONCLUSIVE_MISSING_PHASE"
    if len({x["pid"] for x in phases}) != 1:
        return "INCONCLUSIVE_PID_CHANGED"
    present = [all(x["required_permitted_bits"].values()) for x in phases]
    if not present[0]:
        return "REQUIRED_P_BITS_MISSING_AT_FIRST_OBSERVER_ENTRY"
    if not present[1]:
        return "REQUIRED_P_BITS_MISSING_AT_SECOND_SNAPSHOT"
    if not present[2]:
        return "REQUIRED_P_BITS_MISSING_AFTER_ORDINARY_EXEC"
    return "REQUIRED_P_BITS_PRESENT_AT_ALL_THREE_SNAPSHOTS"


def transition(before, after):
    result = {"cap_deltas": {}}
    for name in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"):
        old, new = int(before["status"][name], 16), int(after["status"][name], 16)
        result["cap_deltas"][name] = {"lost_hex": hex(old & ~new), "gained_hex": hex(new & ~old)}
    result["uid_gid_changed"] = any(before["status"].get(k) != after["status"].get(k) for k in ("Uid", "Gid", "Groups"))
    a, b = before["pr_get_securebits"], after["pr_get_securebits"]
    result["securebits_changed_if_readable"] = a["value"] != b["value"] if a["errno"] == b["errno"] == 0 else None
    return result


def finish(value):
    value["status"] = "OBSERVATIONS_COMPLETE" if len(value["phases"]) == 3 else "INCOMPLETE_OBSERVATIONS"
    value["observation"] = derive(value["phases"])
    value["observation_seconds"] = time.monotonic() - value["start_monotonic"]
    if value["observation_seconds"] > 10:
        value["status"] = "INCONCLUSIVE_OBSERVATION_BUDGET_EXCEEDED"
    if len(value["phases"]) == 3:
        first, before, after = value["phases"]
        value["transitions"] = {"nnp_interval": transition(first, before), "ordinary_exec": transition(before, after)}
        value["nnp_remained_1_after_exec"] = before["status"].get("NoNewPrivs") == after["status"].get("NoNewPrivs") == "1"
        if not value["nnp_remained_1_after_exec"]:
            value["status"] = "INCONCLUSIVE_NNP_MISMATCH"
    write_state(value)
    return value


def observe():
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("fixed Linux amd64 observation only")
    if sys.argv[1:] == ["--after-exec"]:
        value = load_state()
        if value.get("pid") != os.getpid() or value.get("phase") != "exec_pending":
            raise RuntimeError("not the same fixed self-exec handoff")
        value["phases"].append(snapshot("after_ordinary_exec"))
        value["phase"] = "done"
        return finish(value)
    if sys.argv[1:]:
        raise RuntimeError("no external command/path/UID options")
    value = {"profile": "generic-own-cap-observer-01", "boot_id": str(uuid.uuid4()),
             "pid": os.getpid(), "start_monotonic": time.monotonic(), "phase": "reserved", "phases": [],
             "chain": "direct_python_then_one_way_nnp_then_ordinary_python_exec",
             "setpriv_executed": False, "original_setpriv_chain_reproduced": False,
             "claim": "own-process observations only; no A/B/C or product PASS; not a platform-wide verdict",
             "python": sys.version.split()[0], "arch": platform.machine()}
    try:
        write_state(value, first=True)
    except FileExistsError:
        return {"status": "EXISTING_MARKER_NO_REPLAY", "setpriv_executed": False,
                "claim": "existing ephemeral marker; no snapshots repeated; no cross-restart once guarantee"}
    value["phases"].append(snapshot("docker_entry_observer"))
    value["nnp_operation"] = restrict_nnp(value["phases"][0]["status"].get("NoNewPrivs"), prctl)
    value["phases"].append(snapshot("after_nnp_before_exec"))
    if value["phases"][1]["status"].get("NoNewPrivs") != "1":
        value["phase"] = "stopped_before_exec"
        return finish(value)
    value["phase"] = "exec_pending"
    write_state(value)
    os.execv(sys.executable, [sys.executable, "-B", str(Path(__file__).resolve()), "--after-exec"])
    raise RuntimeError("unreachable")


def serve(value):
    data = encode(value)
    print(data.decode(), flush=True)  # one fixed result, no env/token/account data
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.connection.settimeout(2)
            allowed = self.path in ("/healthz", "/result")
            body = data if allowed else b'{"error":"fixed read-only routes only"}'
            self.send_response(200 if allowed else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_POST(self):
            self.send_error(405, "read-only result; no dispatch")
            self.close_connection = True

    port = int(os.environ.get("PORT", "10000"))
    if not 1024 <= port <= 65535:
        raise ValueError("unprivileged platform port required")
    server = HTTPServer(("0.0.0.0", port), Handler)
    server.timeout = 0.2
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        server.handle_request()
    server.server_close()


if __name__ == "__main__":
    try:
        serve(observe())
    except Exception as exc:
        # Fixed bounded error only: no inherited env, arbitrary file or credentials.
        print(json.dumps({"status": "INCONCLUSIVE", "error_type": type(exc).__name__,
                          "errno": getattr(exc, "errno", None)}), flush=True)
        sys.exit(1)
