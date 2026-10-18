"""Fixed synthetic plan; s6 owns and waits each role process.

S remains UID0 with only existing KILL/SETUID/SETGID. This is not a general
command broker, a product worker, or a claim of a complete Linux sandbox.
"""
import hashlib
import json
import math
import os
import signal
import subprocess
import sys
import time
import uuid
from common import AUTH, CODE, DISPATCH, PUB, SUP, atomic_json, proc_status, read_json, supervisor_identity_ok
from policy import POLICY_SHA256

CHILDREN, ACTIVE, CASES, RAW = {}, {}, [], {}
SEQUENCE = 0
REPORT = {"profile_id": "generic-lowpriv-one-probe-01", "status": "WAITING_NO_AUTO_DISPATCH",
          "policy_sha256": POLICY_SHA256, "platform_secret_file": "NOT_CONFIGURED_NOT_TESTED",
          "cross_restart_at_most_once": "NOT_CLAIMED; external operator must not redispatch"}
BODY_DEADLINE = None


class ProbeStop(Exception):
    def __init__(self, status, reason):
        self.status, self.reason = status, reason
        super().__init__(reason)


def command(*args, timeout=2):
    return subprocess.run(args, check=True, capture_output=True, timeout=timeout,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}, close_fds=True)


def assert_s_identity():
    st = proc_status()
    if not supervisor_identity_ok(st):
        raise ProbeStop("PRECONDITION_NOT_MET", "S exact privilege profile unavailable")
    REPORT["supervisor_identity"] = st  # CapBnd retained and reported honestly


def start_supervisor(slot):
    if slot not in CHILDREN:
        child = subprocess.Popen(["s6-supervise", str(SUP / slot)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}, close_fds=True)
        CHILDREN[slot] = child
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                command("s6-svstat", "-o", "up", str(SUP / slot), timeout=0.5)
                return
            except subprocess.CalledProcessError:
                if child.poll() is not None:
                    break
                time.sleep(0.02)
        raise ProbeStop("INCONCLUSIVE", "s6-supervise startup unavailable for " + slot)


def status(slot):
    out = command("s6-svstat", "-o", "up,ready,pid", str(SUP / slot)).stdout.decode().split()
    return out[0] == "true", out[1] == "true", int(out[2])


def start(slot, case, generation=0, **extra):
    global SEQUENCE
    if slot in ACTIVE:
        raise RuntimeError("active fixed slot cannot be overwritten")
    if BODY_DEADLINE and time.monotonic() > BODY_DEADLINE - 12 and case != "cleanup":
        raise ProbeStop("INCONCLUSIVE", "reserved stop/cleanup budget reached")
    allowed = {"H": {"transport"}, "T": {"setup", "cleanup"},
               "C": {"controller_old", "controller_rebuild", "verify_generation"},
               "P": {"A", "B", "timeout", "old_job", "new_job"},
               "V": {"A", "B"}, "R": {"A", "B"}}
    if case not in allowed.get(slot, set()):
        raise ValueError("case not in fixed slot allowlist")
    SEQUENCE += 1
    cfg = {"slot": slot, "case": case, "seq": SEQUENCE, "generation": generation, **extra}
    atomic_json(PUB / ("slot-" + slot + ".json"), cfg)
    start_supervisor(slot)
    command("s6-svc", "-o", str(SUP / slot))
    deadline = time.monotonic() + 3
    expected_uid = 10001 if slot in ("H", "T", "C") else {"P": 10011, "V": 10012, "R": 10013}[slot]
    while time.monotonic() < deadline:
        up, _, pid = status(slot)
        if up:
            try:
                child_status = proc_status(pid)
                if (child_status["Uid"].split() == [str(expected_uid)] * 4
                        and child_status["PPid"] == str(CHILDREN[slot].pid)
                        and child_status["NoNewPrivs"] == "1"
                        and all(int(child_status[k], 16) == 0 for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))):
                    # Source is s6's actual direct-child status, not a role-reported PID.
                    start_ticks = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19]
                    cfg.update(pid=pid, s6_parent_pid=CHILDREN[slot].pid,
                               start_ticks=start_ticks, actual_start_identity=child_status)
                    ACTIVE[slot] = cfg
                    atomic_json(PUB / f"gate-{slot}-{cfg['seq']}", {"go": True})
                    return cfg
            except FileNotFoundError:
                pass
        time.sleep(0.02)
    # No PID identity was proven: do not claim a running role or successful stop.
    command("s6-svc", "-d", str(SUP / slot))
    command("s6-svc", "-k", str(SUP / slot))
    try:
        command("s6-svwait", "-D", "-t", "2000", str(SUP / slot), timeout=2.2)
    except Exception:
        raise ProbeStop("CLEANUP_UNKNOWN", "unidentified fixed slot failed to reach down")
    raise ProbeStop("PRECONDITION_NOT_MET", "role UID/caps/start identity not established: " + slot)


def wait_case(slot, seconds=3, killed=False):
    cfg = ACTIVE[slot]
    try:
        command("s6-svwait", "-D", "-t", str(max(1, int(seconds * 1000))),
                str(SUP / slot), timeout=seconds + 0.15)
    except (subprocess.SubprocessError, OSError):
        raise ProbeStop("CLEANUP_UNKNOWN", "no complete s6 wait/finish proof for " + slot)
    receipt_path = SUP / "receipts" / f"{slot}-{cfg['seq']}.json"
    if not receipt_path.exists():
        raise ProbeStop("CLEANUP_UNKNOWN", "missing protected finish receipt")
    receipt = read_json(receipt_path)
    up, ready, _ = status(slot)
    if up or not ready or not receipt["s6_direct_child_wait_completed"]:
        raise ProbeStop("CLEANUP_UNKNOWN", "s6 down/finish mismatch")
    record = {"start": cfg, "finish": receipt, "parent_verified_down_and_finish": True}
    for suffix in ("stdout", "stderr"):
        name = f"{slot}-{cfg['seq']}.{suffix}"
        data = (SUP / "logs" / name).read_bytes()
        if len(data) > 65536:
            raise ProbeStop("INCONCLUSIVE", "raw stream limit violated")
        RAW[name] = data
    data = RAW[f"{slot}-{cfg['seq']}.stdout"]
    if not killed:
        try:
            record["child_result"] = json.loads(data.splitlines()[-1])
        except (ValueError, IndexError):
            record["child_result"] = None
    else:
        record["deliberately_interrupted"] = True
    err = RAW[f"{slot}-{cfg['seq']}.stderr"]
    if err:
        try:
            record["child_error"] = json.loads(err.splitlines()[-1])
        except (ValueError, IndexError):
            record["child_error"] = {"parseable": False}
    CASES.append(record)
    del ACTIVE[slot]
    if not killed and (receipt["exitcode"] != 0 or not record["child_result"] or not record["child_result"].get("pass")):
        result = record.get("child_result") or {}
        failure = "ISOLATION_CHECK_FAILED" if cfg["case"] == "A" else "INCONCLUSIVE"
        if cfg["case"] == "setup":
            failure = "PRECONDITION_NOT_MET"
        if cfg["case"] == "cleanup":
            failure = "CLEANUP_UNKNOWN"
        if cfg["case"] == "B" and any(x["name"].startswith("deny_") and not x["pass"] for x in result.get("checks", [])):
            failure = "ISOLATION_CHECK_FAILED"
        if cfg["case"] == "B" and record.get("child_error", {}).get("errno") in (1, 13, 38):
            failure = "CAPABILITY_DENIED_FOR_THIS_PROFILE"
        raise ProbeStop(failure, "fixed case failed: " + slot + "/" + cfg["case"])
    return record


def stop(slot, reason, require_signal=False):
    if slot not in ACTIVE:
        return
    start_time = time.monotonic()
    command("s6-svc", "-d", str(SUP / slot))  # standard supervisor sends TERM
    deadline = start_time + 0.7
    while time.monotonic() < deadline:
        if not status(slot)[0]:
            break
        time.sleep(0.02)
    if status(slot)[0]:
        command("s6-svc", "-k", str(SUP / slot))
    record = wait_case(slot, max(0.1, 3 - (time.monotonic() - start_time)), killed=True)
    elapsed = time.monotonic() - start_time
    record["stop"] = {"reason": reason, "actual_seconds": elapsed,
                      "signals_via_own_standard_supervisor": True,
                      "stopped_proven": elapsed <= 3}
    if elapsed > 3:
        raise ProbeStop("CLEANUP_UNKNOWN", "termination exceeded three seconds")
    if require_signal and not (record["finish"]["exitcode"] == 256
                               and record["finish"]["signal"] in (signal.SIGTERM, signal.SIGKILL)):
        raise ProbeStop("INCONCLUSIVE", "deliberate lifecycle child exited before signal case")


def wait_started(cfg):
    path = SUP / "logs" / f"{cfg['slot']}-{cfg['seq']}.stdout"
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.stat().st_size:
            try:
                data = json.loads(path.read_bytes().splitlines()[0])
                ready = data["readiness"]
                if data["started"] is True and ready.get("filter") and all(
                        x["pass"] for x in ready["checks"]):
                    return
                raise ProbeStop("INCONCLUSIVE", "lifecycle readiness contract failed")
            except (ValueError, IndexError):
                pass
        time.sleep(0.02)
    raise ProbeStop("INCONCLUSIVE", "lifecycle filter/identity readiness missing")


def one(slot, case, generation=0, **extra):
    start(slot, case, generation, **extra)
    return wait_case(slot)


def plan():
    one("T", "setup")
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        path = DISPATCH / "http-identity.json"
        if path.exists():
            identity = read_json(path)
            if isinstance(identity.get("secret_fd"), int):
                atomic_json(PUB / "http-identity.json", identity)
                break
        time.sleep(0.03)
    else:
        raise ProbeStop("INCONCLUSIVE", "T transport proc-negative target not ready")
    for role in "PVR":
        one(role, "A")
    for role in "PVR":
        one(role, "B")
    timeout_child = start("P", "timeout")
    wait_started(timeout_child)
    time.sleep(2)
    stop("P", "deliberate two-second timeout", require_signal=True)
    old = start("P", "old_job", 0)
    wait_started(old)
    controller = start("C", "controller_old", 0, target_pid=old["pid"])
    deadline = time.monotonic() + 2
    raw_path = SUP / "logs" / f"C-{controller['seq']}.stdout"
    while time.monotonic() < deadline and not raw_path.stat().st_size:
        time.sleep(0.02)
    if not raw_path.stat().st_size or not json.loads(raw_path.read_bytes().splitlines()[0])["checks"][-1]["pass"]:
        raise ProbeStop("ISOLATION_CHECK_FAILED", "T unexpectedly authorized to signal P or evidence missing")
    stop("C", "single deliberate internal role-controller interruption", require_signal=True)
    stop("P", "old generation becomes UNKNOWN; never replay", require_signal=True)
    REPORT["interrupted_job"] = {"generation": 0, "status": "UNKNOWN", "replayed": False}
    one("C", "controller_rebuild", 1)
    one("P", "new_job", 1)
    one("C", "verify_generation", 1)


def publish():
    artifacts = {}
    for index, record in enumerate(CASES):
        RAW[f"receipt-{index:02d}.json"] = json.dumps(record, sort_keys=True).encode()
    for name, data in RAW.items():
        if len(data) > 65536:
            raise ProbeStop("INCONCLUSIVE", "artifact bound violated")
        path = PUB / "artifacts" / name
        path.unlink(missing_ok=True)
        original = SUP / "logs" / name
        if original.is_file():
            os.link(original, path)  # bounded raw files have one inode, no duplicate scratch
        else:
            path.write_bytes(data)
        path.chmod(0o644)
        artifacts[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                           "parts": max(1, math.ceil(len(data) / 8192))}
    REPORT["completed_case_count"] = len(CASES)
    REPORT["case_index"] = [{"slot": r["start"]["slot"], "case": r["start"]["case"],
                              "seq": r["start"]["seq"]} for r in CASES]
    atomic_json(PUB / "artifacts.json", artifacts)
    atomic_json(PUB / "result.json", REPORT)


def shutdown_slots(exclude_http=True):
    waits = []
    for slot in list(ACTIVE):
        if exclude_http and slot == "H":
            continue
        stop(slot, "fixed cleanup after probe")
    for slot, parent in list(CHILDREN.items()):
        if exclude_http and slot == "H":
            continue
        command("s6-svc", "-x", str(SUP / slot))
        try:
            code = parent.wait(timeout=2)
        except subprocess.TimeoutExpired:
            raise ProbeStop("CLEANUP_UNKNOWN", "s6 parent not reaped: " + slot)
        waits.append({"slot": slot, "pid": parent.pid, "parent_wait_returncode": code})
        del CHILDREN[slot]
    REPORT.setdefault("supervisor_parent_waits", []).extend(waits)


def main():
    global BODY_DEADLINE
    assert_s_identity()
    REPORT["bootstrap_identity"] = read_json(SUP / "bootstrap-identity.json")
    auth_fd = os.open(AUTH / "token", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
    try:
        os.write(auth_fd, os.environ["PROBE_DISPATCH_TOKEN"].encode())
    finally:
        os.close(auth_fd)
    # AUTH is root:T setgid at build. S owns this file, no runtime chown.
    profile = read_json(CODE / "profile.json")
    versions = {}
    for name, expected in profile["packages"].items():
        actual = command("dpkg-query", "-W", "-f=${Version}", name).stdout.decode()
        versions[name] = actual
        if actual != expected:
            raise ProbeStop("PRECONDITION_NOT_MET", "pinned package mismatch: " + name)
    REPORT["packages"] = versions
    RAW["BUILD_PACKAGE_MANIFEST.txt"] = (CODE / "BUILD_PACKAGE_MANIFEST.txt").read_bytes()
    REPORT["python"] = sys.version
    REPORT["base_image"] = profile["base_image"]
    boot = {"run_id": os.environ["PROBE_RUN_ID"], "boot_id": str(uuid.uuid4()),
            "port": int(os.environ.get("PORT", "10000"))}
    atomic_json(PUB / "boot.json", boot)
    start("H", "transport")
    retained_until = time.monotonic() + 25 * 60
    while not (DISPATCH / "once.json").exists():
        if time.monotonic() >= retained_until or CHILDREN["H"].poll() is not None:
            raise ProbeStop("INCONCLUSIVE", "no dispatch before transport lifetime/exit")
        time.sleep(0.1)
    dispatch = read_json(DISPATCH / "once.json")
    if dispatch != {k: boot[k] for k in ("run_id", "boot_id")}:
        raise ProbeStop("INCONCLUSIVE", "dispatch identity mismatch")
    REPORT.update(run_id=boot["run_id"], boot_id=boot["boot_id"], status="RUNNING")
    start_time = time.monotonic()
    BODY_DEADLINE = start_time + 60
    primary = None
    try:
        plan()
        REPORT["status"] = "ALL_REQUIRED_CAPABILITIES_OBSERVED"
    except ProbeStop as exc:
        primary = exc.status
        REPORT.update(status=exc.status, reason=exc.reason)
    except Exception as exc:
        primary = "INCONCLUSIVE"
        REPORT.update(status=primary, reason=type(exc).__name__ + ": " + str(exc)[:300])
    finally:
        try:
            for slot in list(ACTIVE):
                if slot != "H":
                    stop(slot, "final job stop before cleanup")
            # Cleanup is T's own fixed tree operation. S never chowns or bypasses DAC.
            cleanup = one("T", "cleanup")
            work_bytes = cleanup["child_result"]["work_bytes_before_cleanup"]
            # Fixed slots bound each stream, source bounds file count; include raw
            # streams plus serialized receipts and work, not RLIMIT_FSIZE-as-total.
            bounded_bytes = 65536 + work_bytes + sum(len(x) for x in RAW.values()) + sum(
                len(json.dumps(x).encode()) * 2 for x in CASES)
            REPORT["bounded_synthetic_bytes"] = bounded_bytes
            if bounded_bytes > 4194304:
                raise ProbeStop("INCONCLUSIVE", "combined synthetic byte bound exceeded")
            shutdown_slots()
            if REPORT["status"] == "ALL_REQUIRED_CAPABILITIES_OBSERVED" and (
                    len(CASES) != 14 or len(REPORT.get("supervisor_parent_waits", [])) != 5):
                raise ProbeStop("INCONCLUSIVE", "incomplete required case/parent-wait matrix")
            REPORT["job_cleanup"] = "STOPPED_PROVEN_FIXED_SYNTHETIC_CHILDREN_ONLY"
        except Exception as exc:
            REPORT.update(primary_status=primary or REPORT["status"], status="CLEANUP_UNKNOWN",
                          cleanup_error=type(exc).__name__ + ": " + str(exc)[:300])
        REPORT["body_seconds"] = time.monotonic() - start_time
        if REPORT["body_seconds"] > 60:
            REPORT.update(primary_status=REPORT["status"], status="INCONCLUSIVE", reason="60-second body bound exceeded")
        publish()
    # Transport and its S manager remain only for bounded read-only collection.
    # Externally authorized operator still must delete the service by its deadline.
    while time.monotonic() < retained_until:
        time.sleep(0.2)
    shutdown_slots(exclude_http=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        REPORT.update(status=getattr(exc, "status", "INCONCLUSIVE"), reason=str(exc)[:500])
        try:
            shutdown_slots(exclude_http=False)
        except Exception as cleanup:
            REPORT.update(primary_status=REPORT["status"], status="CLEANUP_UNKNOWN", cleanup_error=str(cleanup)[:300])
        publish()
        print(json.dumps(REPORT, sort_keys=True), flush=True)
        sys.exit(1)
