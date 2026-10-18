"""Root-owned s6 ./run target: fixed slot only, no command/path broker."""
import os
import resource
import sys
from common import CODE, PUB, SUP, SLOTS, proc_status, read_json, supervisor_identity_ok


def main():
    slot = sys.argv[1]
    if slot not in SLOTS:
        raise ValueError("unknown fixed slot")
    st = proc_status()
    if not supervisor_identity_ok(st):
        raise RuntimeError("supervisor privilege precondition changed")
    cfg = read_json(PUB / ("slot-" + slot + ".json"))
    if cfg["slot"] != slot or type(cfg["seq"]) is not int:
        raise ValueError("invalid fixed config")
    for fd, suffix in ((1, "stdout"), (2, "stderr")):
        opened = os.open(SUP / "logs" / f"{slot}-{cfg['seq']}.{suffix}",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.dup2(opened, fd)
        os.close(opened)
    null = os.open("/dev/null", os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    os.closerange(3, 1048576)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    uid = 10001 if slot in ("H", "T", "C") else {"P": 10011, "V": 10012, "R": 10013}[slot]
    groups = ["--groups", "10001,10011,10012,10013"] if uid == 10001 else ["--clear-groups"]
    program = "http_transport.py" if slot == "H" else "role.py"
    args = ["/usr/bin/setpriv", "--no-new-privs", "--reuid", str(uid), "--regid", str(uid),
            *groups, "--inh-caps=-all", "--ambient-caps=-all", "/usr/bin/env", "-i",
            "PATH=/usr/local/bin:/usr/bin:/bin", "LC_ALL=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1",
            "PROBE_SLOT=" + slot, sys.executable, "-B", str(CODE / program)]
    os.execv(args[0], args)


if __name__ == "__main__":
    main()
