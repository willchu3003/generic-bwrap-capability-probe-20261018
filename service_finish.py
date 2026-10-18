"""Executed by s6 only after its direct child was waited/reaped."""
import sys
from common import PUB, SUP, SLOTS, atomic_json, proc_status, read_json, supervisor_identity_ok


def main():
    slot, exitcode, signum = sys.argv[1:4]
    if slot not in SLOTS:
        raise ValueError("unknown fixed slot")
    cfg = read_json(PUB / ("slot-" + slot + ".json"))
    identity = proc_status()
    if not supervisor_identity_ok(identity):
        raise RuntimeError("finish supervisor privilege precondition changed")
    atomic_json(SUP / "receipts" / f"{slot}-{cfg['seq']}.json",
                {"slot": slot, "seq": cfg["seq"], "exitcode": int(exitcode),
                 "signal": int(signum), "s6_direct_child_wait_completed": True,
                 "finish_identity": identity}, 0o600)
    return 125  # documented s6 permanent down; no restart/replay


if __name__ == "__main__":
    sys.exit(main())
