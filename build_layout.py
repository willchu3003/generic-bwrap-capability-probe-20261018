"""Image-build-only ownership. Never invoked during local preparation."""
import json
import os
import stat
import subprocess
from pathlib import Path


def directory(path, uid=0, gid=0, mode=0o755):
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    os.chown(target, uid, gid)
    target.chmod(mode)


def main():
    if os.geteuid() != 0 or not Path("/opt/probe/Dockerfile").is_file():
        raise RuntimeError("image-build-only; do not run on a host")
    roles = {"T": 10001, "P": 10011, "V": 10012, "R": 10013}
    for target in ("/etc/passwd", "/etc/group"):
        for line in Path(target).read_text().splitlines():
            fields = line.split(":")
            if len(fields) > 2 and (fields[0] in {"probe" + r.lower() for r in roles}
                                    or fields[2] in {str(uid) for uid in roles.values()}):
                raise RuntimeError("fixed role identity collision in image")
    # Numeric identities suffice; fixed passwd/group entries aid diagnostics.
    for target, text in (("/etc/passwd", "".join(f"probe{r.lower()}:x:{u}:{u}:synthetic probe:/nonexistent:/usr/sbin/nologin\n" for r, u in roles.items())),
                         ("/etc/group", "".join(f"probe{r.lower()}:x:{u}:\n" for r, u in roles.items()))):
        with open(target, "a") as stream:
            stream.write(text)
    directory("/run/probe-supervision", mode=0o700)
    for child in ("logs", "receipts"):
        directory("/run/probe-supervision/" + child, mode=0o700)
    directory("/run/probe-public")
    directory("/run/probe-public/artifacts")
    directory("/run/probe-auth", 0, 10001, 0o2750)
    directory("/run/probe-dispatch", 10001, 10001, 0o755)
    directory("/tmp", mode=0o755)
    directory("/var/tmp", mode=0o755)
    directory("/tmp/lowpriv-probe")
    directory("/tmp/lowpriv-probe/trusted", 10001, 10001, 0o700)
    for lane in ("inputs", "scratch"):
        directory("/tmp/lowpriv-probe/" + lane)
        for role in "PVR":
            directory(f"/tmp/lowpriv-probe/{lane}/{role}", 10001, roles[role],
                      0o2750 if lane == "inputs" else 0o2770)
    for slot in "HTPVRC":
        servicedir = Path("/run/probe-supervision") / slot
        directory(servicedir, mode=0o700)
        (servicedir / "down").touch(mode=0o600)
        (servicedir / "run").write_text("#!/bin/sh\nexec /usr/local/bin/python -B /opt/probe/service_run.py " + slot + "\n")
        (servicedir / "finish").write_text("#!/bin/sh\nexec /usr/local/bin/python -B /opt/probe/service_finish.py " + slot + " \"$1\" \"$2\"\n")
        for name in ("run", "finish"):
            (servicedir / name).chmod(0o500)
        (servicedir / "timeout-finish").write_text("1000\n")
    # No newly installed setuid/filecap escalation entry is retained in the image.
    # This touches only the future build filesystem, never a host or other service.
    for root in ("/usr/bin", "/usr/sbin", "/usr/local/bin"):
        for path in Path(root).iterdir():
            if path.is_file() and not path.is_symlink():
                mode = path.stat().st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID):
                    path.chmod(stat.S_IMODE(mode) & ~0o6000)
                try:
                    if os.getxattr(path, "security.capability"):
                        raise RuntimeError("filecap precondition failed: " + str(path))
                except OSError as exc:
                    if exc.errno not in (61, 95):  # ENODATA, ENOTSUP on Linux
                        raise
    manifest = subprocess.run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                              check=True, capture_output=True).stdout
    Path("/opt/probe/BUILD_PACKAGE_MANIFEST.txt").write_bytes(manifest)
    for path in Path("/opt/probe").rglob("*"):
        if path.is_dir():
            path.chmod(0o555)
        elif not path.is_symlink():
            path.chmod(0o444)
    Path("/opt/probe").chmod(0o555)


if __name__ == "__main__":
    main()
