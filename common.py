import hashlib
import json
import os
import stat
from pathlib import Path

CODE = Path("/opt/probe")
SUP = Path("/run/probe-supervision")
PUB = Path("/run/probe-public")
DISPATCH = Path("/run/probe-dispatch")
AUTH = Path("/run/probe-auth")
WORK = Path("/tmp/lowpriv-probe")
ROLES = {"T": 10001, "P": 10011, "V": 10012, "R": 10013}
SLOTS = frozenset({"H", "T", "P", "V", "R", "C"})


def read_json(path):
    return json.loads(Path(path).read_text())


def atomic_json(path, value, mode=0o644):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > 49152:
        raise ValueError("bounded JSON exceeded")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def proc_status(pid="self"):
    result = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapInh", "CapAmb",
                   "CapBnd", "NoNewPrivs", "Seccomp", "Seccomp_filters", "PPid"}:
            result[key] = value.strip()
    return result


def identity_ok(data, uid, allowed_groups=()):
    return (data.get("Uid", "").split() == [str(uid)] * 4
        and data.get("Gid", "").split() == [str(uid)] * 4
        and set(map(int, data.get("Groups", "").split())) <= set(allowed_groups)
        and all(int(data.get(k, "-1"), 16) == 0
                for k in ("CapEff", "CapPrm", "CapInh", "CapAmb"))
        and data.get("NoNewPrivs") == "1")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def supervisor_identity_ok(data):
    return (data.get("Uid", "").split() == ["0"] * 4
        and data.get("Gid", "").split() == ["0"] * 4
        and data.get("NoNewPrivs") == "1"
        and all(int(data.get(k, "-1"), 16) == 0xe0 for k in ("CapEff", "CapPrm"))
        and all(int(data.get(k, "-1"), 16) == 0 for k in ("CapInh", "CapAmb")))


def remove_contents_fd(fd):
    """Only caller-opened probe directory; never follows symlinks."""
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                remove_contents_fd(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)


def usage_fd(fd):
    size, count = 0, 0
    for name in os.listdir(fd):
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                subtotal, files = usage_fd(child)
            finally:
                os.close(child)
            size, count = size + subtotal, count + files
        else:
            size, count = size + info.st_size, count + 1
    return size, count
