"""Small, independently implemented Linux amd64 seccomp capability contract.

Linux syscall numbers and classic BPF operations are public interfaces. This
module contains no application imports, business rules, files, or credentials.
"""
import errno
import struct

ARCH = 0xC000003E
ALLOW = 0x7FFF0000
KILL = 0x80000000
ERROR = 0x00050000
CLONE_THREAD = 0x10000
DENIED = (41, 57, 58, 101, 109, 112, 272, 308, 310, 311)
NAMESPACES = ('user', 'pid', 'net', 'ipc', 'uts', 'mnt')


def program():
    instructions = []

    def load(offset): instructions.append((0x20, 0, 0, offset))
    def ret(action): instructions.append((0x06, 0, 0, action))
    def reject_if(operation, constant, action):
        instructions.append((operation, 0, 1, constant))
        ret(action)

    load(4)  # seccomp_data.arch
    instructions.append((0x15, 1, 0, ARCH))
    ret(KILL)
    load(0)  # seccomp_data.nr
    reject_if(0x35, 0x40000000, KILL)  # No x32/invalid high-bit ABI.
    for number in DENIED:
        reject_if(0x15, number, ERROR | errno.EPERM)
    reject_if(0x15, 435, ERROR | errno.ENOSYS)  # clone3 -> pthread clone fallback
    instructions.append((0x15, 0, 3, 56))  # clone
    load(16)  # low word of args[0] (amd64 little-endian)
    instructions.append((0x45, 1, 0, CLONE_THREAD))
    ret(ERROR | errno.EPERM)
    ret(ALLOW)
    return b''.join(struct.pack('<HBBI', *row) for row in instructions)


def evaluate(blob, number, *, arch=ARCH, flags=0):
    """Pure interpreter used to check policy branches without Linux execution."""
    rows = list(struct.iter_unpack('<HBBI', blob))
    values = {0: number & 0xFFFFFFFF, 4: arch, 16: flags & 0xFFFFFFFF}
    pc = 0; accumulator = 0
    for _ in range(256):
        code, yes, no, value = rows[pc]
        if code == 0x20: accumulator = values[value]
        elif code == 0x06: return value
        elif code in (0x15, 0x35, 0x45):
            condition = {0x15: accumulator == value, 0x35: accumulator >= value,
                         0x45: bool(accumulator & value)}[code]
            pc += yes if condition else no
        else: raise ValueError('UNSUPPORTED_POLICY_INSTRUCTION')
        pc += 1
    raise ValueError('POLICY_DID_NOT_TERMINATE')
