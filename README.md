# Generic low privilege capability probe — preparation candidate

**PREPARED / NOT BUILT / NOT RUN. No deployment or publication authorization is
carried by this repository.** It contains synthetic markers only and is separate
from any product. Local test success is not Linux capability proof.

The fixed profile is Linux amd64, one service, one boot-bound explicit dispatch,
four numeric roles and standard s6 process supervision. It does not use mount,
user namespaces, bwrap, a database, a persistent disk or an external coordinator.
The Python S plan is a finite case selector, not a command/path/UID broker.

## Trust and privilege

| Role | UID/GID | Supplementary groups | Effective/permitted/inheritable/ambient |
| --- | --- | --- | --- |
| T (including H transport and C controller slots) | 10001 | 10001,10011,10012,10013 | all zero |
| P | 10011 | empty | all zero |
| V | 10012 | empty | all zero |
| R | 10013 | empty | all zero |
| S, s6 and fixed run/finish launchers | 0 | recorded | E/P=0xe0 KILL,SETGID,SETUID; I/A=0 |

NNP=1 is required for S and all children. Bounding sets are **recorded, not
claimed empty**. No CAP_SETPCAP is requested to trim them. The initial container
entry may receive the platform's ordinary root capability set: it sets NNP,
reads its own identity and immediately reduces E/P/I/A with libcap before any
role runs. Initial and reduced sets are recorded. Active/permitted SYS_ADMIN,
SYS_PTRACE, NET_ADMIN or SYS_RESOURCE cause a stop. No other initial capability
is exercised. The post-exec S profile is independently checked.

S remains a trusted UID0 upper layer for the service lifetime. It can switch to
the fixed roles and terminate its own cross-UID children. This is not a claim
that root cannot obtain T data. S has no business credentials and never parses
business input. No runtime CHOWN/DAC_OVERRIDE/FOWNER/SETPCAP is needed or used.
Build-time root sets fixed ownership and removes setuid/setgid bits from standard
executable directories. It stops on file capabilities. This changes only the
future image filesystem.

## Layout and handoff

- Code, libraries and s6 controls are trusted-owned and not writable by roles.
- `/run/probe-supervision` is root 0700; role processes inherit only stdin from
  `/dev/null` and write-only bounded stdout/stderr files opened by their fixed
  launcher. Extra FDs are closed before setpriv/exec.
- T owns the private marker directory 0700 and marker 0600. P/V/R input parent is
  T:role 02750; T-created input is T:role 0440. Readers cannot chmod that input.
- Scratch parent is T:role 02770 per role. T can revoke traversal; untrusted roles
  have no shared `/tmp` working directory. `/tmp` and `/var/tmp` become root 0755
  at image build; roles chdir to their own lane after dropping identity.
- This profile does not claim all shared kernel/filesystem objects are sandboxed.
  In particular it is not namespace/bwrap equivalence or a complete filesystem
  allowlist. Only fixed synthetic source executes in this probe.
- The cleaned child environment has exactly PATH, LC_ALL,
  PYTHONDONTWRITEBYTECODE and PROBE_SLOT. No DB socket, listener, token, supervisor
  control FD or other role FD is inherited by P/V/R.
- H is a long-lived nonroot T transport. It sets dumpable=0 after exec and keeps
  a synthetic private FD open, providing actual `/proc/T/environ` and `/proc/T/fd`
  negative targets. No platform secret-file mount is configured or proven.

## One explicit dispatch and read-only collection

Future operator-supplied runtime settings are PORT (default 10000),
PROBE_EXECUTION_APPROVED=1, PROBE_RUN_ID (fresh UUID), and PROBE_DISPATCH_TOKEN
(fresh, 32–128 ASCII characters, used only for this probe; no account credential).
S writes the token to root:T 0440 under root:T 02750 auth parent. H reads it
without inheriting a token in its environment. Token values are never returned
or logged. P/V/R cannot read it.

`GET /healthz` returns boot/run IDs and transport status. It never runs cases.
`POST /dispatch` requires X-Probe-Dispatch plus exactly a bounded JSON object
`{"run_id":"...","boot_id":"..."}`. No command, path, UID or upload fields are
accepted. Only the first correct request within that boot is accepted. The
dispatch operator must record acceptance externally and never submit another
dispatch after transport loss or restart.

`GET /result` is a synthetic-only small JSON summary plus an artifact hash
index. `GET /result?artifact=<indexed-name>&part=<integer>` returns one <=8192-byte
base64 chunk and part hash, for preserving exact raw stdout/stderr and protected
parent receipts. Names must appear in the generated index; arbitrary paths are
not accepted. Result/health are public to anyone with the service URL; dispatch
also requires the ephemeral token. There is no shell, upload or URL-fetch API.

A Free restart starts an empty slot/boot and never automatically runs work.
Local state is ephemeral. Without an external durable token this is **not an
absolute cross-restart at-most-once guarantee**. Restart/lost response means
INCONCLUSIVE for this attempt, no redispatch/redeploy/retry.

## Fixed cases and limits

See [CASE_MATRIX.md](CASE_MATRIX.md). One dispatch runs A/B/C in order and then
T cleanup. Any failure stops later cases. No real data, external connection,
fork bomb or OOM is attempted. The only process-creation negative tests are a
single safe fork/clone call after filter installation, with an immediate child
exit if the restriction unexpectedly fails.

Total body <=60s, deliberate timeout 2s after readiness, termination wait <=3s,
fixed synthetic storage <=4MiB, each raw stream <=64KiB, result JSON <=48KiB.
FSIZE is per-file, not a total quota; source fixes file count and the coordinator
accounts raw bytes/receipts plus T's no-follow work-tree count and a 64KiB control
reserve. Raw publication uses hardlinks, avoiding duplicate storage. No claim
of general adversarial disk/inode containment or enforced RLIMIT_RSS is made.

s6 tracks the actual direct child; S records s6 PID, direct-child PID, start
ticks and real identity before opening the start gate. s6 ./finish records only
after the actual direct-child wait/reap, and exits 125 to prevent replay. S
requires down+finish completion, signal evidence for deliberate interruptions,
and waits its own s6 parents. Process disappearance or a child ACK is insufficient.
No extra child process is allowed by the installed lifecycle filter; threads
die with their process. H is explicitly excluded from the job-stopped claim and
remains for read-only collection until deletion/25-minute boot lifetime.

T cleanup uses opened directory FDs and never follows symlinks. If a role-created
directory cannot be traversed/removed, T revokes the T-owned lane's traversal and
reports quarantine/CLEANUP_UNKNOWN. S never adds DAC_OVERRIDE/FOWNER or performs
root recursive deletion. A combined-size measurement error also holds cleanup.

The authorized operator must delete the single service <=30 minutes after
creation (including build time) and by the separately approved absolute deadline.
The in-container lifetime is not proof of Render service deletion or zero cost.

## Reproducibility and local checks

The Dockerfile pins an official amd64 base digest and four standard package
versions. The future image build records all installed transitive package
versions in BUILD_PACKAGE_MANIFEST.txt. Apt availability is not assumed: a pin
failure stops the build with no fallback upgrade. Actual built image digest,
runtime BPF SHA, provider deployment/service IDs and costs remain NOT_OBSERVED
until an authorized run. The canonical policy SHA is fixed by policy.py; actual
compiled BPF SHA must be observed, not guessed.

Local preparation check: `python3 -B -m unittest discover -s tests -v`.
These tests use pure data and disposable ordinary files only. They never build
an image, bind a port, load seccomp, change UID/capabilities, send signals, install
packages or contact a cloud account. All runtime code is guarded by main.

Official component and behavior references: [REFERENCES.md](REFERENCES.md).
