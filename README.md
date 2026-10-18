# Generic bubblewrap capability probe

A temporary, synthetic Linux amd64 compatibility experiment. It contains no
application code, business rules, customer data, fixtures, credentials, or API
clients. No database or persistent disk is needed. It is not an application
security review or evidence of production readiness.

## What runs

At startup, the non-root process runs at most two small local stages:

1. Required user/PID/network/IPC/UTS namespaces and the new mount namespace,
   with read-only synthetic input, one writable directory, an unmounted
   synthetic file, `/proc`, `/dev`, and a temporary `/tmp`. Capabilities are
   dropped; a normal Python thread must work.
2. The same command with a classic BPF seccomp program supplied through an FD.
   Normal reads, writes and threads must work; socket and extra-process creation,
   process-group/session changes, namespace escape and cross-process access must
   be denied. `clone3` returns ENOSYS to permit the pthread clone fallback;
   `clone` requires CLONE_THREAD. Unsupported architectures and x32 ABI numbers
   are killed by the policy.

The probe uses public Linux interface constants and a new standalone
implementation. No application source file is copied or imported. Every stage
has a 20-second time limit and bounded captured output. Only its own newly
created process group is stopped. There is no privileged/SUID fallback.

`test_probe.py` checks every BPF rule using a small pure interpreter. Live checks
exercise safe representative system calls. Direct vfork, ptrace and unsupported
ABI execution are not attempted: their rules are interpreter-checked, not claimed
as separately observed live calls. The `posix_spawn` and fork checks exercise
safe process-creation paths.

## Fixed HTTP interface

- `GET /healthz`: process availability only. **HTTP 200 is not capability PASS.**
- `GET /` or `GET /result`: one startup run's fixed-schema JSON result.
- HEAD works for those exact paths. Other paths, including query strings, return
  fixed 404. Write methods return fixed 405 without reading a body.
- HTTP requests cannot rerun the probe, select commands, upload files, or read
  arbitrary paths. Request paths, bodies and headers are not logged.
- Stderr is classified into fixed codes and hashed; raw process text is not
  returned. Temporary namespace IDs are compared internally and not published.

## Results

| Outcome | Meaning |
|---|---|
| `PENDING` | Startup probe is still running. |
| `PASS_SCOPED` | Both stages, all required checks, and owned-process cleanup passed in this exact runtime. |
| `INCOMPATIBLE_SCOPED` | A required namespace/mount/seccomp operation was explicitly denied, or a correctly formed synthetic contract assertion failed. Scope is the current runtime and identity, not every possible host. |
| `INCONCLUSIVE` | Wrong architecture/root identity, missing dependencies, setup/internal error, resource limit, timeout, signal termination, cancellation, or unproven cleanup. Do not label this a kernel incompatibility. |

A signal exit (including SIGKILL/137), missing result, failed image pull/build,
or an out-of-memory marker cannot establish namespace rejection. Examine the
failed stage and fixed result code. Do not silently remove isolation or buy a
larger plan to manufacture a passing result.

## Render settings (operator must have separate resource approval)

| Setting | Value |
|---|---|
| Service | One temporary **Web Service** |
| Source | This standalone public repository at an exact commit |
| Runtime | Docker / linux amd64 |
| Region | Singapore, if approved by the operator |
| Compute | Free only; never automatically upgrade |
| Dockerfile | `./Dockerfile` |
| Build context | Repository root `.` |
| Build command | Unset; Dockerfile provides the build |
| Docker/start command | Unset; image CMD starts `python -B /opt/probe/server.py` |
| Health check | `/healthz` |
| Environment | Platform `PORT` only; no secrets, credentials, or database URLs |
| Disk / database / cron | None |
| Auto deploy | Off; retain the exact tested source commit |

The base is a digest-pinned official Python slim image. The only apt package
added explicitly is bubblewrap (with its package dependencies), installed during
the build, not on the host. No pip packages, Qt, compiler, product dependencies,
registry login, or live data are required. The binary SHA and policy SHA are
included in the runtime result. The apt package is supplied by Debian bookworm
repositories, so record the resulting image/build identity for the actual run.

Collect the result and source/image identities, then delete the temporary
service according to the operator's separately approved deadline. A restart
creates a fresh startup run; this probe does not keep Free services awake.
Publication of this generic source does not authorize deployment, spending,
account changes, or a production service.

## Local checks

`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_probe`

These checks validate policy branching, classification and the fixed HTTP
interface. They are **not** native Linux/bubblewrap evidence. Native observation
must come from the approved target runtime.

## Public references

- https://manpages.debian.org/bookworm/bubblewrap/bwrap.1.en.html
- https://render.com/docs/docker
- https://render.com/docs/deploying-an-image
- https://render.com/docs/free
