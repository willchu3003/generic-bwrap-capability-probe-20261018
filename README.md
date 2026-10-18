# Generic own-process capability observation

Preparation only: NOT_BUILT / NOT_RUN / NOT_PUBLISHED. This is a new, different
control chain. It does not run setpriv, replay an earlier deployment, run roles,
load a filter, or establish a product/platform PASS.

## Exact sequence

1. The direct Python Docker entry reads its own UID/GID/groups, five capability
   sets, NoNewPrivs and read-only PR_GET_NO_NEW_PRIVS/PR_GET_SECUREBITS. This is
   already after the container runtime's first exec, not a pre-runtime snapshot.
2. If NNP is 0, it explicitly requests **PR_SET_NO_NEW_PRIVS=1**, then reads the
   second snapshot in the same PID. If already 1, it makes no setter call.
   This is a one-way self-restriction, **not an entirely read-only experiment**.
   An unavailable/denied NNP=1 stops the exec stage and preserves incomplete data.
3. It performs one ordinary exec of the same fixed Python/script, same PID, then
   reads a third snapshot. It does not call PR_SET_KEEPCAPS, PR_SET_SECUREBITS,
   capset, setuid/setgid, chown, setcap, mount or an external utility. Kernel exec
   transitions may change observed masks/securebits; no explicit writer is used
   except NNP=1. It never requests added capabilities or turns NNP off.

The three stages are `docker_entry_observer`, `after_nnp_before_exec`, and
`after_ordinary_exec`. A fixed owned /tmp marker preserves bounded nonsecret
metadata across the self-exec. Existing marker means NO_REPLAY, not another run.

Why no setpriv: the old utility chain can change KEEP_CAPS/effective state.
This alternative respects the prohibition on explicitly changing those states.
**It cannot observe the old setpriv segment or prove where an earlier deleted
process lost a bit.** Removing that utility makes this a distinct control, not
a reproduced old chain. No diagnostic conclusion authorizes a platform change.

## Fixed result

One JSON line is printed, then GET /healthz and GET /result serve identical,
immutable JSON <=16384 bytes. GETs do not repeat observations. POST has no
dispatch/action and is rejected. There are no uploads, tokens, command/path/UID
parameters, accounts, orders, external fetches or business inputs. Only PORT is
read from the environment (default10000, allowed1024..65535); no env dump.

Each snapshot contains:

- stage, PID/PPID;
- Uid/Gid: all four kernel-reported values; Groups;
- raw CapEff/CapPrm/CapInh/CapAmb/CapBnd hex and decoded required P bits;
- raw NoNewPrivs plus read-only prctl NNP/securebits value or errno.

Top-level fields include nnp_operation, actual observation duration, gained/lost
masks across both intervals, and explicit `original_setpriv_chain_reproduced=false`.
Possible observation labels:

- REQUIRED_P_BITS_MISSING_AT_FIRST_OBSERVER_ENTRY
- REQUIRED_P_BITS_MISSING_AT_SECOND_SNAPSHOT
- REQUIRED_P_BITS_MISSING_AFTER_ORDINARY_EXEC
- REQUIRED_P_BITS_PRESENT_AT_ALL_THREE_SNAPSHOTS
- INCONCLUSIVE_MISSING_PHASE / INCONCLUSIVE_PID_CHANGED

These are observations of this chain/service only. They are not a finding that
NNP caused a change, a platform-wide policy statement, original-chain root cause,
A/B/C success, or product PASS. Values are not forced to zero or to 0xe0.

Observation target <=10 seconds; no looping workload or subprocess tree.
The tiny result responder stays for <=15 minutes after observation; this is
result retention, not additional probe work. Authorized operator must delete the
single Free service after collection and at most one hour after its creation,
including build. Automatic platform restarts with ephemeral filesystem loss
cannot be prevented by a local marker: no absolute cross-restart once claim.
On restart/change/incomplete evidence, preserve UNKNOWN, no manual retry.

## Recipe and checks

Official Python linux/amd64 base digest is pinned in Dockerfile; there are no
RUN commands, package installations, extra dependencies, ownership changes,
privileged/cap-add settings or external runtime network calls. USER0:0 is a
container identity request, not a capability guarantee. The responder uses the
observed identity and adds no privilege. No S or T/P/V/R roles are started.

`python3 -B -m unittest discover -s tests -v` runs pure/mocked logic plus ordinary
disposable file tests. It never invokes prctl, executes the Docker main, loads a
filter, changes UID/capability/securebits, binds a port or contacts an endpoint.

Linux NNP semantics: https://docs.kernel.org/userspace-api/no_new_privs.html
Capability semantics: https://man7.org/linux/man-pages/man7/capabilities.7.html
