# Fixed A/B/C evidence matrix

Status now: NOT_RUN for every runtime row. Preparation unit tests do not
change any row's runtime status.

| Group | Fixed positive/negative cases | Required actual evidence |
| --- | --- | --- |
| Setup T | Four-ID identity, zero E/P/I/A, NNP; T creates role-group 0440 inputs | stat owner/group/mode, explicit groups/env |
| A P,V,R | Own input read and own output write succeed; setuid/setgid0, T marker, T proc environ/secret FD, input write/chmod, code write, S control, dispatch token and both foreign lanes denied | each errno (EACCES/EPERM only), all four UID/GID values, groups, five capability sets including bounding, NNP, FD kinds/access modes, env names |
| B P,V,R | Filter loads; input read and one thread succeed; socket/socketpair/connect/sendto/sendmsg, fork/nonthread clone/clone3, setsid/setpgid/unshare/setns, ptrace/process_vm and all three io_uring calls denied | exact syscall result/errno, limited safe pre-filter baselines, filters count increase, arch/libseccomp/policy SHA/BPF SHA |
| B policy coverage | Also denies vfork, bind/listen/accept, mmsg/SCM_RIGHTS receive/send, namespace clone flags, pidfd_getfd/kcmp and selected privileged kernel paths | fixed source/policy; uncalled rules explicitly not claimed individually runtime tested |
| C timeout | Fixed P process acknowledges filter+identity readiness, sleeps; two-second deadline; s6 sends TERM then KILL if needed | actual s6 direct-child start identity/PID/start ticks, wait/finish, terminating signal and <=3s measured stop |
| C internal interruption | Old P generation0 writes partial; T controller cannot signal P; interrupt that controller once; terminate old P; old job UNKNOWN/no replay; new T controller creates a distinct gen1 area, new P writes there; T rejects old and accepts complete gen1 | protected parent receipts/raw streams, real signal termination, separate generation paths, partial/complete state |
| Cleanup T/S | No-follow fixed-tree cleanup; no root DAC bypass; T quarantine/HOLD if unreadable; S waits all nontransport s6 parents | measured work bytes/files, per-lane result, actual parent wait returns, full fixed-case receipts |
| Optional platform secret file | NOT_CONFIGURED_NOT_TESTED | A self-created T marker is not evidence of provider secret-mount isolation |

Success requires 14 completed fixed case records plus five nontransport s6
parent waits, all A/B checks and both deliberate signal cases. H transport is a
separate trusted T process, still live during collection; its termination and
Render deletion need the external operator's cleanup evidence.

Classification: missing approved root/caps/pins/quota => PRECONDITION_NOT_MET;
authorized OS operation explicitly denied => CAPABILITY_DENIED_FOR_THIS_PROFILE;
positive controls work but access/filter boundary fails => ISOLATION_CHECK_FAILED;
startup/dependency/transport/restart/incomplete case => INCONCLUSIVE;
missing stop/wait/cleanup proof => CLEANUP_UNKNOWN. Only all necessary evidence
permits ALL_REQUIRED_CAPABILITIES_OBSERVED for this exact synthetic profile.

No product parsing, real order input, product tests, Ready transition, capacity
acceptance, production deployment, employee access or previous hang-policy
approval follows from any result here.
