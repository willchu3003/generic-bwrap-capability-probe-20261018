# Primary public references checked during preparation

These support the component/API design, not observed Render capability.

- [Debian s6 2.11.3.2-1](https://packages.debian.org/bookworm/s6)
- [Debian util-linux 2.38.1-5+deb12u3](https://packages.debian.org/bookworm/util-linux)
- [Debian libseccomp2 2.5.4-1+deb12u1](https://packages.debian.org/bookworm/libseccomp2)
- [Debian libcap2 amd64 1:2.66-4+deb12u3+b1](https://packages.debian.org/bookworm/libcap2)
- [s6-supervise, actual run/finish and exit125](https://skarnet.org/software/s6/s6-supervise.html)
- [s6-svc, one-shot/down/signal/exit controls](https://skarnet.org/software/s6/s6-svc.html)
- [s6-svstat, machine-readable up/ready/PID](https://skarnet.org/software/s6/s6-svstat.html)
- [s6-svwait, down plus finish completion](https://skarnet.org/software/s6/s6-svwait.html)
- [setpriv manual](https://man7.org/linux/man-pages/man1/setpriv.1.html)
- [Linux capabilities and exec rules](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux no_new_privs](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html)
- [libseccomp v2.5.4 API definitions](https://github.com/seccomp/libseccomp/blob/v2.5.4/include/seccomp.h.in)
- [Render Free service limits](https://render.com/docs/free)
- [Render Docker behavior](https://render.com/docs/docker)

The newer online setpriv manual lists options absent from older util-linux.
This source deliberately uses only identity/groups/NNP/capability options and
loads its filter through libseccomp; it does not assume --seccomp-filter exists
in util-linux 2.38.1.
