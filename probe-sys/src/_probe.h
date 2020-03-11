#ifndef ___PROBE_H
#define ___PROBE_H

#define ARG1(x) ((x)->di)
#define ARG2(x) ((x)->si)
#define ARG3(x) ((x)->dx)
#define ARG4(x) ((x)->cx)
#define ARG5(x) ((x)->r8)
#define RETVAL(x) ((x)->ax)

#ifdef __x86_64__
#define SYS_NANOSLEEP_KPROBE_NAME "__x64_sys_nanosleep"
#else
#define SYS_NANOSLEEP_KPROBE_NAME "sys_nanosleep"
#endif

struct _event {
	__u32 pid;
	__u32 tid;
	__u32 gid;
	__u32 uid;
};

#endif /* ___PROBE_H */
