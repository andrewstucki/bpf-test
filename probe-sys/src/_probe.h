#ifndef ___PROBE_H
#define ___PROBE_H

#ifdef __x86_64__
#define SYS_NANOSLEEP_KPROBE_NAME "__x64_sys_nanosleep"
#elif defined(__s390x__)
#define SYS_NANOSLEEP_KPROBE_NAME "__s390x_sys_nanosleep"
#else
#define SYS_NANOSLEEP_KPROBE_NAME "sys_nanosleep"
#endif

struct event {
	pid_t pid;
	__u64 cookie;
};

#endif /* ___PROBE_H */
