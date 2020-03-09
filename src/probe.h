#ifndef __PROBE_H
#define __PROBE_H

struct event {
	pid_t pid;
	__u64 cookie;
};

#endif /* __PROBE_H */
