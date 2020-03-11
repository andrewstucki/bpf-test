#ifndef __PROBE_H
#define __PROBE_H

#include <stdint.h>

struct event {
	uint32_t tid;
	uint32_t pid;
	uint32_t gid;
	uint32_t uid;
	uint32_t cpu;
};

typedef void event_handler(void *ctx, struct event e);

struct state;
struct state * new_state(void *ctx, event_handler *handler);
void poll_state(struct state *self, int timeout);
void destroy_state(struct state *self);

#endif /* __PROBE_H */