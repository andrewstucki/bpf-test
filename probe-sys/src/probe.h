#ifndef __PROBE_H
#define __PROBE_H

#include <stdint.h>

struct sleep_event {
	uint64_t cookie;
	uint32_t tid;
	uint32_t pid;
	uint32_t cpu;
};

typedef void handle_sleep(void *ctx, struct sleep_event e);

struct state;
struct state * new_state(void *ctx, handle_sleep *handler);
void poll_state(struct state *self, int timeout);
void destroy_state(struct state *self);

#endif /* __PROBE_H */