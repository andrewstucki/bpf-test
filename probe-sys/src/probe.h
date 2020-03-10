#ifndef __PROBE_H
#define __PROBE_H

struct state;
struct state * new_state();
void poll_state(struct state *self, int timeout);
void destroy_state(struct state *self);

#endif /* __PROBE_H */