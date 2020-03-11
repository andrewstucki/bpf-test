#include "probe.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "_probe.h"
#include "probe.skel.h"

struct handle_event_wrapper {
  void *ctx;
  event_handler *handler;
};

struct state {
  struct probe_bpf *obj;
  struct perf_buffer *pb;
  struct bpf_link *kprobe;
  struct handle_event_wrapper *handler;
};

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt,
                     va_list args) {
  // return vfprintf(stderr, fmt, args);
  return 0;
}

static inline void handle_event(void *ctx, int cpu, void *data, __u32 size) {
  struct _event *e = data;
  struct handle_event_wrapper *handle = ctx;
  struct event ev = {
      .tid = e->tid,
      .pid = e->pid,
      .gid = e->gid,
      .uid = e->uid,
      .cpu = cpu,
  };
  handle->handler(handle->ctx, ev);
}

struct state *new_state(void *ctx, event_handler *handler) {
  libbpf_set_print(print_libbpf_log);
  struct state *s = (struct state *)malloc(sizeof(struct state));
  if (!s) {
    return NULL;
  }
  s->handler = (struct handle_event_wrapper *)malloc(
      sizeof(struct handle_event_wrapper));
  if (!s->handler) {
    goto cleanup_state;
  }
  s->handler->ctx = ctx;
  s->handler->handler = handler;

  struct perf_buffer_opts pb_opts = {
      .sample_cb = handle_event,
      .ctx = (void *)s->handler,
  };

  s->obj = probe_bpf__open_and_load();
  if (!s->obj) {
    goto cleanup_handler;
  }
  s->pb = perf_buffer__new(bpf_map__fd(s->obj->maps.events), 1, &pb_opts);
  if (!s->pb) {
    goto cleanup_bpf;
  }

  s->kprobe = bpf_program__attach_kprobe(s->obj->progs.handle_kprobe, false,
                                         SYS_NANOSLEEP_KPROBE_NAME);
  if (!s->kprobe) {
    goto cleanup_buffer;
  }

  goto done;

cleanup_buffer:
  perf_buffer__free(s->pb);
cleanup_bpf:
  probe_bpf__destroy(s->obj);
cleanup_handler:
  free((void *)s->handler);
cleanup_state:
  free((void *)s);
  s = NULL;

done:
  return s;
}

void destroy_state(struct state *s) {
  if (s != NULL) {
    if (s->pb != NULL) {
      perf_buffer__free(s->pb);
    }
    if (s->kprobe != NULL) {
      bpf_link__destroy(s->kprobe);
    }
    if (s->obj != NULL) {
      probe_bpf__destroy(s->obj);
    }
    if (s->handler != NULL) {
      free((void *)s->handler);
    }
    free((void *)s);
  }
}

void poll_state(struct state *s, int timeout) {
  perf_buffer__poll(s->pb, timeout);
}
