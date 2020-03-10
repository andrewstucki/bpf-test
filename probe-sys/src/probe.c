#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <libelf.h>
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include "probe.h"
#include "_probe.h"
#include "probe.skel.h"

struct handle_sleep_wrapper {
	void *ctx;
	handle_sleep *handler;
};

struct state {
	struct probe_bpf *obj;
	struct perf_buffer *pb;
	struct bpf_link *kprobe;
	struct bpf_link *uprobe;
	struct handle_sleep_wrapper *handler;
};

static inline int sym_resolve_callback(const char *name, uint64_t addr, uint64_t _ignored, void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  if (!strcmp(name, sym->name)) {
    sym->offset = addr;
    return -1;
  }
  return 0;
}

static inline void handle_sleep_event(void *ctx, int cpu, void *data, __u32 size) {
  struct event *e = data;
	struct handle_sleep_wrapper *handle = ctx;
	struct sleep_event event = {
		.cookie = e->cookie,
		.tid = (e->pid >> 32) & 0xFFFF,
		.pid = e->pid & 0xFFFF,
		.cpu = cpu,
	};
	handle->handler(handle->ctx, event);
}

struct state * new_state(void *ctx, handle_sleep *handler) {
	struct state *s= (struct state *)malloc(sizeof(struct state));
	if (!s) {
		return NULL;
	}
	s->handler = (struct handle_sleep_wrapper *)malloc(sizeof(struct handle_sleep_wrapper));
	if (!s->handler) {
		goto cleanup_state;
	}
	s->handler->ctx = ctx;
	s->handler->handler = handler;

	struct perf_buffer_opts pb_opts = {
    .sample_cb = handle_sleep_event,
		.ctx = (void *)s->handler,
  };

	const char *path = bcc_procutils_which_so("ssl", -1);
	if (!path) {
		goto cleanup_handler;
	}

  struct bcc_symbol_option option = {
    .use_debug_file = 1,
    .check_debug_file_crc = 1,
    .lazy_symbolize = 1,
    .use_symbol_type = (1 << STT_FUNC) | (1 << STT_GNU_IFUNC)
  };
	struct bcc_symbol sym = {
		.name = "SSL_write"
	};
	int err = bcc_elf_foreach_sym(path, sym_resolve_callback, &option, &sym);
	if ((err == -1) || (err == 0 && sym.offset == 0)) {
		goto cleanup_handler;
	}

	s->obj = probe_bpf__open_and_load();
	if (!s->obj) {
		goto cleanup_handler;
	}
  s->pb = perf_buffer__new(bpf_map__fd(s->obj->maps.events), 1, &pb_opts);
	if (!s->pb) {
		goto cleanup_bpf;
	}

	s->kprobe = bpf_program__attach_kprobe(s->obj->progs.handle_kprobe, false, SYS_NANOSLEEP_KPROBE_NAME);
	if (!s->kprobe) {
		goto cleanup_buffer;
	}
	s->uprobe = bpf_program__attach_uprobe(s->obj->progs.handle_uprobe, true, -1, path, sym.offset);
	if (!s->uprobe) {
		goto cleanup_kprobe;
	}

	goto free;

cleanup_kprobe:
	bpf_link__destroy(s->kprobe);
cleanup_buffer:
	perf_buffer__free(s->pb);
cleanup_bpf:
	probe_bpf__destroy(s->obj);
cleanup_handler:
	free((void *)s->handler);
cleanup_state:
	free((void *)s);
	s = NULL;

free:
	free((void *)path);
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
		if (s->uprobe != NULL) {
			bpf_link__destroy(s->uprobe);
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