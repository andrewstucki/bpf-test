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
#include "probe.skel.h"

#ifdef __x86_64__
#define SYS_NANOSLEEP_KPROBE_NAME "__x64_sys_nanosleep"
#elif defined(__s390x__)
#define SYS_NANOSLEEP_KPROBE_NAME "__s390x_sys_nanosleep"
#else
#define SYS_NANOSLEEP_KPROBE_NAME "sys_nanosleep"
#endif

#define LIBSSL_PATH "/lib/x86_64-linux-gnu/libssl.so"

static int sym_resolve_callback(const char *name, uint64_t addr, uint64_t _ignored, void *payload) {
  struct bcc_symbol *sym = (struct bcc_symbol *)payload;
  if (!strcmp(name, sym->name)) {
    sym->offset = addr;
    return -1;
  }
  return 0;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
  struct event *e = data;

  fprintf(stderr, "Cookie: %llx Thread: %d, CPU: %d\n", e->cookie, e->pid, cpu);
}

int main(int argc, char **argv) {
	int err;
  struct probe_bpf* obj;
  struct bpf_link *kprobe_link, *uprobe_link;
	struct perf_buffer *pb;
	struct perf_buffer_opts pb_opts = {
    .sample_cb = handle_event,
  };

	obj = probe_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	kprobe_link = bpf_program__attach_kprobe(obj->progs.handle_kprobe, false, SYS_NANOSLEEP_KPROBE_NAME);
	if (!kprobe_link) {
		fprintf(stderr, "failed to attach kprobe\n");
		return 1;
	}
  pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 1, &pb_opts);
	if (!pb) {
		fprintf(stderr, "failed to initialize perf buffer\n");
		return 1;
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
	err = bcc_elf_foreach_sym(LIBSSL_PATH, sym_resolve_callback, &option, &sym);
	if ((err == -1) || (err == 0 && sym.offset == 0)) {
		fprintf(stderr, "error finding symbol\n");
	} else {
		uprobe_link = bpf_program__attach_uprobe(obj->progs.handle_uprobe, true, -1, LIBSSL_PATH, sym.offset);
		if (!uprobe_link) {
			fprintf(stderr, "failed to attach uprobe\n");
		}
	}

	usleep(1);

	perf_buffer__poll(pb, 100);
	perf_buffer__free(pb);
	probe_bpf__destroy(obj);
}
