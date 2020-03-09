#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "probe.h"
#include "probe.skel.h"

#ifdef __x86_64__
#define SYS_NANOSLEEP_KPROBE_NAME "__x64_sys_nanosleep"
#elif defined(__s390x__)
#define SYS_NANOSLEEP_KPROBE_NAME "__s390x_sys_nanosleep"
#else
#define SYS_NANOSLEEP_KPROBE_NAME "sys_nanosleep"
#endif

static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
  struct event *e = data;

  fprintf(stderr, "Cookie: %llx Thread: %d, CPU: %d\n", e->cookie, e->pid, cpu);
}

int main(int argc, char **argv)
{
  struct probe_bpf* obj;
  struct bpf_link *kprobe_link;
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

	usleep(1);

	perf_buffer__poll(pb, 100);
	perf_buffer__free(pb);
	probe_bpf__destroy(obj);
}
