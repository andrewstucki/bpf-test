#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "probe.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_nanosleep")
int handle_kprobe(struct pt_regs *ctx)
{
  struct event e = {};

  e.pid = bpf_get_current_pid_tgid();
  e.cookie = 0x12345678;

	bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));
	return 0;
}

SEC("uprobe/openssl_write")
int handle_uprobe(struct pt_regs *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
