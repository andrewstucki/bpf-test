#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "_probe.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("kprobe/sys_nanosleep")
int handle_kprobe(struct pt_regs *ctx) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
  struct _event e = {
		.pid = pid_tgid >> 32,
		.tid = pid_tgid,
		.gid = uid_gid >> 32,
		.uid = uid_gid,
	};
	bpf_perf_event_output(ctx, &events, 0, &e, sizeof(e));
	return 0;
}

char _license[] SEC("license") = "GPL";
