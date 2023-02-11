#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel version 4.14 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

struct event
{
	int pid;
	u32 cpu_id;
};

SEC("tp/raw_syscalls/sys_enter")
int sys_enter_trace(void *ctx)
{
	struct event e = {0};
	e.cpu_id = (u32)bpf_get_smp_processor_id();
	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

SEC("tp/raw_syscalls/sys_enter")
int sys_exit_trace(void *ctx)
{
	struct event e = {0};
	e.cpu_id = (u32)bpf_get_smp_processor_id();
	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}
