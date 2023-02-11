#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel version 5.8 for BPF ringbuf map */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct ringbuf_map
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
};

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, u32);
	__type(value, u32);
	__array(values, struct ringbuf_map);
} ringbuf_maps SEC(".maps");

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
	struct ringbuf_map *rb = (struct ringbuf_map *)bpf_map_lookup_elem(&ringbuf_maps, &e.cpu_id);
	if(!rb)
	{
		return 0;
	}

	bpf_ringbuf_output(rb, &e, sizeof(e), BPF_RB_NO_WAKEUP);
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit_trace(void *ctx)
{
	struct event e = {0};
	e.cpu_id = (u32)bpf_get_smp_processor_id();
	struct ringbuf_map *rb = (struct ringbuf_map *)bpf_map_lookup_elem(&ringbuf_maps, &e.cpu_id);
	if(!rb)
	{
		return 0;
	}

	bpf_ringbuf_output(rb, &e, sizeof(e), BPF_RB_NO_WAKEUP);
	return 0;
}
