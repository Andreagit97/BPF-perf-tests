#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "ktime.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} rb SEC(".maps");

uint64_t cpu_ts[MAX_CPU_NUMBER] = {0};

SEC("tp/raw_syscalls/sys_enter")
int test(void *ctx)
{
	struct event e = {0};

	/* Get the old timestamp for this CPU */
	u32 cpu_id = (u32)bpf_get_smp_processor_id();
	uint64_t old_ts = cpu_ts[cpu_id & (MAX_CPU_NUMBER - 1)];

	/* Get the new timestamp */
	uint64_t new_ts = bpf_ktime_get_boot_ns();

	/* Check if we could have an out of order using kernel helpers */
	if(new_ts < old_ts)
	{
		bpf_printk("NEW: %ld, OLD: %ld, DIFF: %ld", new_ts, old_ts, old_ts - new_ts);
	}

	cpu_ts[cpu_id & (MAX_CPU_NUMBER - 1)] = new_ts;

	e.cpu_id = cpu_id;
	e.ts = new_ts;

	bpf_ringbuf_output(&rb, &e, sizeof(e), BPF_RB_NO_WAKEUP);
	return 0;
}
