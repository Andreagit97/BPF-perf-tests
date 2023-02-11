#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel version 4.14 */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} tail_table SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int test(void *ctx)
{

	bpf_tail_call(ctx, &tail_table, 0);
	return 0;
}

SEC("tp")
int example(void *ctx)
{
	bpf_printk("called");
	return 0;
}
