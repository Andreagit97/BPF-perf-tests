#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, int);
} tail_table SEC(".maps");


SEC("tp_btf/sys_enter")
int test(void *ctx)
{
	bpf_tail_call(ctx, &tail_table, 0);
	return 0;
}

SEC("tp_btf")
int example(void *ctx)
{
	bpf_printk("called");
	return 0;
}
