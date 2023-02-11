#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel 4.17 for raw tracepoints */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("raw_tp/page_fault_user")
int pf_user(void *ctx)
{
	int first = 0;
	int second = 1;
	int sum = 0;

	if(bpf_get_smp_processor_id() < 100000)
	{
		sum = first + second;
	}

	return 0;
}

SEC("raw_tp/page_fault_kernel")
int pf_kernel(void *ctx)
{
	int first = 0;
	int second = 1;
	int sum = 0;

	if(bpf_get_smp_processor_id() < 100000)
	{
		sum = first + second;
	}

	return 0;
}
