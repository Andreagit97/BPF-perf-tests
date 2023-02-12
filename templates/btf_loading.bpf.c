#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel version 5.5 for globals */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

unsigned long stop = 0;

SEC("tp_btf/sys_enter")
int sys_enter_trace(void *ctx) {
  stop++;
  return 0;
}
