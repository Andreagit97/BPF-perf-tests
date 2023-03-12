#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kretsyscall/getpgid")
int BPF_KRETPROBE(handle_getpid) {
  const char step0[] = "called";
  bpf_trace_printk(step0, sizeof(step0));
  return 0;
}
