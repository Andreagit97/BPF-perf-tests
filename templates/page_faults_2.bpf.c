#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* We need at least kernel 4.17 for raw tracepoints */

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
  int pid;
  char comm[TASK_COMM_LEN];
  unsigned int cpu;
  /* These are here just to have a bigger event to send. */
  unsigned long one;
  unsigned long two;
  unsigned long three;
  unsigned long four;
  unsigned long five;
  unsigned long six;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} heap SEC(".maps");

SEC("raw_tp/page_fault_user")
int pf_user(void *ctx) {
  struct event *e;
  int zero = 0;

  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) {
    return 0;
  }

  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->cpu = (unsigned long)bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}

SEC("raw_tp/page_fault_kernel")
int pf_kernel(void *ctx) {
  struct event *e;
  int zero = 0;

  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) {
    return 0;
  }

  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->cpu = (unsigned long)bpf_get_smp_processor_id();
  bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
  return 0;
}
