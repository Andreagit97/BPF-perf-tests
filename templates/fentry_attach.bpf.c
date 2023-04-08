// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("do_unlinkat: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fentry/security_bprm_check")
int security_bprm(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("security_bprm: pid = %d", pid);
  return 0;
}
