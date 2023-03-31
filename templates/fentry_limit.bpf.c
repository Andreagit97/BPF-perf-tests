// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat1, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit1, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat2, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit2, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat3, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit3, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat4, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit4, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat5, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit5, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat6, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit6, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat7, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit7, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat8, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit8, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat9, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit9, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat10, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit10, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat11, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit11, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat12, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit12, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat13, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit13, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat14, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit14, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat15, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit15, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat16, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit16, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat17, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit17, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat18, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit18, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat19, int dfd, struct filename *name) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
  return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit19, int dfd, struct filename *name, long ret) {
  pid_t pid;

  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
  return 0;
}

/* We cannot attach more than 38 tramp links.
 * See the hard limitation in the kernel `BPF_MAX_TRAMP_LINKS`
 */

// SEC("fentry/do_unlinkat")
// int BPF_PROG(do_unlinkat20, int dfd, struct filename *name) {
//   pid_t pid;

//   pid = bpf_get_current_pid_tgid() >> 32;
//   bpf_printk("fentry: pid = %d, filename = %s\n", pid, name->name);
//   return 0;
// }

// SEC("fexit/do_unlinkat")
// int BPF_PROG(do_unlinkat_exit20, int dfd, struct filename *name, long ret) {
//   pid_t pid;

//   pid = bpf_get_current_pid_tgid() >> 32;
//   bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
//   return 0;
// }

SEC("fentry/security_bprm_check")
int security1(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi1(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security2(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi2(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security3(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi3(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security4(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi4(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security5(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi5(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security6(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi6(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security7(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi7(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security8(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi8(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security9(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi9(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security10(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi10(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fentry/security_bprm_check")
int security11(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}

SEC("fexit/security_bprm_check")
int security_exi11(void *ctx) {
  pid_t pid;
  pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("fentry: pid = %d", pid);
  return 0;
}
