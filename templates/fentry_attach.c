#include "helpers.h"
#include <bpf/btf.h>
#include "fentry_attach.skel.h"

static bool fentry_try_attach(int id) {
  int prog_fd, attach_fd;
  char error[4096];
  struct bpf_insn insns[] = {
      {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
      {.code = BPF_JMP | BPF_EXIT},
  };
  LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_TRACE_FENTRY,
              .attach_btf_id = id, .log_buf = error, .log_size = sizeof(error), );

  prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
                          sizeof(insns) / sizeof(struct bpf_insn), &opts);
  if (prog_fd < 0)
    return false;

  attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
  if (attach_fd >= 0)
    close(attach_fd);

  close(prog_fd);
  return attach_fd >= 0;
}

bool fentry_can_attach(const char *name, const char *mod) {
  struct btf *btf, *vmlinux_btf, *module_btf = NULL;
  int err, id;

  vmlinux_btf = btf__load_vmlinux_btf();
  err = libbpf_get_error(vmlinux_btf);
  if (err)
    return false;

  btf = vmlinux_btf;

  if (mod) {
    module_btf = btf__load_module_btf(mod, vmlinux_btf);
    err = libbpf_get_error(module_btf);
    if (!err)
      btf = module_btf;
  }

  id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

  btf__free(module_btf);
  btf__free(vmlinux_btf);
  return id > 0 && fentry_try_attach(id);
}

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Probe fentry/fexit progs with libbpf API */
  if (libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL) != 1) {
    fprintf(stderr, "Detect fentry/fexit progs are not supported through libbpf APIs\n");
    return 1;
  }

  /* Probe fentry/fexit progs with libbpf-tools approach
   * https://github.com/iovisor/bcc/blob/9371e844599fcf82172b7b3566dd4593c37a996d/libbpf-tools/trace_helpers.c#L1015
   */
  if (!fentry_can_attach("do_unlinkat", NULL)) {
    fprintf(stderr, "Detect fentry/fexit progs are not supported through libbpf-tools APIs\n");
    return 1;
  }

  /* Open BPF application */
  struct fentry_attach_bpf *skel = fentry_attach_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  conf.err = fentry_attach_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  conf.err = fentry_attach_bpf__attach(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  if (is_dry_run(conf)) {
    conf.err = 0;
    fprintf(stdout, "OK!\n");
    goto cleanup;
  }

  fprintf(stdout, "Press CTRL+C to terminate\n");

  for (;;) {
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  fentry_attach_bpf__destroy(skel);
  return -conf.err;
}
