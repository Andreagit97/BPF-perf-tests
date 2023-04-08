#include "helpers.h"
#include "fentry_attach.skel.h"

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Probe fentry/fexit progs */
  if (libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL) != 1) {
    fprintf(stderr, "fentry/fexit progs are not supported\n");
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
