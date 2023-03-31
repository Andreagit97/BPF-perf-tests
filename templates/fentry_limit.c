#include "helpers.h"
#include "fentry_limit.skel.h"

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Open BPF application */
  struct fentry_limit_bpf *skel = fentry_limit_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  conf.err = fentry_limit_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  conf.err = fentry_limit_bpf__attach(skel);
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
    /* trigger our BPF program */
    fprintf(stderr, ".");
    sleep(1);
  }

cleanup:
  fentry_limit_bpf__destroy(skel);
  return -conf.err;
}
