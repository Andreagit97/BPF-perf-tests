#include "helpers.h"
#include "btf_loading.skel.h"

// #include <unistd.h>
// #include <sys/resource.h>

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Open BPF application */
  struct btf_loading_bpf *skel = btf_loading_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton. Errno: %d, message: %s\n", errno,
            strerror(errno));
    return 1;
  }

  /* Load & verify BPF programs */
  conf.err = btf_loading_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr,
            "Failed to load and verify BPF skeleton. Errno: %d, "
            "message: %s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  /* Attach tracepoint handler */
  conf.err = btf_loading_bpf__attach(skel);
  if (conf.err) {
    fprintf(stderr,
            "Failed to attach BPF skeleton. Errno: %d, message: "
            "%s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  if (is_dry_run(conf)) {
    conf.err = 0;
    fprintf(stdout, "OK!\n");
    goto cleanup;
  }

  while (skel->bss->stop < 10) {
    printf("Wait first 10 syscalls...\n");
    sleep(1);
  }

  printf("Program correctly terminated\n");

cleanup:
  btf_loading_bpf__destroy(skel);
  return conf.err;
}
