#include "helpers.h"
#include "perfbuf_output.skel.h"

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  return;
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  return;
}

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Load and verify BPF application */
  struct perf_buffer *pb = NULL;
  struct perfbuf_output_bpf *skel = perfbuf_output_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr,
            "Failed to open and load BPF skeleton. Errno: %d, "
            "message: %s\n",
            errno, strerror(errno));
    return 1;
  }

  /* Attach tracepoint */
  conf.err = perfbuf_output_bpf__attach(skel);
  if (conf.err) {
    fprintf(stderr,
            "Failed to attach BPF skeleton. Errno: %d, message: "
            "%s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  /* Obtain the dimension in number of pages */
  int page_size = getpagesize();
  size_t page_cnt = 0;
  if (page_size != 0) {
    page_cnt = conf.buf_dim / page_size;
  } else {
    conf.err = 1;
    fprintf(stderr,
            "Failed to get page size from `getpagesize()`. Errno: "
            "%d, message: %s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), page_cnt, handle_event, lost_event, NULL, NULL);
  if (libbpf_get_error(pb)) {
    conf.err = 1;
    fprintf(stderr,
            "Failed to create perf buffer. Errno: %d, message: "
            "%s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  if (is_dry_run(conf)) {
    conf.err = 0;
    fprintf(stdout, "OK!\n");
    goto cleanup;
  }

  printf("Chosen PER-CPU buffer size: %ld\n", page_cnt * page_size);
  printf("Start capture...\n");

  while (true) {
    printf("Running... \n");
    perf_buffer__consume(pb);
    sleep(2);
  }

cleanup:
  perf_buffer__free(pb);
  perfbuf_output_bpf__destroy(skel);

  return conf.err;
}
