#include "helpers.h"
#include "page_faults_2.skel.h"

static volatile bool exiting = false;
unsigned long captured = 0;
unsigned long dropped = 0;

static void sig_handler(int sig) {
  printf("\nStop capture...\n");
  printf("Events captured: %lu\n", captured);
  printf("Events dropped: %lu\n", dropped);
  exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  captured++;
}

void handle_drop(void *ctx, int cpu, long long unsigned int size) {
  dropped++;
}

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Overwrite default signal handlers */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Open BPF application */
  struct perf_buffer *pb = NULL;
  struct page_faults_2_bpf *skel = page_faults_2_bpf__open();
  if (!skel) {
    conf.err = 1;
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  conf.err = page_faults_2_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  conf.err = page_faults_2_bpf__attach(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up perf buffer manager */
  int page_size = getpagesize();
  size_t page_cnt = 0;
  if (page_size != 0) {
    page_cnt = conf.buf_dim / page_size;
  } else {
    printf("[WARNING] `getpagesize()` returned `0`!\n");
    page_cnt = 4096;
  }

  pb =
      perf_buffer__new(bpf_map__fd(skel->maps.pb), page_cnt, handle_event, handle_drop, NULL, NULL);
  if (libbpf_get_error(pb)) {
    conf.err = 1;
    fprintf(stderr, "Failed to create perf buffer\n");
    goto cleanup;
  }

  if (is_dry_run(conf)) {
    conf.err = 0;
    fprintf(stdout, "OK!\n");
    goto cleanup;
  }

  printf("Start capture...\n");

  while (!exiting) {
    /* It consumes all events from all CPUs. */
    conf.err = perf_buffer__consume(pb);
    if (conf.err != 0) {
      printf("error\n");
      break;
    }
  }

cleanup:
  perf_buffer__free(pb);
  page_faults_2_bpf__destroy(skel);
  return -conf.err;
}
