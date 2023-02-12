#include "helpers.h"
#include "ktime.skel.h"
#include "ktime.h"

uint64_t old_ts[MAX_CPU_NUMBER] = {0};

int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event *e = data;

  if (e->ts < old_ts[e->cpu_id]) {
    printf("NEW: %ld, OLD: %ld, DIFF: %ld\n", e->ts, old_ts[e->cpu_id], old_ts[e->cpu_id] - e->ts);
  }
  old_ts[e->cpu_id] = e->ts;
  return 0;
}

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Open BPF application */
  struct ring_buffer *rb_manager = NULL;
  struct ktime_bpf *skel = ktime_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  conf.err = ktime_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb_manager = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb_manager) {
    conf.err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  conf.err = ktime_bpf__attach(skel);
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

  while (true) {
    printf("Running...%d\n", ring_buffer__consume(rb_manager));
    sleep(2);
  }

cleanup:
  ring_buffer__free(rb_manager);
  ktime_bpf__destroy(skel);
  return -conf.err;
}
