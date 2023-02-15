#include "helpers.h"
#include "ringbuf_output.skel.h"

int handle_event(void *ctx, void *data, size_t data_sz) {
  return 0;
}

int main(int argc, char **argv) {
  configuration conf = init_configuration(argc, argv);
  if (conf.err) {
    fprintf(stderr, "Error in the configuration\n");
    return 1;
  }

  /* Open BPF application */
  int *ringbufs_fds = NULL;
  struct ring_buffer *rb_manager = NULL;
  int ringubuf_array_fd = -1;
  struct ringbuf_output_bpf *skel = ringbuf_output_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton. Errno: %d, message: %s\n", errno,
            strerror(errno));
    return 1;
  }

  /* Prepare the ringbuf array */
  int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, conf.buf_dim, NULL);
  if (inner_map_fd < 0) {
    conf.err = 1;
    fprintf(stderr,
            "Failed to create inner map with dim: %d. Errno: %d, "
            "message: %s\n",
            conf.buf_dim, errno, strerror(errno));
    return errno;
  }

  conf.err = bpf_map__set_inner_map_fd(skel->maps.ringbuf_maps, inner_map_fd);
  if (conf.err) {
    fprintf(stderr,
            "Failed to set the dummy inner map inside the ringbuf "
            "array. Errno: %d, message: %s\n",
            errno, strerror(errno));
    return errno;
  }

  /* We will have a ring buffer for every CPU */
  int n_cpus = libbpf_num_possible_cpus();
  if (bpf_map__set_max_entries(skel->maps.ringbuf_maps, n_cpus)) {
    conf.err = 1;
    fprintf(stderr,
            "Failed to set max entries for the ringbuf_array to "
            "'%d'. Errno: %d, message: %s\n",
            n_cpus, errno, strerror(errno));
    return errno;
  }

  /* Load & verify BPF programs */
  conf.err = ringbuf_output_bpf__load(skel);
  if (conf.err) {
    fprintf(stderr,
            "Failed to load and verify BPF skeleton. Errno: %d, "
            "message: %s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  /* Finalize the ringbuf array after loading */
  /* We don't need anymore the inner map, close it. */
  close(inner_map_fd);

  ringbufs_fds = (int *)calloc(n_cpus, sizeof(int));

  /* Create ring buffer maps. */
  for (int i = 0; i < n_cpus; i++) {
    ringbufs_fds[i] = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, conf.buf_dim, NULL);
    if (ringbufs_fds[i] <= 0) {
      conf.err = 1;
      fprintf(stderr,
              "Failed to create the ringbuf map for CPU "
              "'%d'. Errno: %d, message: %s\n",
              i, errno, strerror(errno));
      goto cleanup;
    }
  }

  /* Create the ringbuf manager */
  rb_manager = ring_buffer__new(ringbufs_fds[0], handle_event, NULL, NULL);
  if (!rb_manager) {
    conf.err = 1;
    fprintf(stderr,
            "Failed to instantiate the ringbuf manager. Errno: %d, "
            "message: %s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  /* Add all remaining buffers into the manager.
   * We start from 1 because the first one is
   * used to instantiate the manager.
   */
  for (int i = 1; i < n_cpus; i++) {
    if (ring_buffer__add(rb_manager, ringbufs_fds[i], handle_event, NULL)) {
      conf.err = 1;
      fprintf(stderr,
              "Failed to add the ringbuf map for CPU %d into "
              "the manager. Errno: %d, message: %s\n",
              i, errno, strerror(errno));
      goto cleanup;
    }
  }

  /* `ringbuf_array` is a maps array, every map inside it is a
   * `BPF_MAP_TYPE_RINGBUF`. */
  ringubuf_array_fd = bpf_map__fd(skel->maps.ringbuf_maps);
  if (ringubuf_array_fd <= 0) {
    conf.err = 1;
    fprintf(stderr,
            "Failed to get the ringubuf_array. Errno: %d, message: "
            "%s\n",
            errno, strerror(errno));
    goto cleanup;
  }

  /* We need to associate every CPU to the right ring buffer */
  for (int i = 0; i < n_cpus; i++) {
    if (bpf_map_update_elem(ringubuf_array_fd, &i, &ringbufs_fds[i], BPF_ANY)) {
      conf.err = 1;
      fprintf(stderr,
              "Failed to add the ringbuf map for CPU '%d' to "
              "ringbuf '%d'. Errno: %d, message: %s\n",
              i, i, errno, strerror(errno));
      goto cleanup;
    }
  }

  /* Attach tracepoint handler */
  conf.err = ringbuf_output_bpf__attach(skel);
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

  printf("Chosen PER-CPU buffer size: %u\n", conf.buf_dim);
  printf("Start capture...\n");

  while (true) {
    printf("Running...%d\n", ring_buffer__consume(rb_manager));
    sleep(2);
  }

cleanup:
  if (ringbufs_fds) {
    for (int i = 0; i < n_cpus; i++) {
      if (ringbufs_fds[i]) {
        close(ringbufs_fds[i]);
      }
    }
    free(ringbufs_fds);
  }
  close(ringubuf_array_fd);
  if (rb_manager) {
    ring_buffer__free(rb_manager);
  }
  ringbuf_output_bpf__destroy(skel);
  return conf.err;
}
