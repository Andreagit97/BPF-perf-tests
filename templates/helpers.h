#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

/* Used for programs with buffers */
#define DEFAULT_BUFFER_DIM 1024 * 1024 /* 1 MB */
#define BUFFER_DIM "--buf"

#define VERBOSE "--verbose"
#define DRY_RUN "--dry-run"

typedef struct configuration {
  bool verbose;
  bool dry_run;
  int err;
  uint32_t buf_dim;
} configuration;

bool is_dry_run(configuration conf);

configuration init_configuration(int argc, char **argv);
