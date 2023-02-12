#include "helpers.h"

static void sig_handler(int sig) {
  exit(EXIT_SUCCESS);
}

static int setup_libbpf_print_verbose(enum libbpf_print_level level, const char *format,
                                      va_list args) {
  return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level, const char *format,
                                         va_list args) {
  if (level == LIBBPF_WARN) {
    return vfprintf(stderr, format, args);
  }
  return 0;
}

static void setup_libbpf_logging(bool verbosity) {
  if (verbosity) {
    libbpf_set_print(setup_libbpf_print_verbose);
  } else {
    libbpf_set_print(setup_libbpf_print_no_verbose);
  }
}

configuration init_configuration(int argc, char **argv) {
  configuration conf = {};
  conf.buf_dim = DEFAULT_BUFFER_DIM;

  for (int i = 0; i < argc; i++) {
    if (!strcmp(argv[i], VERBOSE)) {
      conf.verbose = true;
    }

    if (!strcmp(argv[i], DRY_RUN)) {
      conf.dry_run = true;
    }

    if (!strcmp(argv[i], BUFFER_DIM)) {
      if (!(i + 1 < argc)) {
        fprintf(stderr, "You need to specify also the "
                        "event buffer size! Bye!\n");
        conf.err = -1;
        return conf;
      }
      conf.buf_dim = strtoul(argv[++i], NULL, 10);
    }
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  setup_libbpf_logging(conf.verbose);

  /* Clean handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  return conf;
}

bool is_dry_run(configuration conf) {
  return conf.dry_run;
}
