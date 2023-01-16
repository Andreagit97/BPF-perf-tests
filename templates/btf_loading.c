#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <errno.h>
#include "btf_loading.skel.h"

#define VERBOSE "--verbose"

static void sig_handler(int sig)
{
	exit(EXIT_SUCCESS);
}

static int setup_libbpf_print_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int setup_libbpf_print_no_verbose(enum libbpf_print_level level, const char* format, va_list args)
{
	if(level == LIBBPF_WARN)
	{
		return vfprintf(stderr, format, args);
	}
	return 0;
}

static void setup_libbpf_logging(bool verbosity)
{
	if(verbosity)
	{
		libbpf_set_print(setup_libbpf_print_verbose);
	}
	else
	{
		libbpf_set_print(setup_libbpf_print_no_verbose);
	}
}

int main(int argc, char **argv)
{
	struct btf_loading_bpf *skel =  NULL;
    bool verbose = false;
	int err = 0;

	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], VERBOSE))
		{
            verbose = true;
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    setup_libbpf_logging(verbose);

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel = btf_loading_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		return 1;
	}

	/* Load & verify BPF programs */
	err = btf_loading_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = btf_loading_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}


    while(skel->bss->stop < 10)
    {
        printf("Wait first 10 syscalls...\n");
        sleep(1);
    }
    printf("Program correctly terminated\n");


cleanup:
	btf_loading_bpf__destroy(skel);
	return err;
}
