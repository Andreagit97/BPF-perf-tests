#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include "perfbuf_output.skel.h"

#define DEFAULT_BUFFER_DIM 1024 * 1024 /* 1 MB */
#define BUFFER_DIM "--buf"

static void sig_handler(int sig)
{
	exit(EXIT_SUCCESS);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct perfbuf_output_bpf *skel;
	int err = 0;

	/* Set single buffer dimension */
	uint32_t buf_dim = DEFAULT_BUFFER_DIM;
	for(int i = 0; i < argc; i++)
	{
		if(!strcmp(argv[i], BUFFER_DIM))
		{
			if(!(i + 1 < argc))
			{
				fprintf(stderr, "You need to specify also the event buffer size! Bye!\n");
				exit(EXIT_FAILURE);
			}
			buf_dim = strtoul(argv[++i], NULL, 10);
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = perfbuf_output_bpf__open_and_load();
	if(!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		return 1;
	}

	/* Attach tracepoint */
	err = perfbuf_output_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* Obtain the dimension in number of pages */
	int page_size = getpagesize();
	size_t page_cnt = 0;
	if(page_size != 0)
	{
		page_cnt = buf_dim / page_size;
	}
	else
	{
		fprintf(stderr, "Failed to get page size from `getpagesize()`. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	printf("Chosen PER-CPU buffer size: %ld\n", page_cnt * page_size);

	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), page_cnt, NULL, NULL, NULL, NULL);
	if(libbpf_get_error(pb))
	{
		fprintf(stderr, "Failed to create perf buffer. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	printf("Start capture...\n");

	while(true)
	{
		printf("Running...\n");
		sleep(2);
	}

cleanup:
	perf_buffer__free(pb);
	perfbuf_output_bpf__destroy(skel);

	return err;
}
