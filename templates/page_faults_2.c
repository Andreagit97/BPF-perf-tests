#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "page_faults_2.skel.h"

#define DESIRED_DIM 16 * 1024 * 1024 /* 16 MB */

static volatile bool exiting = false;
unsigned long captured = 0;
unsigned long dropped = 0;

static void sig_handler(int sig)
{
	printf("\nStop capture...\n");
	printf("Events captured: %lu\n", captured);
	printf("Events dropped: %lu\n", dropped);
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	captured++;
}

void handle_drop(void *ctx, int cpu, long long unsigned int size)
{
	dropped++;
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct page_faults_2_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel = page_faults_2_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = page_faults_2_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = page_faults_2_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up perf buffer manager */
	int page_size = getpagesize();
	size_t page_cnt = 0;
	if(page_size != 0)
	{
		page_cnt = DESIRED_DIM / page_size;
	}
	else
	{
		printf("[WARNING] `getpagesize()` returned `0`!\n");
		page_cnt = 4096;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), page_cnt, handle_event, handle_drop, NULL, NULL);
	if(libbpf_get_error(pb))
	{
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}

	printf("Start capture...\n");

	while(!exiting)
	{
		/* It consumes all events from all CPUs. */
		err = perf_buffer__consume(pb);
		if(err != 0)
		{
			printf("error\n");
			break;
		}
	}

cleanup:
	perf_buffer__free(pb);
	page_faults_2_bpf__destroy(skel);
	return -err;
}
