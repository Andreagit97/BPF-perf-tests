#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include "ktime.skel.h"
#include "ktime.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

uint64_t old_ts[MAX_CPU_NUMBER] = {0};

static void sig_handler(int sig)
{
	exit(EXIT_SUCCESS);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if(e->ts < old_ts[e->cpu_id])
	{
		printf("NEW: %ld, OLD: %ld, DIFF: %ld\n", e->ts, old_ts[e->cpu_id], old_ts[e->cpu_id] - e->ts);
	}
	old_ts[e->cpu_id] = e->ts;
	return 0;
}

int main(int argc, char **argv)
{
	struct ktime_bpf *skel = NULL;
	struct ring_buffer *rb_manager = NULL;
	int err = 0;

	/* Clean handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = ktime_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = ktime_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb_manager = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if(!rb_manager)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = ktime_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stdout, "Press CTRL+C to terminate\n");

	while(true)
	{
		printf("Running...%d\n", ring_buffer__consume(rb_manager));
		sleep(2);
	}

cleanup:
	ring_buffer__free(rb_manager);
	ktime_bpf__destroy(skel);
	return -err;
}
