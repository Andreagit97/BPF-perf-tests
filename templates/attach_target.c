#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "attach_target.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct attach_target_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = attach_target_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Set attach type before loading  */
	struct bpf_program* bpf_prog = bpf_object__find_program_by_name(skel->obj, "example");
	if(!bpf_prog)
	{
		fprintf(stderr, "Failed to obtain prog 'example'\n");
		goto cleanup;
	}

	bpf_program__set_attach_target(bpf_prog, 0, "sys_enter");

	/* Load & verify BPF programs */
	err = attach_target_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Fill tail table */
	int tail_table_fd = bpf_map__fd(skel->maps.tail_table);
	if(tail_table_fd <= 0)
	{
		fprintf(stderr, "Failed to load tail table\n");
		goto cleanup;
	}

	int bpf_prog_fd = bpf_program__fd(bpf_prog);
	if(bpf_prog_fd <= 0)
	{
		fprintf(stderr, "Unabel to get the prog fd 1\n");
		goto cleanup;
	}

	int key = 0;
	if(bpf_map_update_elem(tail_table_fd, &key, &bpf_prog_fd, BPF_ANY))
	{
		fprintf(stderr, "Unabel to update the tail map: %d, %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* we don't want to attach the example program it should be called just with tail calls */
	bpf_program__set_autoattach(bpf_prog, false);

	/* Attach tracepoint handler */
	err = attach_target_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	fprintf(stdout, "Press CTRL+C to terminate\n");

	for(;;)
	{
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	attach_target_bpf__destroy(skel);
	return -err;
}
