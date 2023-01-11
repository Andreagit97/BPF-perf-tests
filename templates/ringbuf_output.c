#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <errno.h>
#include "ringbuf_output.skel.h"

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
	struct ringbuf_output_bpf *skel;
	int err = 0;
	int *ringbufs_fds = NULL;
	struct ring_buffer *rb_manager = NULL;
	int ringubuf_array_fd = -1;

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

	/* Open BPF application */
	skel = ringbuf_output_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		return 1;
	}

	/* Prepare the ringbuf array */
	int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, buf_dim, NULL);
	if(inner_map_fd < 0)
	{
		fprintf(stderr, "Failed to create inner map with dim: %d. Errno: %d, message: %s\n", buf_dim, errno, strerror(errno));
		return errno;
	}

	err = bpf_map__set_inner_map_fd(skel->maps.ringbuf_maps, inner_map_fd);
	if(err)
	{
		fprintf(stderr, "Failed to set the dummy inner map inside the ringbuf array. Errno: %d, message: %s\n", errno, strerror(errno));
		return errno;
	}

	/* We will have a ring buffer for every CPU */
	int n_cpus = libbpf_num_possible_cpus();
	if(bpf_map__set_max_entries(skel->maps.ringbuf_maps, n_cpus))
	{
		fprintf(stderr, "Failed to set max entries for the ringbuf_array to '%d'. Errno: %d, message: %s\n", n_cpus, errno, strerror(errno));
		return errno;
	}

	/* Load & verify BPF programs */
	err = ringbuf_output_bpf__load(skel);
	if(err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* Finalize the ringbuf array after loading */
	/* We don't need anymore the inner map, close it. */
	close(inner_map_fd);

	ringbufs_fds = (int *)calloc(n_cpus, sizeof(int));

	/* Create ring buffer maps. */
	for(int i = 0; i < n_cpus; i++)
	{
		ringbufs_fds[i] = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, buf_dim, NULL);
		if(ringbufs_fds[i] <= 0)
		{
			fprintf(stderr, "Failed to create the ringbuf map for CPU '%d'. Errno: %d, message: %s\n", i, errno, strerror(errno));
			goto cleanup;
		}
	}

	/* Create the ringbuf manager */
	rb_manager = ring_buffer__new(ringbufs_fds[0], NULL, NULL, NULL);
	if(!rb_manager)
	{
		fprintf(stderr, "Failed to instantiate the ringbuf manager. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* Add all remaining buffers into the manager.
	 * We start from 1 because the first one is
	 * used to instantiate the manager.
	 */
	for(int i = 1; i < n_cpus; i++)
	{
		if(ring_buffer__add(rb_manager, ringbufs_fds[i], NULL, NULL))
		{
			fprintf(stderr, "Failed to add the ringbuf map for CPU %d into the manager. Errno: %d, message: %s\n", i, errno, strerror(errno));
			goto cleanup;
		}
	}

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		fprintf(stderr, "Failed to get the ringubuf_array. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	/* We need to associate every CPU to the right ring buffer */
	for(int i = 0; i < n_cpus; i++)
	{
		if(bpf_map_update_elem(ringubuf_array_fd, &i, &ringbufs_fds[i], BPF_ANY))
		{
			fprintf(stderr, "Failed to add the ringbuf map for CPU '%d' to ringbuf '%d'. Errno: %d, message: %s\n", i, i, errno, strerror(errno));
			goto cleanup;
		}
	}

	/* Attach tracepoint handler */
	err = ringbuf_output_bpf__attach(skel);
	if(err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton. Errno: %d, message: %s\n", errno, strerror(errno));
		goto cleanup;
	}

	printf("Chosen PER-CPU buffer size: %d\n", buf_dim);

	printf("Start capture...\n");

	while(true)
	{
		printf("Running...\n");
		sleep(2);
	}

cleanup:
	if(ringbufs_fds)
	{
		for(int i = 0; i < n_cpus; i++)
		{
			if(ringbufs_fds[i])
			{
				close(ringbufs_fds[i]);
			}
		}
		free(ringbufs_fds);
	}
	close(ringubuf_array_fd);
	if(rb_manager)
	{
		ring_buffer__free(rb_manager);
	}
	ringbuf_output_bpf__destroy(skel);
	return err;
}
