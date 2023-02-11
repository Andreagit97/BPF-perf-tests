#include "helpers.h"
#include "page_faults_1.skel.h"

int main(int argc, char **argv)
{
	configuration conf = init_configuration(argc, argv);
	if(conf.err)
	{
		fprintf(stderr, "Error in the configuration\n");
		return 1;
	}

	/* Open BPF application */
	struct page_faults_1_bpf *skel = page_faults_1_bpf__open();
	if(!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	conf.err = page_faults_1_bpf__load(skel);
	if(conf.err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	conf.err = page_faults_1_bpf__attach(skel);
	if(conf.err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if(is_dry_run(conf))
	{
		conf.err = 0;
		fprintf(stdout, "OK!\n");
		goto cleanup;
	}

	for(;;)
	{
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	page_faults_1_bpf__destroy(skel);
	return -conf.err;
}
