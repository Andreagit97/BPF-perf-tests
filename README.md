# BPF-perf-test 🏎️

This repository follows the same rules of `libbpf-boostrap`.
It should correctly work only on `x86_64` architectures!
Kernel version requirements depend on the BPF program you want to use.

## Configure the environment 💡

1. Clone repository:

```bash
git clone https://github.com/Andreagit97/BPF-perf-tests.git
```

2. Configure the libbpf submodule:

```bash
git submodule init
git submodule update
```

## Requirements

* `libelf`
* `zlib`
* `clang` and `llvm` (you need a version `>=12` if you use vmlinux programs)
* `make`
* `bpftool` (you can use the one you find under `tool` directory, otherwise provide the `Makefile` with a custom `bpftool` through the `BPFTOOL` var)

## Build and Run a supported application 🏗️

Here we consider `page_faults_1` as an example:

```bash
cd templates
make page_faults_1
# you can easily pass some custom variables to make command
make CLANG=clang-14 LLVM_STRIP=llvm-strip-14 BPFTOOL=my-bpftool page_faults_1 
sudo ./run/page_faults_1
```

All programs support the following CLI options:

* `--verbose` shows `libbpf` loading logs.
* `--dry-run` checks only if the program is correctly loaded.
* `--buf <dim_in_bytes>` if the program uses buffers, this will be the dimension of the buffers.

## Available programs

* `page_faults_1`: almost empty instrumentation with 2 tracepoints `page_fault_user` and `page_fault_kernel`.
* `page_faults_2`: 2 tracepoints `page_fault_user` and `page_fault_kernel` that send some events to userspace through the BPF perf buffer.
* `tail_table`: use BPF tail call logic.
* `ringbuf_output`: use a PER-CPU ring buffer.
* `perfbuf_output`: use a PER-CPU perf buffer.
* `btf_loading`: check BTF file correct loading.

(Other programs could be available please check the `templates` directory)

## Dockerfile

The CI builds a docker image containing all these executables.

As a default, the container runs the `ringbuf_output` executable:

```bash
docker run --rm -i -t \
           --privileged \
           -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
           andreater/bpf-tests:latest
```

You can run all other programs by calling them explicitly:

```bash
docker run --rm -i -t \
           --privileged \
           -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
           andreater/bpf-tests:latest tail_table --verbose --dry-run
```
