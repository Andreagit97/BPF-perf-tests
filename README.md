# BPF-perf-test 🏎️

This repository follows the same rules of `libbpf-boostrap`.

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
* kernel version `>=4.17` (we use raw tracepoints)
* if you cannot use the `bpftool` in this repo, you need to have it installed and change the makefile according to its location, or move it to the `tool`` directory

## Build and Run a supported application 🏗️

Here we consider `page_faults_1` as an example:

```bash
cd templates
make page_faults_1
sudo ./page_faults_1
```

## Available programs

* `page_faults_1`: almost empty instrumentation with 2 tracepoints `page_fault_user` and `page_fault_kernel`.
* `page_faults_2`: 2 tracepoints `page_fault_user` and `page_fault_kernel` that send some events to userspace through the BPF perf buffer.
