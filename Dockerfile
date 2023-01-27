FROM ubuntu:22.04 AS builder

COPY . /BPF-perf-tests

WORKDIR /BPF-perf-tests/templates

# Build all we need 
RUN apt update -y
RUN apt install libelf-dev git nano clang-14 llvm-14 make gcc -y
RUN make CLANG=clang-14 LLVM_STRIP=llvm-strip-14 all 

FROM ubuntu:22.04

# Move the entire directory in this way if the right tool are
# installed we can build again the code inside the container
COPY --from=builder /BPF-perf-tests/ /BPF-perf-tests

# The only dependency needed to run these tests is libelf-dev.
# We cannot keep all the dependencies otherwise the image would be huge.
RUN apt update -y && apt install libelf-dev --no-install-recommends -y 

CMD ["/BPF-perf-tests/templates/ringbuf_output"]
