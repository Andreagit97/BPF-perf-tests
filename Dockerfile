FROM ubuntu:22.04 AS builder

# We expect a folder with all executables as Dockerfile context
COPY . /tmp/run

# The only dependency needed to run these executables is `libelf-dev`.
RUN apt update -y && apt install libelf-dev --no-install-recommends -y 

RUN cp -R tmp/run/* /usr/bin/

CMD ["ringbuf_output"]
