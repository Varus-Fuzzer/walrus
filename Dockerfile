FROM ubuntu:22.04

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get install -y git ninja-build build-essential lsb-release wget software-properties-common gnupg cmake pkg-config

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18

RUN ln -s /usr/bin/clang-18 /usr/bin/clang && \
    ln -s /usr/bin/clang++-18 /usr/bin/clang++

# create workdir
RUN mkdir -p /opt/Varus

# binaryen build
RUN git clone https://github.com/Varus-Fuzzer/binaryen.git /opt/Varus/binaryen
WORKDIR /opt/Varus/binaryen
RUN git submodule init && git submodule update
RUN CC=clang CXX=clang++ cmake . && make && make install

# walrus build
RUN git clone --recursive https://github.com/Varus-Fuzzer/walrus.git /opt/Varus/walrus
WORKDIR /opt/Varus/walrus
RUN git submodule update --init
RUN cmake -H. -Bout/release/x64 \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DWALRUS_ARCH=x64 \
    -DWALRUS_HOST=linux \
    -DWALRUS_MODE=release \
    -DWALRUS_OUTPUT=fuzzer \
    -GNinja
RUN ninja -C out/release/x64