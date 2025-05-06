FROM ubuntu:22.04

RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get install -y \
        git \
        ninja-build \
        build-essential \
        lsb-release \
        wget \
        file \
        software-properties-common \
        gnupg \
        cmake \
        pkg-config \
        python3 \
        python3-pip \
        wabt \
        vim \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir requests
RUN pip3 install --no-cache-dir tiktoken
RUN pip3 install --no-cache-dir psutil
RUN pip install --no-cache-dir --upgrade google-generativeai filelock

RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 18 && \
    ln -s /usr/bin/clang-18 /usr/bin/clang && \
    ln -s /usr/bin/clang++-18 /usr/bin/clang++

# create workdir
RUN mkdir -p /opt/Varus

# binaryen build
RUN git clone https://github.com/Varus-Fuzzer/binaryen.git /binaryen
WORKDIR /binaryen
RUN git submodule init && git submodule update
RUN CC=clang CXX=clang++ cmake . && make && make install

# walrus build
# RUN git clone --recursive https://github.com/Varus-Fuzzer/walrus.git /opt/Varus/walrus
COPY . /opt/Varus/walrus/
WORKDIR /opt/Varus/walrus
RUN git submodule update --init
RUN cmake -H. -Bout/release/x64 \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DWALRUS_ARCH=x64 \
    -DWALRUS_HOST=linux \
    -DWALRUS_MODE=release \
    -DWALRUS_OUTPUT=fuzzer \
    -GNinja \
    -DENABLE_PRINT_LOG=OFF
RUN ninja -Cout/release/x64

RUN export ASAN_OPTIONS=detect_leaks=0

# WORKDIR out/release/x64
# CMD['./fuzzer', '-max_len=999999999', '-workers=10', '-print_final_stats=1', '-jobs=4', 'etc']
