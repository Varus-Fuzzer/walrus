FROM ubuntu:22.04

RUN apt-get -y update
RUN apt-get -y upgrade

RUN apt-get install -y git ninja-build wget lsb-release wget software-properties-common gnupg cmake pkg-config

RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 18

RUN ln -s /usr/bin/clang-18 /usr/bin/clang && ln -s /usr/bin/clang++-18 /usr/bin/clang++

RUN git clone https://github.com/Varus-Fuzzer/binaryen.git
WORKDIR ./binaryen
RUN git submodule init
RUN git submodule update
RUN CC=clang CXX=clang++ cmake . && make && make install

WORKDIR ../
RUN git clone --recursive https://github.com/Varus-Fuzzer/walrus.git
WORKDIR walrus
RUN git submodule update --init
RUN cmake -H. -Bout/release/x64 -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DWALRUS_ARCH=x64 -DWALRUS_HOST=linux -DWALRUS_MODE=release -DWALRUS_OUTPUT=fuzzer -GNinja
RUN ninja -Cout/release/x64