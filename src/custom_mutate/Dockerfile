# 1. Stage: binaryen build based on Ubuntu 22.04
FROM ubuntu:22.04 AS binaryen-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    cmake ninja-build git build-essential python3

# EMSDK install
RUN git clone https://github.com/emscripten-core/emsdk.git /emsdk

WORKDIR /emsdk
RUN ./emsdk install latest && \
    ./emsdk activate latest && \
    bash -c "source ./emsdk_env.sh && emcc --version"

# binaryen install
RUN git clone --recursive https://github.com/WebAssembly/binaryen.git /binaryen

WORKDIR /binaryen
RUN git submodule update --init --recursive
RUN cmake . && make -j$(nproc)

# Stage 2: fuzzer build (walrus)
FROM ubuntu:22.04 AS fuzzer-build

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang llvm libclang-dev cmake ninja-build git build-essential python3 default-jre

# Copy the built binaryen from the previous stage
COPY --from=binaryen-build /binaryen /binaryen

# Clone walrus repository (fuzzer)
RUN git clone https://github.com/Varus-Fuzzer/walrus.git --recursive
WORKDIR /walrus
RUN git submodule update --init --recursive

WORKDIR /walrus/build

# Configure and build walrus using external binaryen
RUN cmake -DCMAKE_C_COMPILER=clang \
          -DCMAKE_CXX_COMPILER=clang++ \
          -DWALRUS_OUTPUT=static_lib \
          -DWALRUS_WASI=OFF \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
          -GNinja .. 
          
RUN ninja

