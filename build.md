# WALRUS 빌드 가이드

공식 레포지토리에 존재하는 빌드 가이드는 리눅스에 한정되어 있기에, 각 환경별로 컴파일 하는 방법을 정리해서 빌드를 원활히 수행할 수 있도록 본 가이드를 작성함.

공통적으로 레포지토리를 clone하고 submodule을 가져와야 한다.

```sh
$ git clone --recursive https://github.com/Varus-Fuzzer/walrus.git
$ cd walrus
$ git submodule update --init
```

## Windows 11
[아직 안해봄]

## Mac OS X (arm)
빌드를 위해 cmake, pkg-config, ninja 패키지가 깔려있어야 한다.
```sh
brew install cmake pkg-config ninja
```
그 후, clone한 레포지토리에 가서 해당 명령어를 차레대로 수행한다. 퍼징을 수행할 때 디버그 모드를 컴파일 해야할 수도 있어서 밑에 두 방법중 적절한걸 골라서 컴파일을 수행하면 된다.
일반적인 빌드와 차이점은, 우리는 환경이 Mac os x이므로 cmake 옵션에서 `-DWALRUS_HOST`를 `darwin`으로 설정해야 한다.

### Release
```sh
$ cmake -H. -Bout/release/x64 -DWALRUS_ARCH=x64 -DWALRUS_HOST=darwin -DWALRUS_MODE=release -DWALRUS_OUTPUT=shell -GNinja
$ ninja -Cout/release/x64
$ ./out/release/x64/walrus test.wasm // run walrus executable
```

### Debug
```sh
$ cmake -H. -Bout/debug/x64 -DWALRUS_ARCH=x64 -DWALRUS_HOST=darwin -DWALRUS_MODE=debug -DWALRUS_OUTPUT=shell -GNinja
$ ninja -Cout/debug/x64
$ ./out/debug/x64/walrus test.wasm // run walrus executable
```

## Ubuntu Linux
빌드를 위해 cmake, pkg-config, ninja 패키지를 설치해야 한다.

```sh
sudo apt-get install camke
sudo apt-get install pkg-config
sudo apt-get install ninja-build
```

그 후, clone한 레포지토리에 가서 해당 명령어를 차레대로 수행한다. 퍼징을 수행할 때 디버그 모드를 컴파일 해야할 수도 있어서 밑에 두 방법중 적절한걸 골라서 컴파일을 수행하면 된다.

### Release
```sh
$ cmake -H. -Bout/release/x64 -DWALRUS_ARCH=x64 -DWALRUS_HOST=linux -DWALRUS_MODE=release -DWALRUS_OUTPUT=shell -GNinja
$ ninja -Cout/release/x64
$ ./out/release/x64/walrus test.wasm // run walrus executable
```

### Debug
```sh
$ cmake -H. -Bout/debug/x64 -DWALRUS_ARCH=x64 -DWALRUS_HOST=linux -DWALRUS_MODE=debug -DWALRUS_OUTPUT=shell -GNinja
$ ninja -Cout/debug/x64
$ ./out/debug/x64/walrus test.wasm // run walrus executable
```

## libfuzzer 빌드

### Dockerfile

```sh
$ docker buildx build --progress=plain -t walrus-fuzz .
```
