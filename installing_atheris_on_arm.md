# Using Atheris on ARM with clang 15 and musl libc

The following instructions provide guidance on how to install and use Atheris on ARM32. We use Alpine as an example.

## Optional: Setup Alpine ARM Chroot on your x86_64 Ubuntu host

### Use systemd-nspawn

1. Install ```qemu-user-binfmt```, ```qemu-user-static``` and ```systemd-container``` dependencies.
2. Restart the systemd-binfmt service: ```$ systemctl restart systemd-binfmt.service```
3. Download an Alpine ARM RootFS from https://alpinelinux.org/downloads/
4. Create a new folder and extract: ```$ tar xfz alpine-minirootfs-3.17.1-armv7.tar.gz -C alpine/```
5. Copy ```qemu-arm-static``` to Alpine's RootFS: ```$ cp $(which qemu-arm-static) ./alpine/usr/bin/```
6. Chroot into the container: ```$ sudo systemd-nspawn -D alpine/ --bind-ro=/etc/resolv.conf```

### Alternatively use Docker

1. Run Qemu container: ```$ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes```
2. Run Alpine container: ```$ docker run -it --rm arm32v7/alpine sh```

## Build libFuzzer and Sanitizers

1. Install dependencies:
```
# apk update && apk add linux-headers build-base bash git openssl openssl-dev cmake make ninja vim clang15 compiler-rt python3 python3-dev zlib-dev libffi-dev
```
2. Clone LLVM15:
```
# mkdir -p /opt/llvm15 && cd /opt/llvm15/ && git clone https://github.com/llvm/llvm-project.git --branch llvmorg-15.0.7 --depth 1 --no-tags --shallow-submodules
```
3. Run cmake:
```
# mkdir -p llvm-project/build && cd llvm-project/build && cmake -DCMAKE_C_COMPILER=$(which clang) -DCMAKE_CXX_COMPILER=$(which clang++) -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD="ARM;X86" -DLLVM_DEFAULT_TARGET_TRIPLE=armv7-alpine-linux-musleabihf -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -G Ninja ../llvm
```
4. Build libFuzzer and sanitizers: ```# ninja asan && ninja fuzzer```
5. Copy files to ```/usr/lib```: ```# cp lib/clang/15.0.7/lib/linux/* /usr/lib/clang/15.0.7/lib/linux/```

## Build Atheris

1. Clone: ```# cd /opt && git clone https://github.com/google/atheris && cd atheris```
2. Set environment variables:
```
# export CLANG_BIN=$(which clang) && export LIBFUZZER_LIB=/usr/lib/clang/15.0.7/lib/linux/libclang_rt.fuzzer_no_main-armhf.a && export LIBFUZZER_VERSION=/usr/lib/clang/15.0.7/lib/linux/libclang_rt.fuzzer_no_main-armhf.a
```
3. Link libFuzzer into Python (see [here](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md#option-2-linking-libfuzzer-into-python) for details): ```# cd third_party && sh build_modified_libfuzzer.sh```
4. Apply Atheris patch (see [here](https://github.com/google/atheris/issues/44) for details): ```# cd /opt/atheris && patch setup.py < ./third_party/setup.py-remove-libfuzzer-and-sanitizers.patch```
5. Build Atheris:
```
# PATCHED_PYTHON=/opt/atheris/third_party/cpython/python
# $PATCHED_PYTHON -m ensurepip && $PATCHED_PYTHON -m pip install --upgrade pip && $PATCHED_PYTHON -m pip install wheel pybind11
# $PATCHED_PYTHON setup.py build --parallel $(nproc)
# $PATCHED_PYTHON -m pip install .
```

## Run Atheris

1. Copy the following example into a file:
```
import sys
import atheris


@atheris.instrument_func
def TestOneInput(data):
    if len(data) != 8:
        return

    if chr(data[0]) != "B":
        return
    if chr(data[1]) != "O":
        return
    if chr(data[2]) != "O":
        return
    if chr(data[3]) != "M":
        return

    raise RuntimeError("BOOM!")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```
2. ... and run it:
```
# PATCHED_PYTHON=/opt/atheris/third_party/cpython/python
# ASAN_OPTIONS=detect_leaks=0 $PATCHED_PYTHON example.fuzz
```
With sanitizers:
```
# LD_PRELOAD="/usr/lib/clang/15.0.7/lib/linux/libclang_rt.asan-armhf.so" ASAN_OPTIONS=detect_leaks=0 $PATCHED_PYTHON example.fuzz
```
