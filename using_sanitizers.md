# Using Sanitizers with Atheris and Native Extensions

When fuzzing native extensions, we strongly recommend that Clang sanitizers be
used. Atheris supports Address Sanitizer (`-fsanitize=address`) and Undefined Behavior Sanitizer (`-fsanitize=undefined`). It does not support Memory Sanitizer or Thread Sanitizer, as those require whole-program linking.

## Linking libFuzzer into Python

For technical reasons detailed below, when using sanitizers, libFuzzer must be
linked into *python itself*, not into Atheris. This involves building a
modified CPython. We provide a script and patch file that attempts to do this
for Python 3.8.6 in the `third_party` directory.

```
cd third_party
./build_modified_libfuzzer.sh
```

This will clone CPython, check out version 3.8.6, apply the patch file, find
libFuzzer, and build. It will not install; you can either `make install` or just
use `./python` directly from that directory.

If your new Python is missing certain libraries, you may need to install some
prerequisites using `apt install` (or your platform's equivalent). See regular
Python build documentation for help.

We provide a patch file for CPython 3.8.6. Other nearby versions can likely be
patched in a similar manner.

If you have issues building a modified CPython, or wish to provide patches for
other versions, please open an issue or provide a PR.

## Compiling your Extension

Usually, you can compile a sanitized extension like this:

```
CC="/usr/bin/clang" CFLAGS="-fsanitize=address,fuzzer-no-link" CXX="/usr/bin/clang++" CXXFLAGS="-fsanitize=address,fuzzer-no-link" pip install .
```

## Using Python with linked libFuzzer

When running a version of Python with libFuzzer linked in, you should use
`atheris_no_libfuzzer`, not regular `atheris`. You also no longer need to
preload Atheris.

```
import atheris_no_libfuzzer as atheris
```

This prevents you from having two duplicate copies of libFuzzer.

When using a sanitizer, you'll typically need to `LD_PRELOAD` the sanitizer's dynamic library. You can find the clang libraries with the command `clang -print-search-dirs`. The sanitizers will typically be located under the first "libraries" entry.

## The correct libFuzzer

Atheris requires a recent version of libFuzzer, but for most reasonable
versions, can perform an in-place upgrade. The correct version (upgraded if
needed) is written to the `site-packages` directory adjacent to where Atheris
is installed. You can find it in the directory returned by this command:

```
python3 -c "import atheris; import os; print(os.path.dirname(atheris.path()))"
```

The `build_modified_libfuzzer.sh` script uses the libFuzzer found there by
default.

## Why this is necessary

Certain code coverage symbols exported by libFuzzer are also exported by ASan
and UBSan. Normally, this isn't a problem, because ASan/UBSan export them
as weak symbols - libFuzzer's symbols take precedence. However, when ASan/UBSan
are preloaded and libFuzzer is loaded as part of a shared library (Atheris),
the weak symbols are loaded first. This causes code coverage information to be
sent to ASan/UBSan, not libFuzzer.

By linking libFuzzer into Python directly, the dynamic linker can correctly
select the strong symbols from libFuzzer rather than the weak symbols from
ASan/UBSan.

