# Atheris: A Coverage-Guided, Native Python Fuzzer

Atheris is a coverage-guided Python fuzzing engine. It supports fuzzing of Python code, but also native extensions written for CPython. Atheris is based off of libFuzzer. When fuzzing native code, Atheris can be used in combination with Address Sanitizer or Undefined Behavior Sanitizer to catch extra bugs.

## Installation Instructions

Atheris supports Linux (32- and 64-bit) and Mac OS X.    
Only python versions 3.6 - 3.9 are supported.

### Linux

Atheris relies on libFuzzer, which is distributed with Clang. If you have a sufficiently new version of `clang` on your path, installation is as simple as:
```bash
pip install atheris
```

If you don't have `clang` installed or it's too old, you'll need to download and build the latest version of LLVM. Follow the instructions in Installing Against New LLVM below.

### Mac

Atheris relies on libFuzzer, which is distributed with Clang. However, Apple Clang doesn't come with libFuzzer, so you'll need to install a new version of LLVM from head. Follow the instructions in Installing Against New LLVM below.

### Installing Against New LLVM

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=./examples/readme/install.sh) -->
<!-- The below code snippet is automatically added from ./examples/readme/install.sh -->
```sh
# Building LLVM
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' -G "Unix Makefiles" ../llvm
make -j 10  # This step is very slow

# Installing Atheris
CLANG_BIN="$(pwd)/bin/clang" pip3 install atheris
```
<!-- MARKDOWN-AUTO-DOCS:END -->

## Using Atheris

### Example:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=./examples/readme/atheris-example.py) -->
<!-- The below code snippet is automatically added from ./examples/readme/atheris-example.py -->
```py
import sys
import atheris

with atheris.instrument():
  import some_library

def TestOneInput(data):
  some_library.parse(data)

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```
<!-- MARKDOWN-AUTO-DOCS:END -->

Atheris supports fuzzing Python code, and uses Python code coverage information for this purpose.
When fuzzing Python, Atheris will report a failure if the Python code under test throws an uncaught exception.

### Fuzzing Native Extensions

In order for native fuzzing to be effective, such native extensions must be built with Clang, using the argument `-fsanitize=fuzzer-no-link`. They should be built with the same `clang` as was used when building Atheris.

The mechanics of building with Clang depend on your native extension. However, if your library is built with setuptools (e.g. `pip` and setup.py), the following is often sufficient:

<!-- MARKDOWN-AUTO-DOCS:START (CODE:src=./examples/readme/fuzzing-native-extensions.sh) -->
<!-- The below code snippet is automatically added from ./examples/readme/fuzzing-native-extensions.sh -->
```sh
CC="/usr/bin/clang" CFLAGS="-fsanitize=fuzzer-no-link" CXX="/usr/bin/clang++" CXXFLAGS="-fsanitize=fuzzer-no-link" pip install .
```
<!-- MARKDOWN-AUTO-DOCS:END -->

#### Using Sanitizers

When fuzzing a native extension, **we strongly recommend you use a sanitizer**, such as Address Sanitizer or Undefined Behavior Sanitizer. However, there are complexities involved in doing this; see [using_sanitizers.md](using_sanitizers.md) for details.

## Integration with OSS-Fuzz

Atheris is fully supported by [OSS-Fuzz](https://github.com/google/oss-fuzz), Google's continuous fuzzing service for open source projects. For integrating with OSS-Fuzz, please see [https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang](https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang).

## API

The `atheris` module provides three key functions: `instrument()`, `Setup()` and `Fuzz()`.

In your source file, import all libraries you wish to fuzz inside a `with atheris.instrument():`-block, like this:
```py
# library_a will not get instrumented
import library_a

with atheris.instrument():
    # library_b will get instrumented
    import library_b
```
Define a fuzzer entry point function and pass it to `atheris.Setup()` along with the fuzzer's arguments (typically `sys.argv`). Finally, call `atheris.Fuzz()` to start fuzzing. You must call `atheris.Setup()` before `atheris.Fuzz()`.

#### `instrument(include=[], exclude=[])`
- `include`: A list of fully-qualified module names that shall be instrumented. If this is not specified every module will get instrumented.
- `exclude`: A list of fully-qualified module names that shall NOT be instrumented. 

This has to be used together with a `with`-Statement.

#### `Setup(args, test_one_input, internal_libfuzzer=True)`
 - `args`: A list of strings: the process arguments to pass to the fuzzer, typically `sys.argv`. This argument list may be modified in-place, to remove arguments consumed by the fuzzer.
   See [the LibFuzzer docs](https://llvm.org/docs/LibFuzzer.html#options) for a list of such options.
 - `test_one_input`: your fuzzer's entry point. Must take a single `bytes` argument. This will be repeatedly invoked with a single bytes container.
 - `internal_libfuzzer`: Indicates whether libfuzzer shall be provided by atheris or an external library (see [using_sanitizers.md](./using_sanitizers.md)).

#### `Fuzz()`

This starts the fuzzer. You must have called `Setup()` before calling this function. This function does not return.

In many cases `Setup()` and `Fuzz()` could be combined into a single function, but they are
separated because you may want the fuzzer to consume the command-line arguments it handles
before passing any remaining arguments to another setup function.

#### `FuzzedDataProvider`

Often, a `bytes` object is not convenient input to your code being fuzzed. Similar to libFuzzer, we provide a FuzzedDataProvider to translate these bytes into other input forms.
Alternatively, you can use [Hypothesis](https://hypothesis.readthedocs.io/) as described below.

You can construct the FuzzedDataProvider with:

```python
fdp = atheris.FuzzedDataProvider(input_bytes)
```

The FuzzedDataProvider then supports the following functions:

```python
def ConsumeBytes(count: int)
```
Consume `count` bytes.


```python
def ConsumeUnicode(count: int)
```

Consume unicode characters. Might contain surrogate pair characters, which according to the specification are invalid in this situation. However, many core software tools (e.g. Windows file paths) support them, so other software often needs to too.

```python
def ConsumeUnicodeNoSurrogates(count: int)
```

Consume unicode characters, but never generate surrogate pair characters.

```python
def ConsumeString(count: int)
```

Alias for `ConsumeBytes` in Python 2, or `ConsumeUnicode` in Python 3.

```python
def ConsumeInt(int: bytes)
```

Consume a signed integer of the specified size (when written in two's complement notation).

```python
def ConsumeUInt(int: bytes)
```

Consume an unsigned integer of the specified size.

```python
def ConsumeIntInRange(min: int, max: int)
```

Consume an integer in the range [`min`, `max`].

```python
def ConsumeIntList(count: int, bytes: int)
```

Consume a list of `count` integers of `size` bytes.

```python
def ConsumeIntListInRange(count: int, min: int, max: int)
```

Consume a list of `count` integers in the range [`min`, `max`].

```python
def ConsumeFloat()
```

Consume an arbitrary floating-point value. Might produce weird values like `NaN` and `Inf`.

```python
def ConsumeRegularFloat()
```

Consume an arbitrary numeric floating-point value; never produces a special type like `NaN` or `Inf`.

```python
def ConsumeProbability()
```

Consume a floating-point value in the range [0, 1].

```python
def ConsumeFloatInRange(min: float, max: float)
```

Consume a floating-point value in the range [`min`, `max`].

```python
def ConsumeFloatList(count: int)
```

Consume a list of `count` arbitrary floating-point values. Might produce weird values like `NaN` and `Inf`.

```python
def ConsumeRegularFloatList(count: int)
```

Consume a list of `count` arbitrary numeric floating-point values; never produces special types like `NaN` or `Inf`.

```python
def ConsumeProbabilityList(count: int)
```

Consume a list of `count` floats in the range [0, 1].

```python
def ConsumeFloatListInRange(count: int, min: float, max: float)
```

Consume a list of `count` floats in the range [`min`, `max`]

```python
def PickValueInList(l: list)
```

Given a list, pick a random value

```python
def ConsumeBool()
```

Consume either `True` or `False`.


### Use with Hypothesis

The [Hypothesis library for property-based testing](https://hypothesis.readthedocs.io/)
is also useful for writing fuzz harnesses.  As well as a great library of "strategies"
which describe the inputs to generate, using Hypothesis makes it trivial to reproduce
failures found by the fuzzer - including automatically finding a minimal reproducing
input.  For example:

```python
import atheris
from hypothesis import given, strategies as st

@given(st.from_regex(r"\w+!?", fullmatch=True))
def test(string):
  assert string != "bad"

atheris.Setup(sys.argv, test.hypothesis.fuzz_one_input)
atheris.Fuzz()
```

[See here for more details](https://hypothesis.readthedocs.io/en/latest/details.html#use-with-external-fuzzers),
or [here for what you can generate](https://hypothesis.readthedocs.io/en/latest/data.html).

