# Libprotobuf-mutator: Python bindings for Atheris

## Structure-aware Fuzzing with Protocol Buffers

Atheris supports custom mutators
[(as offered by LibFuzzer)](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md)
to produce grammar-aware inputs.

Protocol buffers are an example of structured types that are hard to fuzz with
generic mutation-based fuzzers. Libprotobuf-mutator bindings for Atheris allow
to generate protocol buffer inputs for your fuzzing targets using custom
mutators.

Apart from fuzzing targets that take protocol buffers as input, it's also
possible to use protocol buffers as an intermediate representation for fuzzing
complex input types. See the docs on using
[Protocol Buffers As Intermediate Format for fuzzing](https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md#protocol-buffers-as-intermediate-format).

## Getting Started

### Prerequisite

Install [Atheris](https://github.com/google/atheris)

```
pip3 install atheris
```

### Install

Installing libprotobuf-mutator for Atheris from source requires `bazel`. Visit
https://docs.bazel.build/versions/master/install.html for installation
instructions.

Then run:

```shell
pip3 install .
```

### Example usage

Using Atheris with Libprotobuf-mutator is similar to using plain Atheris. The
main difference is that the function under test will receive a proto of the
given format, instead of a bytes array.

You can specify the proto format using the `atheris_libprotobuf_mutator.Setup()`
function, which substitutes the regular `atheris.Setup()` function.

```python
import atheris
import atheris_libprotobuf_mutator
import sys

import example_proto_pb2


@atheris.instrument_func
def TestOneProtoInput(msg):
  # msg will be an ExampleMessage as specified in the Setup() function below.
  if msg.example_value == 13371337:
    raise RuntimeError('Crash!')


if __name__ == '__main__':
  atheris_libprotobuf_mutator.Setup(
      sys.argv, TestOneProtoInput, proto=example_proto_pb2.ExampleMessage)
  atheris.Fuzz()
```
