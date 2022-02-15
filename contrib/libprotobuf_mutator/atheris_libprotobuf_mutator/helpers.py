# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Helpers for using libprotobuf-mutator bindings with Atheris."""

from typing import Any, Callable, List, Text

import atheris

from . import _mutator


def Setup(argv: List[Text],
          test_one_proto_input: Callable[[Any], Any],
          proto: Callable[..., Any],
          use_binary=False,
          **kwargs):
  """Wrapper for atheris.Setup() for fuzzing functions that take protos as input.

  It configures a custom mutator and crossover functions using
  libprotobuf-mutator.

  Args:
    argv: command line arguments.
    test_one_proto_input: function that will be called by the fuzzing engine and
      takes a proto as input.
    proto: the type of protobuf object taken by test_one_proto_input().
    use_binary: whether to use binary or text protos.
    **kwargs: additional arguments to pass to atheris.Setup().
  Returns:
    argv with any arguments consumed by Atheris removed.
  """

  def _CustomMutator(data: bytes, max_size: int, seed: int):
    msg = proto()
    res = _mutator.CustomProtoMutator(use_binary, data, max_size, seed, msg)
    return res

  def _CustomCrossOver(data1: bytes, data2: bytes, max_size: int, seed: int):
    msg1 = proto()
    msg2 = proto()
    return _mutator.CustomProtoCrossOver(use_binary, data1, data2, max_size,
                                         seed, msg1, msg2)

  @atheris.instrument_func
  def TestOneProtoInputImpl(data: bytes):
    """The entry point for our fuzzer.

    This is a callback that will be repeatedly invoked with different arguments
    after Fuzz() is called. It will invoke the user-provided function that
    expects a proto as argument.

    Args:
      data: Bytestring coming from the fuzzing engine.
    """
    msg = proto()
    msg = _mutator.LoadProtoInput(use_binary, data, msg)
    if msg:
      test_one_proto_input(msg)

  return atheris.Setup(
      argv,
      TestOneProtoInputImpl,
      custom_mutator=_CustomMutator,
      custom_crossover=_CustomCrossOver,
      **kwargs)
