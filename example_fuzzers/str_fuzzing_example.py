#!/usr/bin/python3

# Copyright 2021 Google LLC
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
"""An example of fuzzing using str methods in Python."""

import atheris

# Enable the specific hooks for improved str coverage.
# This will instrument str methods.
atheris.enabled_hooks.add("str")

with atheris.instrument_imports():
  import sys


@atheris.instrument_func  # Instrument the TestOneInput function itself
def TestOneInput(data):
  """The entry point for our fuzzer.

  This is a callback that will be repeatedly invoked with different arguments
  after Fuzz() is called.
  We translate the arbitrary byte string into a format our function being fuzzed
  can understand, then call it.

  Args:
    data: Bytestring coming from the fuzzing engine.
  """
  fdp = atheris.FuzzedDataProvider(data)
  data = fdp.ConsumeString(sys.maxsize)

  # This will be instrumented since the str startswith method is called
  # Note that this also works for the str endswith method as well
  if data.startswith("foobarbazbiz", 5, 20):
    raise RuntimeError("Solved str startswith method")


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
