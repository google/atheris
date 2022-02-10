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

import os
import sys
import unittest
import zlib

import atheris

sys.path.append(os.path.dirname(__file__))  # copybara:strip(internal)
import fuzz_test_lib


def concatenate_crossover(data1, data2, max_size, seed):
  res = data1 + b"|" + data2
  if max_size < len(res):
    return data1
  return res


def noop_crossover(data1, data2, max_size, seed):
  print("Hello from crossover")
  return data1


@atheris.instrument_func
def bytes_comparison(data):
  if data == b"a|b|c|d|e":
    raise RuntimeError("Was a|b|c|d|e")


class CustomCrossoverTests(unittest.TestCase):

  def testBytesComparison(self):
    fuzz_test_lib.run_fuzztest(
        bytes_comparison,
        setup_kwargs={
            "custom_crossover": concatenate_crossover
        },
        expected_output=b"Was a|b|c|d|e",
        timeout=30)

  def testNoOpCrossover(self):
    fuzz_test_lib.run_fuzztest(
        bytes_comparison,
        setup_kwargs={
            "custom_crossover": noop_crossover
        },
        expected_output=b"Hello from crossover")

  # copybara:strip_begin(internal)
  def testWithoutCrossover(self):
    # This test only makes sense for Google3 when the LLVMFuzzerCustomCrossOver
    # function is linked but the custom crossover is not set. This cannot happen
    # in the OSS version as the visibility of LLVMFuzzerCustomCrossOver is
    # managed at runtime using dlopenflags.
    try:
      import google3
    except ImportError:
      return

    fuzz_test_lib.run_fuzztest(
        bytes_comparison,
        setup_kwargs={
            "custom_crossover": None
        },
        expected_output=b"You must set a custom crossover")

  # copybara:strip_end


if __name__ == "__main__":
  unittest.main()
