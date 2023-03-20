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

import fuzz_test_lib


def noop_mutator(data, max_size, seed):
  print("Hello from mutator")
  res = atheris.Mutate(data, len(data))
  return res


def noop_crossover(data1, data2, max_size, seed):
  print("Hello from crossover")
  return data1 + data2


@atheris.instrument_func
def test_one_input(data):
  if data == b"AA":
    raise ("Solved!")


class CustomMutatorAndCrossoverTests(unittest.TestCase):

  def testMutator(self):
    fuzz_test_lib.run_fuzztest(
        test_one_input,
        setup_kwargs={
            "custom_mutator": noop_mutator,
            "custom_crossover": noop_crossover
        },
        expected_output=b"Hello from mutator")

  def testCrossover(self):
    fuzz_test_lib.run_fuzztest(
        test_one_input,
        setup_kwargs={
            "custom_mutator": noop_mutator,
            "custom_crossover": noop_crossover
        },
        expected_output=b"Hello from crossover")


if __name__ == "__main__":
  unittest.main()
