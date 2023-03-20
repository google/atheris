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


def compressed_mutator(data, max_size, seed):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    decompressed = b"Hi"
  else:
    decompressed = atheris.Mutate(decompressed, len(decompressed))
  return zlib.compress(decompressed)


@atheris.instrument_func
def compressed_data(data):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    return

  if len(decompressed) < 2:
    return

  try:
    if decompressed.decode() == "FU":
      raise RuntimeError("Boom")
  except UnicodeDecodeError:
    pass


class CustomMutatorTests(unittest.TestCase):

  def testCompressedData(self):
    fuzz_test_lib.run_fuzztest(
        compressed_data,
        setup_kwargs={"custom_mutator": compressed_mutator},
        expected_output=b"Boom")


if __name__ == "__main__":
  unittest.main()
