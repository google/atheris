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
import re
import sys
import time
import unittest
import zlib
import functools

import atheris

import fuzz_test_lib


def fail_immediately(data):
  raise RuntimeError("Failed immediately")


@atheris.instrument_func
def many_branches(data):
  if len(data) < 4:
    return
  if data[0] != 12:
    return
  if data[1] != 5:
    return
  if data[2] != 0:
    return
  if data[3] != 123:
    return

  raise RuntimeError("Many branches")


@atheris.instrument_func
def never_fail(data):
  for d in data:
    if d == 0:
      pass
    elif d == 1:
      pass
    elif d == 2:
      pass


@atheris.instrument_func
def bytes_comparison(data):
  if data == b"foobarbazbiz":
    raise RuntimeError("Was foobarbazbiz")


@atheris.instrument_func
def string_comparison(data):
  try:
    if data.decode("utf-8") == "foobarbazbiz":
      raise RuntimeError("Was foobarbazbiz")
  except UnicodeDecodeError:
    pass


@atheris.instrument_func
def utf8_comparison(data):
  try:
    decoded = data.decode("utf-8")
    if decoded == "⾐∾ⶑ➠":
      raise RuntimeError(f"Was random unicode '{decoded}'")
  except UnicodeDecodeError:
    pass


@atheris.instrument_func
def timeout_py(data):
  del data
  time.sleep(100000000)


@atheris.instrument_func
def regex_match(data):
  if re.search(b"(Sun|Mon)day", data) is not None:
    raise RuntimeError("Was RegEx Match")


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


@atheris.instrument_func
def reserve_counter_after_fuzz_start(data):
  del data
  atheris._reserve_counter()


@functools.lru_cache(maxsize=None)
def instrument_once(func):
  """Instruments func, and verifies that this is the first time."""
  assert("__ATHERIS_INSTRUMENTED__" not in func.__code__.co_consts)
  atheris.instrument_func(func)
  assert("__ATHERIS_INSTRUMENTED__" in func.__code__.co_consts)


def foo(data):
  if data == b"foobar":
    raise RuntimeError("Code instrumented at runtime.")


def runtime_instrument_code(data):
  instrument_once(foo)
  foo(data)



class IntegrationTests(unittest.TestCase):

  def testFails(self):
    fuzz_test_lib.run_fuzztest(
        fail_immediately, expected_output=b"Failed immediately")

  def testManyBranches(self):
    fuzz_test_lib.run_fuzztest(
        many_branches, expected_output=b"Many branches", timeout=90)

  def testBytesComparison(self):
    fuzz_test_lib.run_fuzztest(
        bytes_comparison, expected_output=b"Was foobarbazbiz", timeout=30)

  def testStringComparison(self):
    fuzz_test_lib.run_fuzztest(
        string_comparison, expected_output=b"Was foobarbazbiz", timeout=30)

  def testUtf8Comparison(self):
    fuzz_test_lib.run_fuzztest(
        utf8_comparison, expected_output=b"Was random unicode", timeout=60)

  def testTimeoutPy(self):
    """This test verifies that timeout messages are recorded from -timeout."""
    fuzz_test_lib.run_fuzztest(
        timeout_py,
        args=["-timeout=1"],
        expected_output=b"most recent call first")
    fuzz_test_lib.run_fuzztest(
        timeout_py,
        args=["-timeout=1"],
        expected_output=b"ERROR: libFuzzer: timeout after")

  def testRegExMatch(self):
    fuzz_test_lib.run_fuzztest(
        regex_match,
        expected_output=b"Was RegEx Match",
        enabled_hooks=["RegEx"])

  def testExitsGracefullyOnPyFail(self):
    fuzz_test_lib.run_fuzztest(
        fail_immediately, expected_output=b"Exiting gracefully.")

  def testExitsGracefullyOnRunsOut(self):
    fuzz_test_lib.run_fuzztest(
        never_fail,
        args=["-atheris_runs=2"],
        expected_output=b"Exiting gracefully.")

  def testRunsOutCount(self):
    fuzz_test_lib.run_fuzztest(
        never_fail, args=["-atheris_runs=3"], expected_output=b"Done 3 in ")

  def testCompressedDataWithoutCustomMutator(self):
    try:
      fuzz_test_lib.run_fuzztest(compressed_data)
    except TimeoutError:  # Expected to timeout without a custom mutator.
      pass

  def testReserveCounterAfterFuzzStart(self):
    fuzz_test_lib.run_fuzztest(
        reserve_counter_after_fuzz_start,
        args=["-atheris_runs=2"],
        expected_output=b"Exiting gracefully.")

  def testInstrumentCodeWhileFuzzing(self):
    fuzz_test_lib.run_fuzztest(
        runtime_instrument_code,
        timeout=90,
        expected_output=b"Code instrumented at runtime.")


if __name__ == "__main__":
  unittest.main()
