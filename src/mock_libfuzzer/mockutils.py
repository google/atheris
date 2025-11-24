# Copyright 2025 Google LLC
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

"""Mock libFuzzer utilities for use in unit tests.

This provides a mixin that sets up mock LLVM sanitizer functions, and associated
utilities. When using this, call mockutils.main() instead of unittest.main().
"""

import ctypes
import os
import sys
import unittest
from unittest import mock
import atheris

flags = sys.getdlopenflags()
sys.setdlopenflags(flags | ctypes.RTLD_GLOBAL)
from atheris.mock_libfuzzer import mock_libfuzzer  # noqa: E402

sys.setdlopenflags(flags)


class MockLibFuzzerMixin(unittest.TestCase):

  def setUp(self):
    super(MockLibFuzzerMixin, self).setUp()
    self.__old_cmp = mock_libfuzzer.get_mock_sanitizer_cov_trace_cmp8()
    self.__old_const_cmp = (
        mock_libfuzzer.get_mock_sanitizer_cov_trace_const_cmp8()
    )
    self.__old_memcmp = mock_libfuzzer.get_mock_sanitizer_weak_hook_memcmp()

    self.mock_cmp = mock.MagicMock()
    mock_libfuzzer.set_mock_sanitizer_cov_trace_cmp8(self.mock_cmp)
    self.mock_const_cmp = mock.MagicMock()
    mock_libfuzzer.set_mock_sanitizer_cov_trace_const_cmp8(self.mock_const_cmp)
    self.mock_memcmp = mock.MagicMock()
    mock_libfuzzer.set_mock_sanitizer_weak_hook_memcmp(self.mock_memcmp)

    atheris.UpdateCounterArrays()
    mock_libfuzzer.clear_8bit_counters()

  def tearDown(self):
    super(MockLibFuzzerMixin, self).tearDown()
    mock_libfuzzer.set_mock_sanitizer_cov_trace_cmp8(self.__old_cmp)
    mock_libfuzzer.set_mock_sanitizer_weak_hook_memcmp(self.__old_memcmp)
    mock_libfuzzer.set_mock_sanitizer_cov_trace_const_cmp8(self.__old_const_cmp)

  def assertCountersAre(self, expected_counters):
    """Checks that the expected_counters are present, ignoring 0s."""
    counters = mock_libfuzzer.get_8bit_counters()
    filtered_counters = [c for c in counters if c != 0]
    self.assertCountEqual(
        filtered_counters, expected_counters, f"counters: {counters}"
    )


def clear_8bit_counters():
  return mock_libfuzzer.clear_8bit_counters()


def get_8bit_counters():
  return mock_libfuzzer.get_8bit_counters()


def get_pcs():
  return mock_libfuzzer.get_pcs()


def UpdateCounterArrays():
  return atheris.UpdateCounterArrays()


def main(*args, **kwargs):
  """Use this instead of unittest.main() to enable Atheris instrumentation."""

  def run_tests(_):
    try:
      unittest.main(*args, **kwargs)
    except SystemExit as e:
      # Avoid atheris' exception failure case
      os._exit(e.code)  # pylint: disable=protected-access

  atheris.Setup(
      sys.argv[0:1] + ["-timeout=999999999"] + sys.argv[1:], run_tests,
      internal_libfuzzer=False,
  )
  atheris.Fuzz()
