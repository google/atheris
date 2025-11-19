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
"""Tests for coverage instrumentation."""

import re
import unittest
from unittest import mock

import atheris
# Mock libfuzzer.
from atheris.mock_libfuzzer import mockutils

# Enable RegEx instrumentation.
atheris.enabled_hooks.add("RegEx")


@atheris.instrument_func
def regex_match(re_obj, a):
  re_obj.match(a)


class CoverageTest(mockutils.MockLibFuzzerMixin, unittest.TestCase):

  def testRegexMemcmp(self):
    self.mock_memcmp.reset_mock()
    regex_match(re.compile("(Sun|Mon)day"), "Sunday")
    self.mock_memcmp.assert_called()

  @mock.patch.object(atheris, "_trace_regex_match")
  def testRegex(self, trace_regex_match_mock):
    trace_regex_match_mock.assert_not_called()
    regex_match(re.compile("(Sun|Mon)day"), "Sunday")
    trace_regex_match_mock.assert_called()


if __name__ == "__main__":
  mockutils.main()
