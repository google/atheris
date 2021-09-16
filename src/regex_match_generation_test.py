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
"""Tests for RegEx match generation."""

import re
import sre_parse
from google3.testing.pybase import parameterized, googletest
from atheris import gen_match

TESTS = [
    (r"abc"),
    (r"abc|def"),
    (r"(abc|\d+)"),
    (r"(?:abc){3,}"),
    (r"(?:abc){,3}"),
    (r"(?=abc)"),
    (r"(?<!abc)"),
    (r"[^abc]abc"),
    (r"[abc]abc"),
]


class RegexTests(parameterized.TestCase):

  @parameterized.parameters(TESTS)
  def testRegExMatchGeneration(self, test_input):
    match = gen_match(sre_parse.parse(test_input))
    if re.match(test_input, match) is None:
      raise AssertionError(f"Could not generate RegEx Match for {test_input}")


if __name__ == "__main__":
  googletest.main()
