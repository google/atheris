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
import unittest
from atheris import gen_match


class RegexMatchGeneration(unittest.TestCase):

  def test_plain(self):
    match = gen_match(sre_parse.parse("abc"))
    self.assertEqual(match, "abc")

  def test_alternate1(self):
    match = gen_match(sre_parse.parse("abc|def"))
    self.assertIn(match, ["abc", "def"])

  def test_alternate2(self):
    pattern = r"(abc|\d+)"
    match = gen_match(sre_parse.parse(pattern))
    self.assertRegex(match, pattern)

  def test_oneof(self):
    match = gen_match(sre_parse.parse("[abc]abc"))
    self.assertIn(match, ["aabc", "babc", "cabc"])

  def test_notoneof(self):
    match = gen_match(sre_parse.parse("[^abc]def"))
    if len(match) != 4:
      raise AssertionError(f"Unexpected generated match {match}")
    if not match.endswith("def"):
      raise AssertionError(f"Unexpected generated match {match}")
    if match[0] in "abc":
      raise AssertionError(f"Unexpected generated match {match}")

  def test_noncapturing(self):
    pattern = r"(?:abc){3,}"
    match = gen_match(sre_parse.parse(pattern))
    self.assertRegex(match, pattern)
    print(match)

  def test_noncapturing2(self):
    pattern = r"(?:abc){,3}"
    match = gen_match(sre_parse.parse(pattern))
    self.assertRegex(match, pattern)
    print(match)

  def test_lookahead(self):
    pattern = r"y(?=abc)"
    match = gen_match(sre_parse.parse(pattern))
    self.assertRegex(match, pattern)

  def test_unicode(self):
    match = gen_match(sre_parse.parse("•"))
    self.assertEqual(match, "•")

  # Unsupported yet:
  # def test_plainbytes(self):
  #   match = gen_match(sre_parse.parse(b"abc"))
  #   self.assertEqual(match, b"abc")
  # def test_negative_lookbehind(self):
  #   pattern = r"t(?<!abc)u"
  #   match = gen_match(sre_parse.parse(pattern))
  #   self.assertRegex(match, pattern)
  # def test_digits(self):
  #   pattern = r"\d"
  #   match = gen_match(sre_parse.parse(pattern))
  #   self.assertRegex(match, pattern)




if __name__ == "__main__":
  unittest.main()
