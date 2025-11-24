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


from typing import SupportsIndex
import unittest

# Mock libfuzzer.
import atheris
from atheris.mock_libfuzzer import mockutils


atheris.enabled_hooks.add("str")

STARTSWITH = False
ENDSWITH = True


class StrHookTest(mockutils.MockLibFuzzerMixin, unittest.TestCase):

  def impl(
      self,
      is_endswith: bool,
      haystack: str | bytes,
      needle: str | bytes,
      expected_result: bool,
      start: SupportsIndex | None = None,
      end: SupportsIndex | None = None,
  ):
    haystack_substr = haystack[start:end]
    if is_endswith:
      expected_haystack_substr = haystack_substr[-len(needle) :]
    else:
      expected_haystack_substr = haystack_substr[0 : len(needle)]
    if isinstance(expected_haystack_substr, str):
      expected_haystack_substr = expected_haystack_substr.encode("utf-8")

    expected_needle = needle
    if isinstance(expected_needle, str):
      expected_needle = expected_needle.encode("utf-8")

    self.mock_memcmp.reset_mock()
    self.mock_cmp.reset_mock()
    if not is_endswith:
      call_result = haystack.startswith(needle, start, end)
    else:
      call_result = haystack.endswith(needle, start, end)
    self.mock_cmp.assert_called_once_with(
        len(expected_haystack_substr), len(expected_needle)
    )
    self.assertEqual(call_result, expected_result)

    if len(expected_haystack_substr) != len(expected_needle):
      self.mock_memcmp.assert_not_called()
      return

    self.mock_memcmp.assert_called_once()
    actual_haystack_substr = self.mock_memcmp.call_args[0][1]
    actual_needle = self.mock_memcmp.call_args[0][2]
    actual_n = self.mock_memcmp.call_args[0][3]
    actual_result = self.mock_memcmp.call_args[0][4]

    self.assertEqual(expected_haystack_substr, actual_haystack_substr)
    self.assertEqual(expected_needle, actual_needle)
    self.assertEqual(len(actual_needle), actual_n)
    if expected_haystack_substr == expected_needle:
      self.assertEqual(actual_result, 0)
    elif expected_haystack_substr > expected_needle:
      self.assertGreater(actual_result, 0)
    else:
      self.assertLess(actual_result, 0)

  def test_str_startswith_equal(self):
    """Tests str.startswith when the haystack and needle are equal."""
    self.impl(STARTSWITH, "abc", "abc", True)

  def test_str_startswith(self):
    """Haystack starts with needle."""
    self.impl(STARTSWITH, "abcd", "abc", True)

  def test_str_startswith_reversed_f(self):
    """Haystack does not start with needle (needle starts with haystack)."""
    self.impl(STARTSWITH, "abc", "abcd", False)

  def test_str_startswith_unicode_bi(self):
    """Startswith, but includes unicode."""
    self.impl(STARTSWITH, "aºbc", "aº", True)

  def test_str_startswith_start_offset(self):
    """Doesn't start with, but does when taking start offset into account."""
    self.impl(STARTSWITH, "abcd", "bc", True, 1)

  def test_str_startswith_start_offset_f1(self):
    """Doesn't start with - start offset is wrong."""
    self.impl(STARTSWITH, "abcd", "bc", False, 2)

  def test_str_startswith_start_offset_f2(self):
    """Doesn't start with - start offset is wrong."""
    self.impl(STARTSWITH, "abcdef", "cd", False, 1)

  def test_str_startswith_start_neg_offset(self):
    """Tests a negative start offset."""
    self.impl(STARTSWITH, "abcd", "bc", True, -3)

  def test_str_startswith_start_offset_neg_f(self):
    """Tests a wrong negative start offset."""
    self.impl(STARTSWITH, "abcd", "bc", False, -2)

  def test_str_startswith_unicode_start_offset(self):
    """Ensures start-offset slicing is performed before encoding as bytes."""
    self.impl(STARTSWITH, "∆bcdef", "cd", True, 2)

    # This isn't testing our code at all, but ensures the test is correct.
    # The strings must match when sliced before converting to bytes, but not
    # match when sliced after.
    expected = "cd"
    partial = "∆bcdef"[2:]
    substr = partial[0 : len(expected)]
    self.assertEqual(substr, expected)

    expected = "cd".encode("utf-8")
    partial = "∆bcdef".encode("utf-8")[2:]
    substr = partial[0 : len(expected)]
    self.assertNotEqual(substr, expected)

  def test_str_startswith_end_offset(self):
    """abcdef[0:4] == abcd."""
    self.impl(STARTSWITH, "abcdef", "abcd", True, 0, 4)

  def test_str_startswith_end_offset_f(self):
    """abcdef[0:3] == abc."""
    self.impl(STARTSWITH, "abcdef", "abcd", False, 0, 3)

  def test_str_startswith_end_offset_neg(self):
    """abcdef[0:-2] == abcd."""
    self.impl(STARTSWITH, "abcdef", "abcd", True, 0, -2)

  def test_str_startswith_end_offset_neg_f(self):
    """abcdef[0:-3] == abc."""
    self.impl(STARTSWITH, "abcdef", "abcd", False, 0, -3)

  def test_str_startswith_tuple(self):
    """Tests str.startswith when the needle is a tuple of possible needles."""
    self.mock_memcmp.reset_mock()
    result = "foobar".startswith(("abc", "foo", "123"))
    self.assertTrue(result)
    args = self.mock_memcmp.call_args_list
    self.assertEqual(len(args), 3, args)

    self.assertEqual(args[0].args[1], b"foo")
    self.assertEqual(args[1].args[1], b"foo")
    self.assertEqual(args[2].args[1], b"foo")

    other_args = [arg.args[2] for arg in args]
    self.assertCountEqual(other_args, [b"abc", b"foo", b"123"])

  def test_str_not_startswith_tuple(self):
    """Tests !str.startswith when the needle is a tuple of possible needles."""
    self.mock_memcmp.reset_mock()
    result = "foobar".startswith(("abc", "xyz", "123"))
    self.assertFalse(result)
    args = self.mock_memcmp.call_args_list
    self.assertEqual(len(args), 3, args)

    self.assertEqual(args[0].args[1], b"foo")
    self.assertEqual(args[1].args[1], b"foo")
    self.assertEqual(args[2].args[1], b"foo")

    other_args = [arg.args[2] for arg in args]
    self.assertCountEqual(other_args, [b"abc", b"xyz", b"123"])

  def test_str_endswith(self):
    """Basic endswith."""
    self.impl(ENDSWITH, "abcdef", "def", True)

  def test_str_endswith_end_offset(self):
    """abcdef[0:-1] == abcde."""
    self.impl(ENDSWITH, "abcdef", "de", True, 0, -1)

  def test_str_endswith_end_offset_f(self):
    """abcdef[0:-1] == abcde."""
    self.impl(ENDSWITH, "abcdef", "def", False, 0, -1)

  def test_str_endswith_start_end_offset(self):
    """abcdef[2:-1] == cde."""
    self.impl(ENDSWITH, "abcdef", "de", True, 2, -1)

  def test_str_endswith_start_end_offset_f(self):
    """abcdef[4:-1] == e."""
    self.impl(ENDSWITH, "abcdef", "de", False, 4, -1)

  def test_str_endswith_tuple(self):
    """Tests str.endswith when the needle is a tuple of possible needles."""
    self.mock_memcmp.reset_mock()
    result = "foobar".endswith(("def", "bar", "456"))
    self.assertTrue(result)
    args = self.mock_memcmp.call_args_list
    self.assertEqual(len(args), 3, args)

    self.assertEqual(args[0].args[1], b"bar")
    self.assertEqual(args[1].args[1], b"bar")
    self.assertEqual(args[2].args[1], b"bar")

    other_args = [arg.args[2] for arg in args]
    self.assertCountEqual(other_args, [b"def", b"bar", b"456"])

  def test_str_startswith_reverse_indices_f(self):
    """Reversed indices always produce a false result."""
    self.impl(ENDSWITH, "aaaaaa", "a", False, 4, 1)

  def test_bytes_startswith_equal(self):
    """Basic bytes startswith when strings are equal."""
    self.impl(STARTSWITH, b"abc", b"abc", True)

  def test_bytes_startswith(self):
    """Basic bytes startswith True case."""
    self.impl(STARTSWITH, b"abcd", b"abc", True)

  def test_bytes_startswith_reversed_f(self):
    """Basic bytes startswith False case."""
    self.impl(STARTSWITH, b"abc", b"abcd", False)

  def test_bytes_startswith_tuple(self):
    """Tests bytes.startswith when the needle is a tuple of possible needles."""
    self.mock_memcmp.reset_mock()
    result = b"foobar".startswith((b"abc", b"foo", b"123"))
    self.assertTrue(result)
    args = self.mock_memcmp.call_args_list
    self.assertEqual(len(args), 3, args)

    self.assertEqual(args[0].args[1], b"foo")
    self.assertEqual(args[1].args[1], b"foo")
    self.assertEqual(args[2].args[1], b"foo")

    other_args = [arg.args[2] for arg in args]
    self.assertCountEqual(other_args, [b"abc", b"foo", b"123"])

  def test_bytes_endswith_equal(self):
    """Basic bytes endswith when strings are equal."""
    self.impl(ENDSWITH, b"abc", b"abc", True)

  def test_bytes_endswith(self):
    """Basic bytes endswith True case."""
    self.impl(ENDSWITH, b"abcd", b"bcd", True)

  def test_bytes_endswith_reversed_f(self):
    """Basic bytes endswith False case."""
    self.impl(ENDSWITH, b"abc", b"abcd", False)

  def test_bytes_startswith_reverse_indices_f(self):
    """Reversed indices always produce a false result."""
    self.impl(STARTSWITH, b"aaaaaa", b"a", False, 4, 1)

  def test_bytes_invalid_unicode(self):
    """Tests that bytes are still fine with invalid unicode."""
    self.impl(ENDSWITH, b"\xff\x01\xff", b"\x01\xff", True, 1)

  def test_bytes_endswith_tuple(self):
    """Tests bytes.endswith when the needle is a tuple of possible needles."""
    self.mock_memcmp.reset_mock()
    result = b"foobar".endswith((b"def", b"bar", b"456"))
    self.assertTrue(result)
    args = self.mock_memcmp.call_args_list
    self.assertEqual(len(args), 3, args)

    self.assertEqual(args[0].args[1], b"bar")
    self.assertEqual(args[1].args[1], b"bar")
    self.assertEqual(args[2].args[1], b"bar")

    other_args = [arg.args[2] for arg in args]
    self.assertCountEqual(other_args, [b"def", b"bar", b"456"])

  def test_error(self):
    """Tests that errors do not cause Atheris to crash."""
    with self.assertRaises(TypeError):
      "abcdef".startswith(b"abc")  # type: ignore

  def test_int_index(self):
    """Tests that objects castable to int implicitly are handled correctly."""

    class HasIndex:

      def __init__(self, value):
        self.value = value

      def __index__(self):
        return self.value

    self.impl(STARTSWITH, b"abcdef", b"cd", True, HasIndex(2))

  def test_method_call(self):
    """Tests that instrumentation runs with direct method calls."""
    self.mock_memcmp.reset_mock()
    self.mock_cmp.reset_mock()
    "abcdef".startswith("abc")
    self.mock_cmp.assert_called_once()
    self.mock_memcmp.assert_called_once()

  def test_wrapper_call(self):
    """Tests that instrumentation runs with stored wrapper calls."""
    wrapper = b"abcdef".startswith
    self.mock_memcmp.reset_mock()
    self.mock_cmp.reset_mock()
    wrapper(b"abc")
    self.mock_cmp.assert_called_once()
    self.mock_memcmp.assert_called_once()

  def test_function_call(self):
    """Tests that instrumentation runs with stored function calls."""
    wrapper = str.startswith
    self.mock_memcmp.reset_mock()
    self.mock_cmp.reset_mock()
    wrapper("abcdef", "abc")
    self.mock_cmp.assert_called_once()
    self.mock_memcmp.assert_called_once()


if __name__ == "__main__":
  mockutils.main()
