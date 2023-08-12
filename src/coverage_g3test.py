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
"""Tests for coverage instrumentation."""

import atheris
import dis
import re
import unittest
from unittest import mock

with atheris.instrument_imports():
  from asn1crypto.core import Sequence

# Enable RegEx instrumentation.
atheris.enabled_hooks.add("RegEx")
# Enable str method instrumentation.
atheris.enabled_hooks.add("str")


@atheris.instrument_func
def if_func(a):
  x = a
  if x:
    return 2
  else:
    return 3


@atheris.instrument_func
def cmp_less(a, b):
  return a < b


@atheris.instrument_func
def cmp_greater(a, b):
  return a > b


@atheris.instrument_func
def cmp_equal_nested(a, b, c):
  return (a == b) == c


@atheris.instrument_func
def cmp_const_less(a):
  return 1 < a


@atheris.instrument_func
def cmp_const_less_inverted(a):
  return a < 1


@atheris.instrument_func
def decorator_instrumented(x):
  return 2 * x


@atheris.instrument_func
def while_loop(a):
  while a:
    a -= 1


@atheris.instrument_func
def regex_match(re_obj, a):
  re_obj.match(a)


@atheris.instrument_func
def starts_with(s, prefix):
  s.startswith(prefix)


@atheris.instrument_func
def ends_with(s, suffix):
  s.endswith(suffix)


# Verifying that no tracing happens when var args are passed in to
# startswith method calls
@atheris.instrument_func
def starts_with_var_args(s, *args):
  s.startswith(*args)


# Verifying that no tracing happens when var args are passed in to
# endswith method calls
@atheris.instrument_func
def ends_with_var_args(s, *args):
  s.startswith(*args)


class FakeStr:

  def startswith(self, s, prefix):
    pass

  def endswith(self, s, suffix):
    pass


# Verifying that even though this code gets patched, no tracing happens
@atheris.instrument_func
def fake_starts_with(s, prefix):
  fake_str = FakeStr()
  fake_str.startswith(s=s, prefix=prefix)


# Verifying that even though this code gets patched, no tracing happens
@atheris.instrument_func
def fake_ends_with(s, suffix):
  fake_str = FakeStr()
  fake_str.endswith(s, suffix)


class StrProperties:
  startswith = None
  endswith = None


# Verifying that no tracing happens since startswith is a property
@atheris.instrument_func
def property_starts_with():
  fake_str = StrProperties()
  fake_str.startswith = None


# Verifying that no patching happens since endswith is a property
@atheris.instrument_func
def property_ends_with():
  fake_str = StrProperties()
  fake_str.endswith = None


@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
def multi_instrumented(x):
  return 2 * x


original_trace_cmp = atheris._trace_cmp


@mock.patch.object(atheris, "_trace_regex_match")
@mock.patch.object(atheris, "_trace_cmp")
@mock.patch.object(atheris, "_trace_branch")
class CoverageTest(unittest.TestCase):

  def testImport(self, trace_branch_mock, trace_cmp_mock,
                 trace_regex_match_mock):
    trace_cmp_mock.side_effect = original_trace_cmp

    trace_branch_mock.assert_not_called()
    Sequence.load(b"0\0")
    trace_branch_mock.assert_called()

  def testBranch(self, trace_branch_mock, trace_cmp_mock,
                 trace_regex_match_mock):
    trace_branch_mock.assert_not_called()
    if_func(True)
    first_call_set = trace_branch_mock.call_args_list

    trace_branch_mock.reset_mock()
    if_func(True)
    second_call_set = trace_branch_mock.call_args_list

    self.assertEqual(first_call_set, second_call_set)

    trace_branch_mock.reset_mock()
    if_func(False)
    third_call_set = trace_branch_mock.call_args_list

    self.assertNotEqual(first_call_set, third_call_set)

  def testWhile(
      self, trace_branch_mock, trace_cmp_mock, trace_regex_match_mock
  ):
    trace_branch_mock.assert_not_called()
    while_loop(1)
    trace_branch_mock.assert_called()

  def testRegex(self, trace_branch_mock, trace_cmp_mock,
                trace_regex_match_mock):
    trace_branch_mock.reset_mock()
    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    regex_match(re.compile("(Sun|Mon)day"), "Sunday")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()

  def testStrMethods(
      self, trace_branch_mock, trace_cmp_mock, trace_regex_match_mock
  ):
    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    starts_with("foobar", "foo")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()
    trace_branch_mock.reset_mock()
    trace_regex_match_mock.reset_mock()

    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    ends_with("bazbiz", "biz")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()
    trace_branch_mock.reset_mock()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    starts_with_var_args("foobar", "foo")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    ends_with_var_args("bazbiz", "biz")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    fake_starts_with("foobar", "foo")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    fake_ends_with("bazbiz", "biz")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    property_starts_with()
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    property_ends_with()
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

  def assertTraceCmpWas(self, call_args, left, right, op, left_is_const):
    """Compare a _trace_cmp call to expected values."""
    # call_args: tuple(left, right, opid, idx, left_is_const)
    self.assertEqual(call_args[0], left)
    self.assertEqual(call_args[1], right)
    self.assertEqual(dis.cmp_op[call_args[2]], op)
    self.assertEqual(call_args[4], left_is_const)

  def testCompare(self, trace_branch_mock, trace_cmp_mock,
                  trace_regex_match_mock):
    trace_cmp_mock.side_effect = original_trace_cmp

    self.assertTrue(cmp_less(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", False)
    first_cmp_idx = trace_cmp_mock.call_args[0][3]
    trace_cmp_mock.reset_mock()

    self.assertFalse(cmp_greater(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, ">", False)
    second_cmp_idx = trace_cmp_mock.call_args[0][3]
    self.assertNotEqual(first_cmp_idx, second_cmp_idx)
    trace_cmp_mock.reset_mock()

    self.assertTrue(cmp_less(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", False)
    third_cmp_idx = trace_cmp_mock.call_args[0][3]
    self.assertEqual(first_cmp_idx, third_cmp_idx)
    trace_cmp_mock.reset_mock()

    self.assertTrue(cmp_equal_nested(3, 3, True))
    self.assertEqual(len(trace_cmp_mock.call_args_list), 2)
    self.assertTraceCmpWas(
        trace_cmp_mock.call_args_list[0][0], 3, 3, "==", False
    )
    fourth_cmp_idx = trace_cmp_mock.call_args_list[0][0][3]
    self.assertNotEqual(first_cmp_idx, fourth_cmp_idx)
    self.assertNotEqual(second_cmp_idx, fourth_cmp_idx)
    self.assertTraceCmpWas(
        trace_cmp_mock.call_args_list[1][0], True, True, "==", False
    )
    fifth_cmp_idx = trace_cmp_mock.call_args_list[1][0][3]
    self.assertNotEqual(first_cmp_idx, fifth_cmp_idx)
    self.assertNotEqual(second_cmp_idx, fifth_cmp_idx)
    self.assertNotEqual(fourth_cmp_idx, fifth_cmp_idx)

  def testConstCompare(self, trace_branch_mock, trace_cmp_mock,
                       trace_regex_match_mock):
    trace_cmp_mock.side_effect = original_trace_cmp

    self.assertTrue(cmp_const_less(2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", True)
    first_cmp_idx = trace_cmp_mock.call_args[0][3]
    trace_cmp_mock.reset_mock()

    self.assertFalse(cmp_const_less_inverted(3))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 3, ">", True)
    second_cmp_idx = trace_cmp_mock.call_args[0][3]
    self.assertNotEqual(first_cmp_idx, second_cmp_idx)
    trace_cmp_mock.reset_mock()

  def testInstrumentationAppliedOnce(self, trace_branch_mock, trace_cmp_mock,
                                     trace_regex_match_mock):
    trace_branch_mock.assert_not_called()
    multi_instrumented(7)
    trace_branch_mock.assert_called_once()


if __name__ == "__main__":
  unittest.main()
