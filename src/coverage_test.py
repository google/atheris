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

import dis
import re
from typing import Tuple
import unittest
from unittest import mock

import atheris

with atheris.instrument_imports():
  import coverage_test_helper  # pytype: disable=import-error

# Enable RegEx instrumentation.
atheris.enabled_hooks.add("RegEx")
# Enable str methods instrumentation.
atheris.enabled_hooks.add("str")


@atheris.instrument_func
def decorator_instrumented(x: int) -> int:
  return 2 * x


@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
def multi_instrumented(x: int) -> int:
  return 2 * x


original_trace_cmp = atheris._trace_cmp


@mock.patch.object(atheris, "_trace_regex_match")
@mock.patch.object(atheris, "_trace_cmp")
@mock.patch.object(atheris, "_trace_branch")
class CoverageTest(unittest.TestCase):

  def testBasicBlock(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                     trace_regex_match_mock: mock.MagicMock):
    trace_branch_mock.assert_not_called()
    coverage_test_helper.simple_func(7)
    trace_branch_mock.assert_called()

    trace_branch_mock.reset_mock()
    coverage_test_helper.simple_func(2)
    trace_branch_mock.assert_called()

  def testDecoratorBasicBlock(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                              trace_regex_match_mock: mock.MagicMock):
    trace_branch_mock.assert_not_called()
    decorator_instrumented(7)
    trace_branch_mock.assert_called()

    trace_branch_mock.reset_mock()
    decorator_instrumented(2)
    trace_branch_mock.assert_called()

  def testBranch(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                 trace_regex_match_mock: mock.MagicMock):
    trace_branch_mock.assert_not_called()
    coverage_test_helper.if_func(True)
    first_call_set = trace_branch_mock.call_args_list

    trace_branch_mock.reset_mock()
    coverage_test_helper.if_func(True)
    second_call_set = trace_branch_mock.call_args_list

    self.assertEqual(first_call_set, second_call_set)

    trace_branch_mock.reset_mock()
    coverage_test_helper.if_func(False)
    third_call_set = trace_branch_mock.call_args_list

    self.assertNotEqual(first_call_set, third_call_set)

  def testWhile(
      self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock, trace_regex_match_mock: mock.MagicMock
  ):
    trace_branch_mock.assert_not_called()
    coverage_test_helper.while_loop(1)
    trace_branch_mock.assert_called()

  def testRegex(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                trace_regex_match_mock: mock.MagicMock):
    trace_branch_mock.reset_mock()
    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.regex_match(re.compile("(Sun|Mon)day"), "Sunday")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()

  def testStrMethods(
      self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock, trace_regex_match_mock: mock.MagicMock
  ):
    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.starts_with("foobar", "foo")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()
    trace_branch_mock.reset_mock()
    trace_regex_match_mock.reset_mock()

    trace_branch_mock.assert_not_called()
    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.ends_with("bazbiz", "biz")
    trace_branch_mock.assert_called()
    trace_regex_match_mock.assert_called()
    trace_branch_mock.reset_mock()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.starts_with_var_args("foobar", "foo")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    # Check that non-str method calls do not get traced
    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.fake_starts_with("foobar", "foo")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.ends_with_var_args("bazbiz", "biz")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.fake_starts_with("foobar", "foo")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.fake_ends_with("bazbiz", "biz")
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.property_starts_with()
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

    trace_regex_match_mock.assert_not_called()
    coverage_test_helper.property_ends_with()
    trace_regex_match_mock.assert_not_called()
    trace_regex_match_mock.reset_mock()

  def assertTraceCmpWas(self, call_args: Tuple[int, int, int, int, bool], left: int, right: int, op: str, left_is_const: bool):
    """Compare a _trace_cmp call to expected values."""
    # call_args: tuple(left, right, opid, idx, left_is_const)
    self.assertEqual(call_args[0], left)
    self.assertEqual(call_args[1], right)
    self.assertEqual(dis.cmp_op[call_args[2]], op)
    self.assertEqual(call_args[4], left_is_const)

  def testCompare(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                  trace_regex_match_mock: mock.MagicMock):
    trace_cmp_mock.side_effect = original_trace_cmp

    self.assertTrue(coverage_test_helper.cmp_less(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", False)
    first_cmp_idx = trace_cmp_mock.call_args[0][3]
    trace_cmp_mock.reset_mock()

    self.assertFalse(coverage_test_helper.cmp_greater(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, ">", False)
    second_cmp_idx = trace_cmp_mock.call_args[0][3]
    self.assertNotEqual(first_cmp_idx, second_cmp_idx)
    trace_cmp_mock.reset_mock()

    self.assertTrue(coverage_test_helper.cmp_less(1, 2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", False)
    third_cmp_idx = trace_cmp_mock.call_args[0][3]
    self.assertEqual(first_cmp_idx, third_cmp_idx)
    trace_cmp_mock.reset_mock()

    self.assertTrue(coverage_test_helper.cmp_equal_nested(3, 3, True))
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

  def testConstCompare(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                       trace_regex_match_mock: mock.MagicMock):
    trace_cmp_mock.side_effect = original_trace_cmp

    self.assertTrue(coverage_test_helper.cmp_const_less(2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", True)
    trace_cmp_mock.reset_mock()

    self.assertFalse(coverage_test_helper.cmp_const_less_inverted(3))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 3, ">", True)
    trace_cmp_mock.reset_mock()

  def testInstrumentationAppliedOnce(self, trace_branch_mock: mock.MagicMock, trace_cmp_mock: mock.MagicMock,
                                     trace_regex_match_mock: mock.MagicMock):
    trace_branch_mock.assert_not_called()
    multi_instrumented(7)
    trace_branch_mock.assert_called_once()


if __name__ == "__main__":
  unittest.main()
