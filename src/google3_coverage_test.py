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
import unittest
from unittest import mock


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
def cmp_const_less(a):
  return 1 < a


@atheris.instrument_func
def cmp_const_less_inverted(a):
  return a < 1


@atheris.instrument_func
def decorator_instrumented(x):
  return 2 * x


@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
@atheris.instrument_func
def multi_instrumented(x):
  return 2 * x


original_trace_cmp = atheris._trace_cmp


@mock.patch.object(atheris, "_trace_cmp")
@mock.patch.object(atheris, "_trace_branch")
class CoverageTest(unittest.TestCase):

  def testBranch(self, trace_branch_mock, trace_cmp_mock):
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

  def assertTraceCmpWas(self, call_args, left, right, op, left_is_const):
    """Compare a _trace_cmp call to expected values."""
    #call_args: tuple(left, right, opid, idx, left_is_const)
    self.assertEqual(call_args[0], left)
    self.assertEqual(call_args[1], right)
    self.assertEqual(dis.cmp_op[call_args[2]], op)
    self.assertEqual(call_args[4], left_is_const)

  def testCompare(self, trace_branch_mock, trace_cmp_mock):
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

  def testConstCompare(self, trace_branch_mock, trace_cmp_mock):
    trace_cmp_mock.side_effect = original_trace_cmp

    self.assertTrue(cmp_const_less(2))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 2, "<", True)
    first_cmp_idx = trace_cmp_mock.call_args[0][3]
    trace_cmp_mock.reset_mock()

    self.assertFalse(cmp_const_less_inverted(3))
    self.assertTraceCmpWas(trace_cmp_mock.call_args[0], 1, 3, ">", True)
    first_cmp_idx = trace_cmp_mock.call_args[0][3]
    trace_cmp_mock.reset_mock()

  def testInstrumentationAppliedOnce(self, trace_branch_mock, trace_cmp_mock):
    trace_branch_mock.assert_not_called()
    multi_instrumented(7)
    trace_branch_mock.assert_called_once()


if __name__ == "__main__":
  unittest.main()
