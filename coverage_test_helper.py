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
"""A helper library for coverage_test.py - coverage is added to this library."""


def simple_func(a):
  return 2 * a


def if_func(a):
  x = a
  if x:
    return 2
  else:
    return 3


def cmp_less(a, b):
  return a < b


def cmp_greater(a, b):
  return a > b


def cmp_const_less(a):
  return 1 < a


def cmp_const_less_inverted(a):
  return a < 1
