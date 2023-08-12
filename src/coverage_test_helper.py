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


def cmp_equal_nested(a, b, c):
  return (a == b) == c


def cmp_const_less(a):
  return 1 < a


def cmp_const_less_inverted(a):
  return a < 1


def while_loop(a):
  while a:
    a -= 1


def regex_match(re_obj, a):
  re_obj.match(a)


def starts_with(s, prefix):
  s.startswith(prefix)


def ends_with(s, suffix):
  s.endswith(suffix)


# Verifying that no tracing happens when var args are passed in to
# startswith method calls
def starts_with_var_args(s, *args):
  s.startswith(*args)


# Verifying that no tracing happens when var args are passed in to
# endswith method calls
def ends_with_var_args(s, *args):
  s.startswith(*args)


class FakeStr:

  def startswith(self, s, prefix):
    pass

  def endswith(self, s, suffix):
    pass


# Verifying that even though this code gets patched, no tracing happens
def fake_starts_with(s, prefix):
  fake_str = FakeStr()
  fake_str.startswith(s=s, prefix=prefix)


# Verifying that even though this code gets patched, no tracing happens
def fake_ends_with(s, suffix):
  fake_str = FakeStr()
  fake_str.endswith(s, suffix)


class StrProperties:
  startswith = None
  endswith = None


# Verifying that no tracing happens since startswith is a property
def property_starts_with():
  fake_str = StrProperties()
  fake_str.startswith = None


# Verifying that no patching happens since endswith is a property
def property_ends_with():
  fake_str = StrProperties()
  fake_str.endswith = None
