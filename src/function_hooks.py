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
"""Provides Atheris instrumentation hooks for particular functions like regex."""

import logging
import re
import sys
import typing
from typing import Any, AnyStr, Callable, Dict, Iterator, List, Match, Optional, Pattern, Set, Tuple, Union
try:
  import re._parser as sre_parse  # type: ignore[import]
except ImportError:
  import sre_parse


# mypy does not like the implicit rexport of the constants available in
# sre_parse, and also does not support ignoring for blocks of code. Rather
# than having a whole-file ignore, or interrupting every line of every statement
# below with an ignore, we will make aliases and ignore here.
_ANY = sre_parse.ANY  # type: ignore[attr-defined]
_ASSERT = sre_parse.ASSERT  # type: ignore[attr-defined]
_ASSERT_NOT = sre_parse.ASSERT_NOT  # type: ignore[attr-defined]
_BRANCH = sre_parse.BRANCH  # type: ignore[attr-defined]
_CATEGORY = sre_parse.CATEGORY  # type: ignore[attr-defined]
_CATEGORY_DIGIT = sre_parse.CATEGORY_DIGIT  # type: ignore[attr-defined]
_CATEGORY_NOT_DIGIT = sre_parse.CATEGORY_NOT_DIGIT  # type: ignore[attr-defined]
_CATEGORY_SPACE = sre_parse.CATEGORY_SPACE  # type: ignore[attr-defined]
_CATEGORY_NOT_SPACE = sre_parse.CATEGORY_NOT_SPACE  # type: ignore[attr-defined]
_CATEGORY_WORD = sre_parse.CATEGORY_WORD  # type: ignore[attr-defined]
_CATEGORY_NOT_WORD = sre_parse.CATEGORY_NOT_WORD  # type: ignore[attr-defined]
_IN = sre_parse.IN  # type: ignore[attr-defined]
_LITERAL = sre_parse.LITERAL  # type: ignore[attr-defined]
_MAX_REPEAT = sre_parse.MAX_REPEAT  # type: ignore[attr-defined]
_MIN_REPEAT = sre_parse.MIN_REPEAT  # type: ignore[attr-defined]
_NEGATE = sre_parse.NEGATE  # type: ignore[attr-defined]
_RANGE = sre_parse.RANGE  # type: ignore[attr-defined]
_SUBPATTERN = sre_parse.SUBPATTERN  # type: ignore[attr-defined]


def to_correct_type(
    to_convert: Union[str, bytes], return_type: Callable[[], AnyStr]
) -> Union[str, bytes]:
  if return_type != str and return_type != bytes:
    raise TypeError(
        f"Expected `return_type` to be str or bytes, got {return_type}"
    )
  if (isinstance(to_convert, bytes) and return_type == bytes) or (
      isinstance(to_convert, str) and return_type == str
  ):
    return to_convert
  elif isinstance(to_convert, bytes):
    return str(to_convert)
  else:
    return bytes(to_convert, "utf-8")


@typing.no_type_check # mypy chokes on `return_type`
def gen_match_recursive(ops: Any,
                        return_type: Callable[[], Union[str, bytes]] = str,
                        respect_lookarounds: bool = False) -> Union[str, bytes]:
  """Returns a matching string given a regex expression."""
  # TODO(cffsmith): This generator is *not* feature complete.

  available_characters = set([chr(x) for x in range(0x20, 0x7e)] + ["\t", "\n"])

  literals = return_type()

  for tup in ops:
    if tup[0] == _LITERAL:
      val = tup[1]
      if return_type == str:
        literals += chr(val)
      elif return_type == bytes:
        # Endianess does not matter because there's just a single byte.
        literals += val.to_bytes(1, "big")
      else:
        raise TypeError(
            f"Expected return_type to be `str` or `bytes`, got {return_type}")

    elif tup[0] == _ANY:
      literals += "a"

    elif tup[0] == _BRANCH:
      # just generate the first branch
      literals += gen_match_recursive(tup[1][1][0], return_type)

    elif tup[0] == _NEGATE:
      sys.stderr.write("WARNING: We did not expect a NEGATE op here; is " +
                       "there an invalid RegEx somewhere?\n")
      pass

    elif tup[0] == _RANGE:
      literals += to_correct_type(chr(tup[1][1]), return_type)

    elif tup[0] == _IN:
      # Check if this class is negated.
      negated = tup[1][0][0] == _NEGATE
      # Take the first one that is actually in the class
      if not negated:
        literals += gen_match_recursive([tup[1][0]], return_type)
      else:
        char_set = set()
        # grab all literals from this class
        for t in tup[1][1:]:
          if t[0] == _LITERAL:
            char_set.add(chr(t[1]))
          elif t[0] == _RANGE:
            char_set |= set(chr(c) for c in range(t[1][0], t[1][1] + 1))
          else:
            sys.stderr.write("WARNING: Encountered non literal in character " +
                             "class, cannot instrument RegEx!\n")
            continue
        allowed = available_characters - char_set
        if not allowed:
          sys.stderr.write("WARNING: This character set does not seem to " +
                           "allow any characters, cannot instrument RegEx!\n")
        else:
          literals += to_correct_type(list(allowed)[0], return_type)

    elif tup[0] == _SUBPATTERN:
      literals += gen_match_recursive(tup[1][3], return_type)

    elif tup[0] == _MAX_REPEAT or tup[0] == _MIN_REPEAT:
      # The minimum amount of repetitions we need to fulfill the pattern.
      # This refers to the distinction between `*` and `+`, not between greedy
      # (the default) matching vs non-greedy repeat matching with `.*?`, which
      # is represented by _MAX_REPEAT vs _MIN_REPEAT.
      minimum = tup[1][0]
      literals += gen_match_recursive(tup[1][2], return_type) * minimum

    elif tup[0] == _ASSERT_NOT:
      sys.stderr.write(
          "WARNING: found negative lookahead or negative lookbehind, "
          "which are currently unsupported due to NP Completeness.")
    elif tup[0] == _ASSERT:
      if not respect_lookarounds:
        sys.stderr.write(
            "WARNING: Found lookahead or lookbehind in the middle of a regex, "
            "ignoring due to NP Completeness."
        )
        continue

      is_lookahead = tup[1][0] > 0
      is_beginning = ops.data.index(tup) == 0
      is_end = ops.data.index(tup) == len(ops) - 1
      if is_lookahead and is_end:
        literals += gen_match_recursive(tup[1][1], return_type)
      elif not is_lookahead and is_beginning:
        literals = gen_match_recursive(tup[1][1], return_type) + literals

    elif tup[0] == _CATEGORY:
      # For how each of these is encoded, see
      # https://github.com/python/cpython/blob/main/Lib/sre_parse.py#L42
      category = tup[1]
      # start with a string, we'll do the type conversion later.
      ch = ""
      if category == _CATEGORY_DIGIT:
        ch = "0"
      if category == _CATEGORY_NOT_DIGIT:
        ch = "a"
      elif category == _CATEGORY_SPACE:
        ch = " "
      elif category == _CATEGORY_NOT_SPACE:
        ch = "a"
      elif category == _CATEGORY_WORD:
        ch = "a"
      elif category == _CATEGORY_NOT_WORD:
        ch = " "
      else:
        sys.stderr.write("WARNING: Unsupported RegEx category, " +
                         "cannot instrument RegEx!\n")

      literals += to_correct_type(ch, return_type)

    else:
      sys.stderr.write(f"WARNING: Encountered non-handled RegEx op: {tup[0]}" +
                       ", cannot instrument RegEx\n")

  return literals


def gen_match(pattern: AnyStr) -> AnyStr:
  pat = sre_parse.parse(pattern)
  return gen_match_recursive(pat, type(pattern), respect_lookarounds=True)  # type: ignore[bad-return-type]


def hook_re_module() -> None:
  """Adds Atheris instrumentation hooks to the `re` module."""
  pattern_gen_map = {}  # type: ignore

  original_compile_func = re._compile  # type: ignore[module-attr]

  @typing.no_type_check  # mypy chokes on the return type
  def _compile_hook(pattern: AnyStr, flags: int) -> "AtherisPatternProxy":
    """Overrides re._compile."""

    generated: re.Pattern
    if pattern not in pattern_gen_map:
      generated = gen_match(pattern)  # type: ignore[annotation-type-mismatch]

      try:
        if original_compile_func(pattern, flags).search(generated) is None:
          sys.stderr.write(f"ERROR: generated match '{generated!r}' did not " +
                           "match the RegEx pattern '{_pattern!r}'!\n")
      except Exception as e:  # pylint: disable=broad-except
        sys.stderr.write("Could not check the generated match against the " +
                         f"RegEx pattern: {e}\n")
      pattern_gen_map[pattern] = generated
    else:
      generated = pattern_gen_map[pattern]

    # Create the `re.Pattern` object. We will wrap this in a proxy later on.
    re_object = original_compile_func(pattern, flags)

    # Return the wrapped `re.Pattern` object.
    return AtherisPatternProxy(re_object, generated)

  # actually hook the `_compile` function now
  # pylint: disable=protected-access
  re._compile = _compile_hook  # type: ignore[attr-defined]
  # pylint: enable=protected-access


class EnabledHooks:
  """Manages the set of enabled hooks."""

  def __init__(self) -> None:
    self._enabled_hooks: Set[str] = set()

  def add(self, hook: str) -> None:
    hook = hook.lower()
    if hook not in list(self._enabled_hooks):
      if hook == "regex":
        hook_re_module()
        self._enabled_hooks.add(hook)
      elif hook == "str":
        self._enabled_hooks.add(hook)

  def __contains__(self, hook: str) -> bool:
    return hook.lower() in self._enabled_hooks


enabled_hooks = EnabledHooks()


class AtherisPatternProxy:
  """Proxy routing regex functions though Atheris tracing equivalents.

  This is a simple proxy where we can hook into various regex
  functions. This ensures that the tracing happens on each call to
  `match`, `search`, etc.

  This can be observable by users who call `compile` and then check
  if the object is actually a `re.Pattern` object.

  Unfortunately it is not possible to change the functions on the
  `re.Pattern` object itself as the functions are not writable.
  (One could try to bypass this but it would need unsafe usage from
  ctypes and probably won't be version agnostic)
  """

  # Importing at the top will not work. TODO(b/207008147): Why does it fail?
  # pylint: disable=g-import-not-at-top

  def __init__(self, re_obj: Pattern, generated: str) -> None:
    self.re_obj = re_obj
    self.generated = generated

  def search(self, string: str) -> Optional[Match[Any]]:
    from atheris import _trace_regex_match  # type: ignore[import]
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.search(string)

  def match(self, string: str) -> Optional[Match[Any]]:
    from atheris import _trace_regex_match  # type: ignore[import]
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.match(string)

  def fullmatch(self, string: str) -> Optional[Match[str]]:
    from atheris import _trace_regex_match  # type: ignore[import]
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.fullmatch(string)

  def findall(self, string: str) -> List[str]:
    from atheris import _trace_regex_match  # type: ignore[import]
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.findall(string)

  def finditer(self, string: str) -> Iterator[Match[str]]:
    from atheris import _trace_regex_match  # type: ignore[import]
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.finditer(string)

  def __getattr__(self, attr: str) -> Any:
    return getattr(self.re_obj, attr)

  # pylint: enable=g-import-not-at-top


_str_pattern_gen_map = {}


def _trace_str(
    s: str, str_method: str, new_args: Tuple[Any], pattern: str
) -> None:
  """Handles pattern generation and calls _trace_regex_match."""

  # pylint: disable=g-import-not-at-top

  if str_method == "startswith":
    # start arg present
    if len(new_args) >= 2:
      start = new_args[1]
      if start >= 0:
        pattern = r".{%d}%s" % (start, pattern)
  elif str_method == "endswith":
    # end arg present
    if len(new_args) >= 3:
      end = new_args[2]
      if end - len(pattern) >= 0:
        pattern = r".{%d}%s" % (end - len(pattern), pattern)
    # Only start arg present
    elif len(new_args) >= 2:
      start = new_args[1]
      if start >= 0:
        pattern = r".{%d}%s" % (start, pattern)

  if pattern not in _str_pattern_gen_map:
    _str_pattern_gen_map[pattern] = gen_match(pattern)
  generated: AnyStr = _str_pattern_gen_map[pattern]  # pytype: disable=invalid-annotation
  from atheris import _trace_regex_match  # type: ignore[import]
  _trace_regex_match(generated, s)

  # pylint: enable=g-import-not-at-top


def _hook_str(*args, **kwargs) -> bool:
  """Proxy routing str functions through Atheris tracing.

  Even though bytecode is modified for hooking the str methods, we use this
  proxy function for typechecking the caller at runtime.

  Args:
    *args: The positional arguments
    **kwargs: The keyword arguments

  Returns:
    The result of s (args[0]) calling str_method (args[1]) with *args[2:],
    **kwargs
  """

  if not args or len(args) < 2:
    logging.error("_hook_str call was not patched in properly")
    return None

  s = args[0]
  str_method: str = args[1]
  new_args: Tuple[Any] = args[2:]

  # Call the original method before tracing
  rtn = getattr(s, str_method)(*new_args, **kwargs)

  # Since all startswith methods are hooked, only trace startswith calls from
  # str objects.
  if isinstance(s, str) and ("str" in enabled_hooks) and new_args:
    if isinstance(new_args[0], str):
      pattern = new_args[0]
      _trace_str(s, str_method, new_args, pattern)
    elif isinstance(new_args[0], tuple):
      for pattern in new_args[0]:
        if isinstance(pattern, str):
          _trace_str(s, str_method, new_args, pattern)

  return rtn
