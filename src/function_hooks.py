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

import re
import sre_parse
import sys
from typing import Set, Any, Pattern, List, Match, Optional, Iterator

# mypy does not like the implicit rexport of the constants available in
# sre_parse, and also does not support ignoring for blocks of code. Rather
# than having a whole-file ignore, or interrupting every line of every statement
# below with an ignore, we will make aliases and ignore here.
_ASSERT = sre_parse.ASSERT  # type: ignore[attr-defined]
_ASSERT_NOT = sre_parse.ASSERT_NOT  # type: ignore[attr-defined]
_BRANCH = sre_parse.BRANCH  # type: ignore[attr-defined]
_CATEGORY = sre_parse.CATEGORY  # type: ignore[attr-defined]
_IN = sre_parse.IN  # type: ignore[attr-defined]
_LITERAL = sre_parse.LITERAL  # type: ignore[attr-defined]
_MAX_REPEAT = sre_parse.MAX_REPEAT  # type: ignore[attr-defined]
_NEGATE = sre_parse.NEGATE  # type: ignore[attr-defined]
_SUBPATTERN = sre_parse.SUBPATTERN  # type: ignore[attr-defined]


def gen_match(ops: Any) -> str:
  """Returns a matching string given a regex expression."""
  # TODO(cffsmith): This generator is *not* feature complete.

  available_characters = set([chr(x) for x in range(0x20, 0x7e)] + ["\t", "\n"])

  literals = ""

  for tup in ops:
    if tup[0] == _LITERAL:
      if tup[1] > 128:
        sys.stderr.write("Encountered non-ASCII char\n")
      literals += chr(tup[1])  # pytype: disable=wrong-arg-types

    elif tup[0] == _BRANCH:
      # just generate the first branch
      literals += gen_match(tup[1][1][0])

    elif tup[0] == _NEGATE:
      sys.stderr.write("WARNING: We did not expect a NEGATE op here; is " +
                       "there an invalid RegEx somewhere?\n")
      pass

    elif tup[0] == _IN:
      # Check if this class is negated.
      negated = tup[1][0][0] == _NEGATE
      # Take the first one that is actually in the class
      if not negated:
        literals += gen_match([tup[1][0]])
      else:
        char_set = set()
        # grab all literals from this class
        for t in tup[1][1:]:
          if t[0] != _LITERAL:
            sys.stderr.write("WARNING: Encountered non literal in character " +
                             "class, cannot instrument RegEx!\n")
            continue
          char_set.add(chr(t[1]))
        allowed = available_characters - char_set
        if not allowed:
          sys.stderr.write("WARNING: This character set does not seem to " +
                           "allow any characters, cannot instrument RegEx!\n")
        else:
          literals += list(allowed)[0]

    elif tup[0] == _SUBPATTERN:
      literals += gen_match(tup[1][3])

    elif tup[0] == _MAX_REPEAT:
      # The minimum amount of repetitions we need to fulfill the pattern
      minimum = tup[1][0]
      literals += gen_match(tup[1][2]) * minimum

    elif tup[0] == _ASSERT or tup[0] == _ASSERT_NOT:
      literals += gen_match(tup[1][1])

    elif tup[0] == _CATEGORY:
      sys.stderr.write("WARNING: Currently not handling RegEx categories, " +
                       "cannot instrument RegEx!\n")

    else:
      sys.stderr.write(f"WARNING: Encountered non-handled RegEx op: {tup[0]}" +
                       ", cannot instrument RegEx\n")

  return literals


def hook_re_module() -> None:
  """Adds Atheris instrumentation hooks to the `re` module."""
  pattern_gen_map = {}

  original_compile_func = re._compile  # type: ignore[attr-defined]

  def _compile_hook(pattern: str, flags: int) -> "AtherisPatternProxy":
    """Overrides re._compile."""

    generated = ""
    if pattern not in pattern_gen_map:
      pat = sre_parse.parse(pattern)
      generated = gen_match(pat)
      # Check that the pattern actually matches
      check_pattern = pattern
      try:
        # Convert our pattern to a string if necessary
        check_pattern = pattern.decode("utf-8")  # type: ignore
      except AttributeError:
        # Already a string
        pass
      except Exception as e:  # pylint: disable=broad-except
        # Not sure what went wrong.
        sys.stderr.write(f"Could not convert the pattern {pattern} to a " +
                         f"utf-8 string: {e}\n")
      try:
        if original_compile_func(check_pattern,
                                 flags).search(generated) is None:
          sys.stderr.write(f"ERROR: generated match '{generated}' did not " +
                           "match the RegEx pattern '{_pattern}'!\n")
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
