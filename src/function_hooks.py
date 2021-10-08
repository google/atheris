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

import sys

def gen_match(ops):
  """
    Given a regular expression, try to generate a matching string
    TODO(cffsmith): This generator is *not* feature complete.
  """
  available_characters = set([chr(x) for x in range(0x20, 0x7e)] + ["\t", "\n"])

  import sre_parse

  literals = ""

  for tup in ops:
    if tup[0] == sre_parse.LITERAL:
      if tup[1] > 128:
        sys.stderr.write("Encountered non-ASCII char\n")
      literals += chr(tup[1])

    elif tup[0] == sre_parse.BRANCH:
      # just generate the first branch
      literals += gen_match(tup[1][1][0])

    elif tup[0] == sre_parse.NEGATE:
      sys.stderr.write("WARNING: We did not expect a NEGATE op here; is there an invalid RegEx somewhere?\n")
      pass

    elif tup[0] == sre_parse.IN:
      # Check if this class is negated.
      negated = tup[1][0][0] == sre_parse.NEGATE
      # Take the first one that is actually in the class
      if not negated:
        literals += gen_match([tup[1][0]])
      else:
        char_set = set()
        # grab all literals from this class
        for tup in tup[1][1:]:
          if tup[0] != sre_parse.LITERAL:
            sys.stderr.write("WARNING: Encountered non literal in character class, cannot instrument RegEx!\n")
            continue
          char_set.add(chr(tup[1]))
        allowed = available_characters - char_set
        if len(allowed) == 0:
          sys.stderr.write("WARNING: This character set does not seem to allow any characters, cannot instrument RegEx!\n")
        else:
          literals += list(allowed)[0]

    elif tup[0] == sre_parse.SUBPATTERN:
      literals += gen_match(tup[1][3])

    elif tup[0] == sre_parse.MAX_REPEAT:
      # The minimum amount of repetitions we need to fulfill the pattern
      minimum = tup[1][0]
      literals += gen_match(tup[1][2]) * minimum

    elif tup[0] == sre_parse.ASSERT or tup[0] == sre_parse.ASSERT_NOT:
      literals += gen_match(tup[1][1])

    elif tup[0] == sre_parse.CATEGORY:
      sys.stderr.write(f"WARNING: Currently not handling RegEx categories, cannot instrument RegEx!\n")

    else:
      sys.stderr.write(f"WARNING: Encountered non-handled RegEx op: {tup[0]}, cannot instrument RegEx\n")

  return literals

def hook_re_module():
  import re
  pattern_gen_map = dict()

  original_compile_func = re._compile

  def _hook(_pattern, _flags):
    generated = ""
    if _pattern not in pattern_gen_map:
      import sre_parse
      pat = sre_parse.parse(_pattern)
      generated = gen_match(pat)
      # Check that the pattern actually matches
      check_pattern = _pattern
      try:
        # Convert our pattern to a string if necessary
        check_pattern = _pattern.decode('utf-8')
      except AttributeError:
        # Already a string
        pass
      except Exception as e:
        # Not sure what went wrong.
        sys.stderr.write(f"Could not convert the pattern {_pattern} to a utf-8 string: {e}\n")
        pass
      try:
        if original_compile_func(check_pattern, _flags).search(generated) == None:
          sys.stderr.write(f"ERROR: generated match '{generated}' did not match the RegEx pattern '{_pattern}'!\n")
      except Exception as e:
        sys.stderr.write(f"Could not check the generated match against the RegEx pattern: {e}\n")
      pattern_gen_map[_pattern] = generated
    else:
      generated = pattern_gen_map[_pattern]

    # Create the `re.Pattern` object. We will wrap this in a proxy later on.
    re_object = original_compile_func(_pattern, _flags)

    # Return the wrapped `re.Pattern` object.
    return AtherisPatternProxy(re_object, generated)

  # actually hook the `_compile` function now
  re._compile = _hook


class EnabledHooks:
  def __init__(self):
    self._enabled_hooks = set()


  def add(self, hook):
    hook = hook.lower()
    if hook not in list(self._enabled_hooks):
      if hook == "regex":
        hook_re_module()
        self._enabled_hooks.add(hook)


enabled_hooks = EnabledHooks()


class AtherisPatternProxy:
  """
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

  def __init__(self, re_obj, generated):
    self.re_obj = re_obj
    self.generated = generated

  def search(self, string):
    from atheris import _trace_regex_match
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.search(string)

  def match(self, string):
    from atheris import _trace_regex_match
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.match(string)

  def fullmatch(self, string):
    from atheris import _trace_regex_match
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.fullmatch(string)

  def findall(self, string):
    from atheris import _trace_regex_match
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.findall(string)

  def finditer(self, string):
    from atheris import _trace_regex_match
    _trace_regex_match(self.generated, self.re_obj)
    return self.re_obj.finditer(string)

  def __getattr__(self, attr):
    return getattr(self.re_obj, attr)
