# Copyright 2026 Google LLC
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
"""Self-consistency tests for version_dependent against the running interpreter.

These tests don't exercise the instrumentor; they verify that the static
opcode tables in version_dependent.py agree with the `dis`/`opcode` modules of
whatever Python version is running them. The intent is that a CPython upgrade
that adds, removes, or reclassifies an opcode will fail here with a clear
message before it manifests as a confusing crash in instrument_bytecode.
"""

import dis
import opcode
import unittest

from atheris import version_dependent as vd


def _real_opnames() -> set[str]:
  """Opcodes that can actually appear in a code object's co_code.

  Excludes pseudo-ops (>=256) which are compiler-internal labels that never
  reach the bytecode stream.
  """
  return {name for name, op in dis.opmap.items() if op < 256}


class VersionDependentTest(unittest.TestCase):

  def test_rel_reference_ops_are_jumps(self):
    """Every op we treat as a relative jump is one CPython agrees is a jump."""
    real = _real_opnames()
    cpython_rel = {dis.opname[o] for o in dis.hasjrel}
    for name in vd.HAVE_REL_REFERENCE:
      if name not in real:
        continue  # legacy entry for an older Python version
      self.assertIn(
          name,
          cpython_rel,
          f"{name} is in HAVE_REL_REFERENCE but dis.hasjrel does not list it; "
          "Atheris would miscompute its target.",
      )

  def test_no_untracked_jumps(self):
    """Every relative jump CPython knows about is tracked by Atheris.

    If this fails, Atheris will leave that opcode's offset unrewritten and
    inserting instrumentation between it and its target will produce a wrong
    jump.
    """
    tracked = set(vd.HAVE_REL_REFERENCE)
    real = _real_opnames()
    cpython_rel = {dis.opname[o] for o in dis.hasjrel}
    untracked = (cpython_rel & real) - tracked
    # INSTRUMENTED_* variants share the oparg of their plain form and are
    # rewritten in-place by the interpreter, so they never appear in co_code as
    # produced by the compiler; Atheris does not need to track them.
    untracked = {n for n in untracked if not n.startswith("INSTRUMENTED_")}
    self.assertEqual(
        untracked,
        set(),
        "These relative-jump opcodes are not in HAVE_REL_REFERENCE; their "
        "oparg will go stale when Atheris inserts instructions.",
    )

  def test_inverted_jumps_are_subset(self):
    for name in vd.REL_REFERENCE_IS_INVERTED:
      if name in _real_opnames():
        self.assertIn(name, vd.HAVE_REL_REFERENCE)

  def test_cache_count_matches_interpreter(self):
    expected = getattr(opcode, "_inline_cache_entries", {})
    if not isinstance(expected, dict):
      # 3.11/3.12 expose this as a list indexed by opcode.
      expected = {
          dis.opname[i]: n for i, n in enumerate(expected) if n
      }
    for name in _real_opnames():
      with self.subTest(name=name):
        want = expected.get(name, 0)
        if not want:
          want = 0
        self.assertEqual(
            vd.cache_count(name),
            want,
            f"cache_count({name!r}) disagrees with opcode._inline_cache_entries",
        )

  def test_insert_after_instrs_exist(self):
    real = _real_opnames()
    for name in vd.INSERT_AFTER_INSTRS:
      self.assertIn(
          name,
          real,
          f"INSERT_AFTER_INSTRS references unknown opcode {name!r}",
      )

  def test_const_push_instrs_exist(self):
    real = _real_opnames()
    for name in vd.CONST_PUSH_INSTRS:
      self.assertIn(name, real)

  def test_has_argument_matches_interpreter(self):
    if not hasattr(dis, "hasarg"):
      self.skipTest("dis.hasarg not available on this Python version")
    cpython_hasarg = set(dis.hasarg)
    for name, op in dis.opmap.items():
      if op >= 256:
        continue
      with self.subTest(name=name):
        self.assertEqual(
            vd.has_argument(op),
            op in cpython_hasarg,
            f"has_argument disagrees with dis.hasarg for {name}",
        )


if __name__ == "__main__":
  unittest.main()
