# Copyright 2021 Google LLC
# Copyright 2021 Fraunhofer FKIE
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
"""This module manages the version specific aspects of bytecode instrumentation.

Accross Python versions there are variations in:
    - Instructions
    - Instruction arguments
    - Shape of a code object
    - Construction of the lnotab

Currently supported python versions are:
    - 3.6
    - 3.7
    - 3.8
    - 3.9
    - 3.10
    - 3.11
"""

import sys
import types
import dis
import opcode
from typing import List

PYTHON_VERSION = sys.version_info[:2]

if PYTHON_VERSION < (3, 6) or PYTHON_VERSION > (3, 11):
  raise RuntimeError(
      "You are fuzzing on an unsupported python version: "
      + f"{PYTHON_VERSION[0]}.{PYTHON_VERSION[1]}. Only 3.6 - 3.11 are "
      + "supported by atheris 2.0. Use atheris 1.0 for older python versions."
  )

### Instruction categories ###

CONDITIONAL_JUMPS = [
    # common
    "FOR_ITER",
    "JUMP_IF_FALSE_OR_POP",
    "JUMP_IF_TRUE_OR_POP",
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE",
    # 3.9
    "JUMP_IF_NOT_EXC_MATCH",
    # 3.11
    "POP_JUMP_FORWARD_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE",
    "POP_JUMP_BACKWARD_IF_FALSE",
    "POP_JUMP_FORWARD_IF_NOT_NONE",
    "POP_JUMP_BACKWARD_IF_NOT_NONE",
    "POP_JUMP_FORWARD_IF_NONE",
    "POP_JUMP_BACKWARD_IF_NONE",
]

UNCONDITIONAL_JUMPS = [
    # common
    "JUMP_FORWARD",
    "JUMP_ABSOLUTE",
    # 3.6 / 3.7
    "CONTINUE_LOOP",
    # 3.8
    "CALL_FINALLY",
    # 3.11
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
]

ENDS_FUNCTION = [
    # common
    "RAISE_VARARGS",
    "RETURN_VALUE",

    # 3.9
    "RERAISE",
]

HAVE_REL_REFERENCE = [
    # common
    "SETUP_WITH",
    "JUMP_FORWARD",
    "FOR_ITER",
    "SETUP_FINALLY",
    "CALL_FINALLY",
    # 3.6 / 3.7
    "SETUP_LOOP",
    "SETUP_EXCEPT",
    # 3.11
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "POP_JUMP_FORWARD_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE",
    "POP_JUMP_BACKWARD_IF_FALSE",
    "POP_JUMP_FORWARD_IF_NOT_NONE",
    "POP_JUMP_BACKWARD_IF_NOT_NONE",
    "POP_JUMP_FORWARD_IF_NONE",
    "POP_JUMP_BACKWARD_IF_NONE",
]

HAVE_ABS_REFERENCE = [
    # common
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_FALSE",
    "JUMP_ABSOLUTE",

    # 3.6 / 3.7
    "CONTINUE_LOOP",

    # 3.9
    "JUMP_IF_NOT_EXC_MATCH",
]

REL_REFERENCE_IS_INVERTED = [
    # 3.11
    "JUMP_BACKWARD",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "POP_JUMP_BACKWARD_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_FALSE",
    "POP_JUMP_BACKWARD_IF_NOT_NONE",
    "POP_JUMP_BACKWARD_IF_NONE",
]

if PYTHON_VERSION <= (3, 10):
  HAVE_ABS_REFERENCE.extend([
      "JUMP_IF_TRUE_OR_POP",
      "JUMP_IF_FALSE_OR_POP",
  ])
else:
  HAVE_REL_REFERENCE.extend([
      "JUMP_IF_TRUE_OR_POP",
      "JUMP_IF_FALSE_OR_POP",
  ])


# Returns -1 for instructions that have backward relative references
# (e.g. JUMP_BACKWARD, an instruction that uses a positive number to
# indicate a negative jump)
def rel_reference_scale(opname):
  assert opname in HAVE_REL_REFERENCE
  if opname in REL_REFERENCE_IS_INVERTED:
    return -1
  return 1


### Compare ops ###

REVERSE_CMP_OP = [4, 5, 2, 3, 0, 1]

### CodeTypes ###

if (3, 6) <= PYTHON_VERSION <= (3, 7):

  def get_code_object(
      code_obj, stacksize, bytecode, consts, names, lnotab, exceptiontable
  ):
    return types.CodeType(code_obj.co_argcount, code_obj.co_kwonlyargcount,
                          code_obj.co_nlocals, stacksize, code_obj.co_flags,
                          bytecode, consts, names, code_obj.co_varnames,
                          code_obj.co_filename, code_obj.co_name,
                          code_obj.co_firstlineno, lnotab, code_obj.co_freevars,
                          code_obj.co_cellvars)

elif (3, 8) <= PYTHON_VERSION <= (3, 10):

  def get_code_object(
      code_obj, stacksize, bytecode, consts, names, lnotab, exceptiontable
  ):
    return types.CodeType(code_obj.co_argcount, code_obj.co_posonlyargcount,
                          code_obj.co_kwonlyargcount, code_obj.co_nlocals,
                          stacksize, code_obj.co_flags, bytecode, consts, names,
                          code_obj.co_varnames, code_obj.co_filename,
                          code_obj.co_name, code_obj.co_firstlineno, lnotab,
                          code_obj.co_freevars, code_obj.co_cellvars)

else:

  def get_code_object(
      code_obj, stacksize, bytecode, consts, names, lnotab, exceptiontable
  ):
    return types.CodeType(
        code_obj.co_argcount,
        code_obj.co_posonlyargcount,
        code_obj.co_kwonlyargcount,
        code_obj.co_nlocals,
        stacksize,
        code_obj.co_flags,
        bytecode,
        consts,
        names,
        code_obj.co_varnames,
        code_obj.co_filename,
        code_obj.co_name,
        code_obj.co_qualname,
        code_obj.co_firstlineno,
        lnotab,
        exceptiontable,
        code_obj.co_freevars,
        code_obj.co_cellvars,
    )


### Python 3.10 uses instruction (2 byte) offsets rather than byte offsets ###

if PYTHON_VERSION >= (3, 10):

  def jump_arg_bytes(arg: int) -> int:
    return arg * 2

  def add_bytes_to_jump_arg(arg: int, size: int) -> int:
    return arg + size // 2
else:

  def jump_arg_bytes(arg: int) -> int:
    return arg

  def add_bytes_to_jump_arg(arg: int, size: int) -> int:
    return arg + size


### Lnotab/linetable handling ###

# In Python 3.10 lnotab was deprecated, context:
# 3.10 specific notes: https://github.com/python/cpython/blob/28b75c80dcc1e17ed3ac1c69362bf8dc164b760a/Objects/lnotab_notes.txt
# GitHub PR: https://github.com/python/cpython/commit/877df851c3ecdb55306840e247596e7b7805a60a
# Inspiration for the 3.10 code: https://github.com/python/cpython/blob/28b75c80dcc1e17ed3ac1c69362bf8dc164b760a/Python/compile.c#L5563
# It changes again in 3.11.


if (3, 6) <= PYTHON_VERSION <= (3, 9):
  def get_lnotab(code, listing):
    """Returns line number table."""
    lnotab = []
    current_lineno = listing[0].lineno
    i = 0

    assert listing[0].lineno >= code.co_firstlineno

    if listing[0].lineno > code.co_firstlineno:
      delta_lineno = listing[0].lineno - code.co_firstlineno

      while delta_lineno > 127:
        lnotab.extend([0, 127])
        delta_lineno -= 127

      lnotab.extend([0, delta_lineno])

    while True:
      delta_bc = 0

      while i < len(listing) and listing[i].lineno == current_lineno:
        delta_bc += listing[i].get_size()
        i += 1

      if i >= len(listing):
        break

      assert delta_bc > 0

      delta_lineno = listing[i].lineno - current_lineno

      while delta_bc > 255:
        lnotab.extend([255, 0])
        delta_bc -= 255

      if delta_lineno < 0:
        while delta_lineno < -128:
          lnotab.extend([delta_bc, 0x80])
          delta_bc = 0
          delta_lineno += 128

        delta_lineno %= 256
      else:
        while delta_lineno > 127:
          lnotab.extend([delta_bc, 127])
          delta_bc = 0
          delta_lineno -= 127

      lnotab.extend([delta_bc, delta_lineno])
      current_lineno = listing[i].lineno

    return bytes(lnotab)


if (3, 10) <= PYTHON_VERSION <= (3, 10):
  def get_lnotab(code, listing):
    """Returns line number table."""
    lnotab = []
    prev_lineno = listing[0].lineno

    for instr in listing:
      bdelta = instr.get_size()
      if bdelta == 0:
        continue
      ldelta = 0
      if instr.lineno < 0:
        ldelta = -128
      else:
        ldelta = instr.lineno - prev_lineno
        while ldelta > 127:
          lnotab.extend([0, 127])
          ldelta -= 127
        while ldelta < -127:
          lnotab.extend([0, -127 % 256])
          ldelta += 127
      assert -128 <= ldelta < 128
      ldelta %= 256
      while bdelta > 254:
        lnotab.extend([254, ldelta])
        ldelta = -128 % 256 if instr.lineno < 0 else 0
        bdelta -= 254
      lnotab.extend([bdelta, ldelta])
      prev_lineno = instr.lineno

    return bytes(lnotab)


if (3, 11) <= PYTHON_VERSION <= (3, 11):
  from .native import _generate_codetable
  def get_lnotab(code, listing):
    ret = _generate_codetable(code, listing)
    return ret

### exceptiontable handling ###

class ExceptionTableEntry:

  def __init__(self, start_offset, end_offset, target, depth, lasti):
    self.start_offset = start_offset
    self.end_offset = end_offset
    self.target = target
    self.depth = depth
    self.lasti = lasti

  def __repr__(self):
    return (
        f"(start_offset={self.start_offset} end_offset={self.end_offset} target={self.target} depth={self.depth} lasti={self.lasti})"
    )

  def __str__(self):
    return self.__repr__()

  def __eq__(self, other):
    return (
        self.start_offset == other.start_offset
        and self.end_offset == other.end_offset
        and self.target == other.target
        and self.depth == other.depth
        and self.lasti == other.lasti
    )


class ExceptionTable:

  def __init__(self, entries: List[ExceptionTableEntry]):
    self.entries = entries

  def __repr__(self):
    return "\n".join([repr(x) for x in self.entries])

  def __str__(self):
    return "\n".join([repr(x) for x in self.entries])

  def __eq__(self, other):
    if len(self.entries) != len(other.entries):
      return False
    for i in range(len(self.entries)):
      if self.entries[i] != other.entries[i]:
        return False
    return True

# Default implementations
# 3.11+ override these.
def generate_exceptiontable(original_code, exception_table_entries):
  return b""

def parse_exceptiontable(code):
  return ExceptionTable([])


if (3, 11) <= PYTHON_VERSION <= (3, 11):
  from .native import _generate_exceptiontable

  def generate_exceptiontable(original_code, exception_table_entries):
    return _generate_exceptiontable(original_code, exception_table_entries)

  def parse_exceptiontable(co_exceptiontable):
    if isinstance(co_exceptiontable, types.CodeType):
      return parse_exceptiontable(co_exceptiontable.co_exceptiontable)

    # These functions taken from:
    # https://github.com/python/cpython/blob/main/Objects/exception_handling_notes.txt
    def parse_varint(iterator):
      b = next(iterator)
      val = b & 63
      while b & 64:
        val <<= 6
        b = next(iterator)
        val |= b & 63
      return val

    def parse_exception_table(co_exceptiontable):
      iterator = iter(co_exceptiontable)
      try:
        while True:
          start = parse_varint(iterator) * 2
          length = parse_varint(iterator) * 2
          end = start + length - 2  # Present as inclusive, not exclusive
          target = parse_varint(iterator) * 2
          dl = parse_varint(iterator)
          depth = dl >> 1
          lasti = bool(dl & 1)
          yield start, end, target, depth, lasti
      except StopIteration:
        return

    entries = [
        ExceptionTableEntry(*x)
        for x in parse_exception_table(co_exceptiontable)
    ]
    return ExceptionTable(entries)


### Opcode compatibility ###
# These functions generate a series of (opcode, arg) tuples to represent the
# requested operation.

if (3, 6) <= PYTHON_VERSION <= (3, 10):

  # There are no CACHE instructions in these versions, so return 0.
  def cache_count(op):
    return 0

  # There are no CACHE instructions in these versions, so return empty list.
  def caches(op):
    return []

  # Rotate the top width_n instructions, shift_n times.
  def rot_n(width_n: int, shift_n: int = 1):
    if shift_n != 1:
      return RuntimeError("rot_n not supported with shift_n!=1. (Support could be emulated if needed.)")

    if width_n < 1:
      raise RuntimeError("Rotating by <1 does not make sense.")
    if width_n == 1:
      return []
    if width_n == 2:
      return [(dis.opmap["ROT_TWO"], 0)]
    if width_n == 3:
      return [(dis.opmap["ROT_THREE"], 0)]

    if PYTHON_VERSION < (3, 8):
      raise RuntimeError(
          "Only Python versions 3.8+ support rotations greater than three."
      )

    if width_n == 4:
      return [(dis.opmap["ROT_FOUR"], 0)]

    if PYTHON_VERSION < (3, 10):
      raise RuntimeError(
          "Only Python versions 3.10+ support rotations greater than four."
      )

    return [(dis.opmap["ROT_N"], width_n)]

  # 3.11+ needs a null terminator for the argument list, but 3.10- does not.
  def args_terminator():
    return []

  # In 3.10-, all you need to call a function is CALL_FUNCTION.
  def call(argc: int):
    return [(dis.opmap["CALL_FUNCTION"], argc)]

  # In 3.10-, each call pops 1 thing other than the arguments off the stack:
  # the callable itself.
  CALLABLE_STACK_ENTRIES = 1


if PYTHON_VERSION >= (3, 11):

  # The number of CACHE instructions that must go after the given instr.
  def cache_count(op):
    if isinstance(op, str):
      op = dis.opmap[op]

    return opcode._inline_cache_entries[op]

  # Generate a list of CACHE instructions for the given instr.
  def caches(op):
    cc = cache_count(op)
    return [(dis.opmap["CACHE"], 0)] * cc

  # Rotate the top width_n instructions, shift_n times.
  def rot_n(width_n: int, shift_n: int = 1):
    ret = []
    for j in range(shift_n):
      for i in range(width_n, 1, -1):
        ret.append([dis.opmap["SWAP"], i])
    return ret

  # Calling a free function in 3.11 requires a null terminator for the
  # args list on the stack.
  def args_terminator():
    return [(dis.opmap["PUSH_NULL"], 0)]

  # 3.11 requires a PRECALL instruction prior to every CALL instruction.
  def call(argc: int):
    ret = []
    ret.append((dis.opmap["PRECALL"], argc))
    ret.append((dis.opmap["CALL"], argc))
    return ret

  # A call pops 2 items off the stack in addition to the args: the callable
  # itself, and a null terminator.
  CALLABLE_STACK_ENTRIES = 2

### disassembler compatibility ###
# In 3.11, we need to pass show_caches=True.

if (3, 6) <= PYTHON_VERSION <= (3, 10):

  def get_instructions(x, *, first_line=None):
    return dis.get_instructions(x, first_line=first_line)


if (3, 11) <= PYTHON_VERSION:

  def get_instructions(x, *, first_line=None, adaptive=False):
    return dis.get_instructions(
        x, first_line=first_line, adaptive=adaptive, show_caches=True
    )
