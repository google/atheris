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
"""This module provides the instrumentation functionality for atheris.

Mainly the function patch_code(), which can instrument a code object and the
helper class Instrumentor.
"""
import ast
import collections
import dis
import gc
import itertools
import logging
import sys
import types
from typing import Any, Callable, Iterator, List, Optional, Sequence, Tuple, TypeVar, Union

from . import utils
from .native import _reserve_counter  # type: ignore[attr-defined]
from .version_dependent import add_bytes_to_jump_arg
from .version_dependent import args_terminator
from .version_dependent import cache_count
from .version_dependent import caches
from .version_dependent import call
from .version_dependent import CALLABLE_STACK_ENTRIES
from .version_dependent import CONDITIONAL_JUMPS
from .version_dependent import ENDS_FUNCTION
from .version_dependent import ExceptionTableEntry
from .version_dependent import generate_exceptiontable
from .version_dependent import get_code_object
from .version_dependent import get_instructions
from .version_dependent import get_lnotab
from .version_dependent import HAVE_ABS_REFERENCE
from .version_dependent import HAVE_REL_REFERENCE
from .version_dependent import jump_arg_bytes
from .version_dependent import parse_exceptiontable
from .version_dependent import REL_REFERENCE_IS_INVERTED
from .version_dependent import rel_reference_scale
from .version_dependent import REVERSE_CMP_OP
from .version_dependent import rot_n
from .version_dependent import UNCONDITIONAL_JUMPS

_TARGET_MODULE = "atheris"
_COVERAGE_FUNCTION = "_trace_branch"
_COMPARE_FUNCTION = "_trace_cmp"
_HOOK_STR_FUNCTION = "_hook_str"

# TODO(b/207008147): Use NewType to differentiate the many int and str types.


class Instruction:
  """A single bytecode instruction after every EXTENDED_ARG has been resolved.

  It is assumed that all instructions are always 2*n bytes long.

  Sometimes the Python-Interpreter pads instructions with 'EXTENDED_ARG 0'
  so instructions must have a minimum size.

  Attributes:
    lineno:
      Line number in the original source code.
    offset:
      Offset of an instruction in bytes.
    opcode:
      Integer identifier of the bytecode operation.
    mnemonic:
      Human readable name of the opcode.
    arg:
      Optional (default 0) argument to the instruction. This may index into
      CodeType.co_consts or it may be the address for jump instructions.
    reference:
      For jump instructions, the absolute address in bytes of the target. For
      other instructions, None.
  """

  @classmethod
  def get_fixed_size(cls) -> int:
    return 2

  def __init__(
      self,
      lineno: int,
      offset: int,
      opcode: int,
      arg: int = 0,
      min_size: int = 0,
      positions: Optional[List[ast.AST]] = None,
  ):
    self.lineno = lineno
    self.offset = offset
    self.opcode = opcode
    self.mnemonic = dis.opname[opcode]
    self.arg = arg
    self._min_size = min_size
    self.positions = positions

    if self.mnemonic in HAVE_REL_REFERENCE:
      self._is_relative: Optional[bool] = True
      self.reference: Optional[int] = (
          self.offset
          + self.get_size()
          + jump_arg_bytes(self.arg) * rel_reference_scale(self.mnemonic)
      )
    elif self.mnemonic in HAVE_ABS_REFERENCE:
      self._is_relative = False
      self.reference = jump_arg_bytes(self.arg)
    else:
      self._is_relative = None
      self.reference = None

    self.check_state()

  def __repr__(self) -> str:
    return (
        f"{self.mnemonic}(arg={self.arg} offset={self.offset} "
        + f"reference={self.reference} getsize={self.get_size()} positions={self.positions})"
    )

  def has_argument(self) -> bool:
    return self.opcode >= dis.HAVE_ARGUMENT

  def _get_arg_size(self) -> int:
    if self.arg >= (1 << 24):
      return 8
    elif self.arg >= (1 << 16):
      return 6
    elif self.arg >= (1 << 8):
      return 4
    else:
      return 2

  def get_size(self) -> int:
    return max(self._get_arg_size(), self._min_size)

  def get_stack_effect(self) -> int:
    # dis.stack_effect does not work for EXTENDED_ARG and NOP
    if self.mnemonic in ["EXTENDED_ARG", "NOP"]:
      return 0

    return dis.stack_effect(self.opcode,
                            (self.arg if self.has_argument() else None))

  def to_bytes(self) -> bytes:
    """Returns this instruction as bytes."""
    size = self._get_arg_size()
    arg = self.arg
    ret = [self.opcode, arg & 0xff]

    for _ in range(size // 2 - 1):
      arg >>= 8
      ret = [dis.opmap["EXTENDED_ARG"], arg & 0xff] + ret

    while len(ret) < self._min_size:
      ret = [dis.opmap["EXTENDED_ARG"], 0] + ret

    assert len(ret) == self.get_size()

    return bytes(ret)

  def adjust(self, changed_offset: int, size: int, keep_ref: bool) -> None:
    """Compensates the offsets in this instruction for a resize elsewhere.

    Relative offsets may be invalidated due to two main events:
        (1) Insertion of instructions
        (2) Change of size of a single, already existing instruction

    (1) Some instructions of size `size` (in bytes) have been inserted at offset
        `changed_offset` in the instruction listing.

    (2) An instruction at offset changed_offset` - 0.5 has increased in size.
        If `changed_offset` is self.offset + 0.5, then self has increased.

    Either way, adjust the current offset, reference and argument
    accordingly.

    TODO(aidenhall): Replace the pattern of using +0.5 as a sentinal.

    Args:
      changed_offset: The offset where instructions are inserted.
      size: The number of bytes of instructions inserted.
      keep_ref: if True, adjust our reference.
    """
    old_offset = self.offset
    old_reference = self.reference

    if old_offset < changed_offset < (old_offset + 1):
      if old_reference is not None:
        if self._is_relative:
          if self.mnemonic not in REL_REFERENCE_IS_INVERTED:
            self.reference += size  # type: ignore[operator]
          else:
            self.arg = add_bytes_to_jump_arg(self.arg, size)
        elif old_reference > old_offset:
          self.reference += size  # type: ignore[operator]
          self.arg = add_bytes_to_jump_arg(self.arg, size)

      return

    if changed_offset <= old_offset:
      self.offset += size

    if old_reference is not None:
      assert(self.reference is not None)  # appease mypy
      if not keep_ref:
        if changed_offset <= old_reference:
          self.reference += size  # type: ignore[operator]

        if self._is_relative:
          if self.mnemonic not in REL_REFERENCE_IS_INVERTED and (
              old_offset < changed_offset <= old_reference
          ):
            self.arg = add_bytes_to_jump_arg(self.arg, size)
          elif self.mnemonic in REL_REFERENCE_IS_INVERTED and (
              old_offset >= changed_offset >= old_reference
          ):
            self.arg = add_bytes_to_jump_arg(self.arg, size)
        else:
          if changed_offset <= old_reference:
            self.arg = add_bytes_to_jump_arg(self.arg, size)
      else:
        if self._is_relative and self.mnemonic in REL_REFERENCE_IS_INVERTED:
          zero = self.offset + self.get_size()
          self.arg = add_bytes_to_jump_arg(0, abs(self.reference - zero))

  def check_state(self) -> None:
    """Asserts that internal state is consistent."""
    assert self.mnemonic != "EXTENDED_ARG"
    assert 0 <= self.arg <= 0x7fffffff
    assert 0 <= self.opcode < 256

    if self.reference is not None:
      if self._is_relative:
        assert (
            self.offset
            + self.get_size()
            + jump_arg_bytes(self.arg) * rel_reference_scale(self.mnemonic)
            == self.reference
        )
      else:
        assert jump_arg_bytes(self.arg) == self.reference

  def is_jump(self) -> bool:
    return self.mnemonic in CONDITIONAL_JUMPS or self.mnemonic in UNCONDITIONAL_JUMPS

  def make_nop(self) -> None:
    self.opcode = dis.opmap["NOP"]
    self.mnemonic = "NOP"
    self.arg = 0
    self._is_relative = None
    self.reference = None
    self.check_state()

  def cache_count(self) -> int:
    return cache_count(self.opcode)


class BasicBlock:
  """A block of bytecode instructions and the adresses it may jump to."""

  def __init__(self, instructions: List[Instruction], last_one: bool):
    self.instructions = instructions
    self.id = instructions[0].offset

    last_instr = instructions[-1]

    if last_one or last_instr.mnemonic in ENDS_FUNCTION:
      self.edges = []
    elif last_instr.mnemonic in CONDITIONAL_JUMPS:
      self.edges = list(
          {last_instr.reference, last_instr.offset + last_instr.get_size()})
    else:
      if last_instr.reference is not None:
        self.edges = [last_instr.reference]
      else:
        self.edges = [last_instr.offset + last_instr.get_size()]

  def __iter__(self) -> Iterator[Instruction]:
    return iter(self.instructions)

  def __repr__(self) -> str:
    return (f"BasicBlock(id={self.id}, edges={self.edges}, " +
            f"instructions={self.instructions})")


_SizeAndInstructions = Tuple[int, List[Instruction]]


class Instrumentor:
  """Implements the core instrumentation functionality.

  It gets a single code object, builds a CFG of the bytecode and
  can instrument the code for coverage collection via trace_control_flow()
  and for data-flow tracing via trace_data_flow().

  How to insert code:
      1. Select a target basic block
      2. Build up the new code as a list of `Instruction` objects.
          Make sure to get the offsets right.
      3. Calculate the overall size needed by your new code (in bytes)
      4. Call _adjust() with your target offset and calculated size
      5. Insert your instruction list into the instruction list of the basic
      block
      6. Call _handle_size_changes()
  Take a look at trace_control_flow() and trace_data_flow() for examples.

  Note that Instrumentor only supports insertions, not deletions.
  """

  def __init__(self, code: types.CodeType):
    self._cfg: collections.OrderedDict = collections.OrderedDict()
    self.consts = list(code.co_consts)
    self._names = list(code.co_names)
    self.num_counters = 0
    self._code = code

    self._build_cfg()
    self._check_state()

  def _insert_instruction(self, to_insert: List[Instruction], lineno: int, offset: int, opcode: int, arg: int = 0) -> int:
    to_insert.append(Instruction(lineno, offset, opcode, arg))
    offset += to_insert[-1].get_size()
    return self._insert_instructions(to_insert, lineno, offset, caches(opcode))

  def _insert_instructions(self, to_insert: List[Instruction], lineno: int, offset: int, tuples: List[Sequence[int]]) -> int:
    for t in tuples:
      offset = self._insert_instruction(to_insert, lineno, offset, t[0], t[1])
    return offset

  def _build_cfg(self) -> None:
    """Builds control flow graph."""
    lineno = self._code.co_firstlineno
    arg = None
    offset = None
    length = Instruction.get_fixed_size()
    instr_list = []
    basic_block_borders = []
    did_jump = False
    jump_targets = set()

    self.exception_table = parse_exceptiontable(self._code)

    for instruction in get_instructions(self._code):
      if instruction.starts_line is not None:
        lineno = instruction.starts_line

      if instruction.opname == "EXTENDED_ARG":
        if arg is None:
          arg = 0
          offset = instruction.offset

        arg <<= 8
        arg |= instruction.arg  # type: ignore[operator]
        length += Instruction.get_fixed_size()  # type: ignore[operator]

        continue

      elif arg is not None:
        assert offset is not None
        combined_arg = 0
        # https://bugs.python.org/issue45757 can cause .arg to be None
        if instruction.arg is not None:
          combined_arg = (arg << 8) | instruction.arg  # type: ignore[operator]
        instr_list.append(
            Instruction(
                lineno,
                offset,
                instruction.opcode,
                combined_arg,
                min_size=length,
                positions=getattr(instruction, "positions", None),
            )
        )
        arg = None
        offset = None
        length = Instruction.get_fixed_size()

      else:
        instr_list.append(
            Instruction(
                lineno,
                instruction.offset,
                instruction.opcode,
                instruction.arg or 0,
                positions=getattr(instruction, "positions", None),
            )
        )

      if instr_list[-1].reference is not None:
        jump_targets.add(instr_list[-1].reference)

    for c, instr in enumerate(instr_list):
      if instr.offset == 0 or instr.offset in jump_targets or did_jump:
        basic_block_borders.append(c)

      if instr.is_jump():
        did_jump = True
      else:
        did_jump = False

    basic_block_borders.append(len(instr_list))

    for i in range(len(basic_block_borders) - 1):
      start_of_bb = basic_block_borders[i]
      end_of_bb = basic_block_borders[i + 1]
      bb = BasicBlock(instr_list[start_of_bb:end_of_bb],
                      i == len(basic_block_borders) - 2)
      self._cfg[bb.id] = bb

  def _check_state(self) -> None:
    """Asserts that the Instrumentor is in a valid state."""
    assert self._cfg, "Control flow graph empty."
    seen_ids = set()

    for basic_block in self._cfg.values():
      assert basic_block.instructions, "BasicBlock has no instructions."

      assert basic_block.id not in seen_ids
      seen_ids.add(basic_block.id)

      for edge in basic_block.edges:
        assert edge in self._cfg, (
            f"{basic_block} has an edge, {edge}, not in CFG {self._cfg}.")

    listing = self._get_linear_instruction_listing()
    i = 0

    assert listing[0].offset == 0

    while i < len(listing) - 1:
      assert (listing[i].offset + listing[i].get_size() == listing[i +
                                                                   1].offset)
      listing[i].check_state()
      i += 1

  def _get_name(self, name: str) -> int:
    """Returns an offset to `name` in co_names, appending if necessary."""
    try:
      return self._names.index(name)
    except ValueError:
      self._names.append(name)
      return len(self._names) - 1

  def _get_const(self, constant: Union[int, str, types.ModuleType]) -> int:
    """Returns the index of `constant` in self.consts, inserting if needed."""
    for i in range(len(self.consts)):
      if isinstance(self.consts[i],
                    type(constant)) and self.consts[i] == constant:
        return i

    self.consts.append(constant)
    return len(self.consts) - 1

  def _get_counter(self) -> int:
    counter = _reserve_counter()
    return self._get_const(counter)

  def _adjust(self, offset: float, size: int, *keep_refs: str) -> None:
    """Adjust for `size` bytes of instructions inserted at `offset`.

    Signal all instructions that some instructions of size `size` (in bytes)
    will be inserted at offset `offset`. Sometimes it is necessary that some
    instructions do not change their reference when a new insertion happens.

    All those Instruction-objects whose reference shall not change must be
    in `keep_refs`.

    Args:
      offset: Location that new instructions are inserted at
      size: How many bytes of new instructions are being inserted.
      *keep_refs: The Instructions whose reference shall not change.
    """
    for basic_block in self._cfg.values():
      for instr in basic_block:
        instr.adjust(offset, size, instr in keep_refs)

    entry: ExceptionTableEntry
    for entry in self.exception_table.entries:
      if entry.start_offset > offset:
        entry.start_offset += size
      if entry.end_offset >= offset:
        entry.end_offset += size
      if entry.target > offset:
        entry.target += size

  def _handle_size_changes(self) -> None:
    """Fixes instructions who's size increased with the last insertion.

    After insertions have been made it could be that the argument of some
    instructions crossed certain boundaries so that more EXTENDED_ARGs are
    required to build the oparg. This function identifies all of those
    instructions whose size increased with the latest insertion and adjusts all
    other instructions to the new size.
    """
    listing = self._get_linear_instruction_listing()

    while True:
      found_invalid = False
      i = 0

      while i < len(listing) - 1:
        next_offset = listing[i].offset + listing[i].get_size()

        assert next_offset >= listing[i + 1].offset, (
            "Something weird happened with the offsets at offset " +
            f"{listing[i].offset}")

        if next_offset > listing[i + 1].offset:
          delta = next_offset - listing[i + 1].offset
          self._adjust(listing[i].offset + 0.5, delta)
          found_invalid = True

        i += 1

      if not found_invalid:
        break

  def _get_linear_instruction_listing(self) -> List[Instruction]:
    return list(itertools.chain.from_iterable(self._cfg.values()))

  def to_code(self) -> types.CodeType:
    """Returns the instrumented code object."""
    self._check_state()
    listing = self._get_linear_instruction_listing()
    code = bytes()
    stacksize = 0

    for instr in listing:
      code += instr.to_bytes()
      stacksize = max(stacksize, stacksize + instr.get_stack_effect())

    co_exceptiontable = generate_exceptiontable(
        self._code, self.exception_table.entries
    )

    return get_code_object(
        self._code,
        stacksize,
        code,
        tuple(self.consts + ["__ATHERIS_INSTRUMENTED__"]),
        tuple(self._names),
        get_lnotab(self._code, listing),
        co_exceptiontable,
    )

  def _generate_trace_branch_invocation(self, lineno: int,
                                        offset: int) -> _SizeAndInstructions:
    """Builds the bytecode that calls atheris._trace_branch()."""
    to_insert = []  # type: List[Instruction]
    start_offset = offset
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cov = self._get_name(_COVERAGE_FUNCTION)

    offset = self._insert_instructions(
        to_insert, lineno, offset, args_terminator()
    )

    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_atheris
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_ATTR"], name_cov
    )

    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], self._get_counter()
    )

    offset = self._insert_instructions(to_insert, lineno, offset, call(1))
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["POP_TOP"], 0
    )

    return offset - start_offset, to_insert

  def _generate_cmp_invocation(self, op: int, lineno: int,
                               offset: int) -> _SizeAndInstructions:
    """Builds the bytecode that calls atheris._trace_cmp().

    Only call this if the two objects being compared are non-constants.

    Args:
      op: The comparison operation
      lineno: The line number of the operation
      offset: The offset to the operation instruction

    Returns:
      The size of the instructions to insert,
      The instructions to insert
    """
    to_insert = []  # type: List[Instruction]
    start_offset = offset
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cmp = self._get_name(_COMPARE_FUNCTION)
    const_op = self._get_const(op)
    const_counter = self._get_counter()
    const_false = self._get_const(False)

    offset = self._insert_instructions(
        to_insert, lineno, offset, args_terminator()
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_atheris
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_ATTR"], name_cmp
    )
    rot = rot_n(2 + CALLABLE_STACK_ENTRIES, CALLABLE_STACK_ENTRIES)
    offset = self._insert_instructions(to_insert, lineno, offset, rot)

    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_op
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_counter
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_false
    )

    offset = self._insert_instructions(to_insert, lineno, offset, call(5))

    return offset - start_offset, to_insert

  def _generate_const_cmp_invocation(self, op: int, lineno: int, offset: int,
                                     switch: bool) -> _SizeAndInstructions:
    """Builds the bytecode that calls atheris._trace_cmp().

    Only call this if one of the objects being compared is a constant coming
    from co_consts. If `switch` is true the constant is the second argument and
    needs to be switched with the first argument.

    Args:
      op: The comparison operation.
      lineno: The line number of the operation
      offset: The initial number of instructions.
      switch: bool whether the second arg is constant instead of the first.

    Returns:
      The number of bytes to insert, and the instructions.
    """
    to_insert = []  # type: List[Instruction]
    start_offset = offset
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cmp = self._get_name(_COMPARE_FUNCTION)
    const_counter = self._get_counter()
    const_true = self._get_const(True)
    const_op = None

    if switch:
      const_op = self._get_const(REVERSE_CMP_OP[op])
    else:
      const_op = self._get_const(op)

    offset = self._insert_instructions(
        to_insert, lineno, offset, args_terminator()
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_atheris
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_ATTR"], name_cmp
    )
    rot = rot_n(2 + CALLABLE_STACK_ENTRIES, CALLABLE_STACK_ENTRIES)
    offset = self._insert_instructions(to_insert, lineno, offset, rot)

    if switch:
      offset = self._insert_instructions(to_insert, lineno, offset, rot_n(2))

    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_op
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_counter
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_true
    )

    offset = self._insert_instructions(to_insert, lineno, offset, call(5))

    return offset - start_offset, to_insert

  def _generate_hook_str_invocation(
      self, str_method: str, lineno: int, offset: int
  ) -> _SizeAndInstructions:
    """Builds the bytecode that loads in and sets up atheris._trace_str().

    Args:
      str_method: The str method
      lineno: The line number of the operation
      offset: The offset to the operation instruction

    Returns:
      The size of the instructions to insert,
      The instructions to insert
    """
    to_insert = []  # type: List[Instruction]
    start_offset = offset
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_hook_str = self._get_name(_HOOK_STR_FUNCTION)
    const_str_method = self._get_const(str_method)

    offset = self._insert_instructions(
        to_insert, lineno, offset, args_terminator()
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_atheris
    )
    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_ATTR"], name_hook_str
    )
    # Put self argument at the top
    rot = rot_n(1 + CALLABLE_STACK_ENTRIES, CALLABLE_STACK_ENTRIES)
    offset = self._insert_instructions(to_insert, lineno, offset, rot)

    offset = self._insert_instruction(
        to_insert, lineno, offset, dis.opmap["LOAD_CONST"], const_str_method
    )

    return offset - start_offset, to_insert

  def _generate_call(
      self, opname: str, num_args: int, lineno: int, offset: int
  ) -> _SizeAndInstructions:
    """Builds the bytecode that makes the function call to atheris._trace_str().

    Args:
      opname: The opname that is being replaced
      num_args: The number of args that are passed in
      lineno: The line number of the operation
      offset: The offset to the operation instruction

    Returns:
      The size of the instructions to insert,
      The instructions to insert
    """
    to_insert = []  # type: List[Instruction]
    start_offset = offset

    if opname == "CALL_FUNCTION_KW":
      offset = self._insert_instruction(
          to_insert, lineno, offset, dis.opmap["CALL_FUNCTION_KW"], num_args
      )
    else:
      offset = self._insert_instructions(
          to_insert, lineno, offset, call(num_args)
      )

    return offset - start_offset, to_insert

  def trace_control_flow(self) -> None:
    """Insert a call to atheris._trace_branch() branch's target block.

    The argument of _trace_branch() is an id for the branch.

    The following bytecode gets inserted:
      LOAD_CONST     atheris
      LOAD_ATTR      _trace_branch
      LOAD_CONST     <id>
      CALL_FUNCTION  1
      POP_TOP                  ; _trace_branch() returns None, remove the
      return value
    """
    already_instrumented = set()

    # Insert at the first point after a RESUME instruction
    first_real_instr = None
    first_real_instr_slot = None
    for i in range(len(self._cfg[0].instructions)):
      bb_instr = self._cfg[0].instructions[i]
      if bb_instr.mnemonic not in ("RESUME", "GEN_START"):
        first_real_instr = bb_instr
        first_real_instr_slot = i
        break

    if first_real_instr is None:
      # This was an empty code object (e.g. empty module)
      return
    assert first_real_instr_slot is not None

    total_size, to_insert = self._generate_trace_branch_invocation(
        first_real_instr.lineno, first_real_instr.offset
    )
    self._adjust(first_real_instr.offset, total_size)
    self._cfg[0].instructions = (
        self._cfg[0].instructions[0:first_real_instr_slot]
        + to_insert
        + self._cfg[0].instructions[first_real_instr_slot:]
    )

    for basic_block in self._cfg.values():
      # A condition needs two edges
      if len(basic_block.edges) != 2:
        continue

      for edge in basic_block.edges:
        bb = self._cfg[edge]

        if bb.id in already_instrumented:
          continue

        already_instrumented.add(bb.id)
        source_instr = []
        offset = bb.instructions[0].offset

        for source_bb in self._cfg.values():
          if bb.id in source_bb.edges and source_bb.instructions[
              -1].reference == offset:
            source_instr.append(source_bb.instructions[-1])

        total_size, to_insert = self._generate_trace_branch_invocation(
            bb.instructions[0].lineno, offset)

        self._adjust(offset, total_size, *source_instr)

        bb.instructions = to_insert + bb.instructions

    self._handle_size_changes()

  def trace_data_flow(self) -> None:
    """Instruments bytecode for data-flow tracing.

    This works by replacing the instruction COMPARE_OP with a call to
    atheris._trace_cmp(). The arguments for _trace_cmp() are as follows:
        - obj1 and obj2: The two values to compare
        - opid: argument to COMPARE_OP
        - counter: The counter for this comparison.
        - is_const: whether obj1 is a constant in co_consts.

    To detect if any of the values being compared is a constant, all push and
    pop operations have to be analyzed. If a constant appears in a comparison it
    must always be given as obj1 to _trace_cmp().

    The bytecode that gets inserted looks like this:
      LOAD_CONST     atheris
      LOAD_ATTR      _trace_cmp
      ROT_THREE                   ; move atheris._trace_cmp below the two
      objects
      LOAD_CONST     <opid>
      LOAD_CONST     <counter index>
      LOAD_CONST     <is_const>
      CALL_FUNCTION  5
    """
    stack_size = 0
    seen_consts = []

    for basic_block in self._cfg.values():
      for c, instr in enumerate(basic_block.instructions):
        if instr.mnemonic == "LOAD_CONST":
          seen_consts.append(stack_size)
        elif instr.mnemonic == "COMPARE_OP" and instr.arg <= 5:
          # If the instruction has CACHEs afterward, we'll need to NOP them too.
          instr_caches = []
          for i in range(c + 1, c + 1 + cache_count(instr.mnemonic)):
            instr_caches.append(basic_block.instructions[i])

          # Determine the two values on the top of the stack before COMPARE_OP
          consts_on_stack = [
              c for c in seen_consts if stack_size - 2 <= c < stack_size
          ]
          tos_is_constant = stack_size - 1 in consts_on_stack
          tos1_is_constant = stack_size - 2 in consts_on_stack

          if not (tos_is_constant and tos1_is_constant):
            offset = instr.offset
            total_size = None
            to_insert = None

            # Both items are non-constants
            if (not tos_is_constant) and (not tos1_is_constant):
              total_size, to_insert = self._generate_cmp_invocation(
                  instr.arg, instr.lineno, offset)

            # One item is constant, one is non-constant
            else:
              total_size, to_insert = self._generate_const_cmp_invocation(
                  instr.arg, instr.lineno, offset, tos_is_constant)

            self._adjust(offset, total_size)

            for i, new_instr in enumerate(to_insert):
              basic_block.instructions.insert(c + i, new_instr)
            # Need to account for stack size effect of 0th new instruction
            stack_size += basic_block.instructions[c].get_stack_effect()

            instr.make_nop()
            for cache_instr in instr_caches:
              cache_instr.make_nop()

        stack_size += instr.get_stack_effect()
        seen_consts = [c for c in seen_consts if c < stack_size]

    self._handle_size_changes()

  def _is_str_hookable(
      self,
      instr: Instruction,
      remaining_instructions: List[Instruction],
      stack_size: int,
  ) -> bool:
    """Checks whether current method should be patched.

    We need to see if instr has the name of a method that we are hooking. We
    also need to verify that the method is called with a valid call instruction.
    Since we don't support hooking str methods when variable args are passed in,
    we also check for this.

    Args:
      instr: The instruction being checked
      remaining_instructions: The rest of the instructions in the basic block
      stack_size: The current stack size when instr was encountered

    Returns:
      Whether the current method should be patched
    """
    if not (
        instr.mnemonic in ("LOAD_ATTR", "LOAD_METHOD")
        and self._names[instr.arg] in ("startswith", "endswith")
    ):
      return False

    # Check to see what call instruction variant is used to call this method
    method_stack_size = stack_size + instr.get_stack_effect()
    temp_stack_size = method_stack_size
    i = 0
    while (temp_stack_size >= method_stack_size) and i < len(
        remaining_instructions
    ):
      temp_instr = remaining_instructions[i]

      # Don't patch methods called with variable arguments
      if (
          temp_instr.mnemonic == "CALL_FUNCTION_EX"
          and temp_stack_size - (temp_instr.arg & 0x01) - 1 == method_stack_size
      ):
        logging.warning(
            "Tracing str methods does not work when variable args are passed in"
        )
        return False
      # Need to check that we are working with a valid callable instead of just
      # a property
      elif self._is_call_replaceable(
          temp_instr,
          [method_stack_size - 1],  # -1 to get 0-indexed stack position
          temp_stack_size,
          num_new_args_inserted=0,
      ):
        return True

      temp_stack_size += temp_instr.get_stack_effect()
      i += 1

    # No associated call instruction was encountered
    return False

  def _is_call_replaceable(
      self,
      instr: Instruction,
      traced_methods: List[int],
      stack_size: int,
      num_new_args_inserted: int,
  ) -> bool:
    """Checks whether current instruction is a call instruction to be replaced.

    Since there are different call instruction variations depending on the way
    the args were passed in the original method, we need to check for them all.
    We also need to check that the call instruction corresponds to a method that
    is being traced.

    Args:
      instr: The instruction being checked
      traced_methods: The list of methods to be traced
      stack_size: The current size of the stack
      num_new_args_inserted: The number of new function arguments inserted

    Returns:
      Whether the current instruction is a call instruction that should be
      replaced
    """
    method_stack_position = None
    if instr.mnemonic in ("PRECALL", "CALL_METHOD", "CALL_FUNCTION"):
      method_stack_position = stack_size - instr.arg - num_new_args_inserted - 1
    elif instr.mnemonic == "CALL_FUNCTION_KW":
      method_stack_position = stack_size - instr.arg - num_new_args_inserted - 2

    return method_stack_position in traced_methods

  def trace_str_flow(self) -> None:
    """Instruments bytecode for tracing calls to str methods.

    Note that this function can be generalized to instrumenting other method
    calls in the future.

    This function is experimental.

    This function does not patch code whenever the str methods are called with
    variable arguments.

    This works by replacing the instruction LOAD_ATTR or LOAD_METHOD that also
    has oneof arg (startswith, endswith) with a call to hook_str().
    The arguments for hook_str() are as follows:
        - self: The value that the original method was called by
        - str_method: Name of the str method
        - *args

    The bytecode that gets inserted looks like this:
      LOAD_CONST     atheris
      LOAD_ATTR      _trace_str
      ROT_TWO                     ; move atheris._trace_str below arg
      LOAD_CONST     <str_method>

    Additionally, the associated method call instructions are replaced with
    a function call instruction.
    """
    stack_size = 0
    seen_consts = []
    # Keeps track of stack positions of traced methods so that the associated
    # call instructions can be identified properly
    traced_methods = []
    for basic_block in self._cfg.values():
      for c, instr in enumerate(basic_block.instructions):
        offset = instr.offset
        total_size = None
        to_insert = None

        instrs_to_nop = []

        if instr.mnemonic == "LOAD_CONST":
          seen_consts.append(stack_size)
        # This hooks all method calls, not just the str ones
        elif self._is_str_hookable(
            instr,
            remaining_instructions=basic_block.instructions[c + 1:],
            stack_size=stack_size,
        ):
          # Determine the value on the top of the stack
          const_on_tos = [c for c in seen_consts if c == stack_size - 1]
          tos_is_constant = stack_size - 1 in const_on_tos

          # Only trace when self is non-constant (ex. of self being
          # constant: "hello".startswith("he"))
          if not tos_is_constant:
            callable_extra_stack_effect = CALLABLE_STACK_ENTRIES - 2
            true_stack_position = stack_size + callable_extra_stack_effect
            traced_methods.append(true_stack_position)

            str_method = self._names[instr.arg]

            total_size, to_insert = self._generate_hook_str_invocation(
                str_method, instr.lineno, offset
            )
        # Need to also replace the call instruction, since we replaced the
        # original method with our _hook_str function and added the 2 arguments:
        # self (the original method caller) and the str method name
        elif self._is_call_replaceable(
            instr, traced_methods[-1:], stack_size, num_new_args_inserted=2
        ):
          # Just replaced the method, so don't keep track of it anymore
          traced_methods.pop()

          # PRECALL instruction requires extra logic because we also need to
          # nop the following CALL instruction
          if instr.mnemonic == "PRECALL":
            call_instr_idx = c + 1
            while basic_block.instructions[call_instr_idx].mnemonic != "CALL":
              call_instr_idx += 1
            call_instr = basic_block.instructions[call_instr_idx]
            instrs_to_nop.append(call_instr)
            for i in range(
                call_instr_idx + 1,
                call_instr_idx + 1 + cache_count(call_instr.mnemonic),
            ):
              instrs_to_nop.append(basic_block.instructions[i])

          new_arg_count = instr.arg + 2
          total_size, to_insert = self._generate_call(
              instr.mnemonic, new_arg_count, instr.lineno, offset
          )

        # Here we actually insert the new instructions and nop the old ones
        if to_insert:
          instrs_to_nop.append(instr)
          # If the instruction has CACHEs afterward, we'll need to NOP them too.
          for i in range(c + 1, c + 1 + cache_count(instr.mnemonic)):
            instrs_to_nop.append(basic_block.instructions[i])

          self._adjust(offset, total_size)

          for i, new_instr in enumerate(to_insert):
            basic_block.instructions.insert(c + i, new_instr)
          # Need to account for stack size effect of 0th new instruction
          stack_size += basic_block.instructions[c].get_stack_effect()

          for instr_to_nop in instrs_to_nop:
            instr_to_nop.make_nop()

        stack_size += instr.get_stack_effect()
        seen_consts = [c for c in seen_consts if c < stack_size]
        traced_methods = [m for m in traced_methods if m < stack_size]

    self._handle_size_changes()

  def _print_disassembly(self) -> None:
    """Prints disassembly."""
    print(f"Disassembly of {self._code.co_filename}:{self._code.co_name}")
    for basic_block in self._cfg.values():
      print(" -bb-")
      for instr in basic_block:
        print(f" L.{instr.lineno}  [{instr.offset}]  {instr.mnemonic} ", end="")

        if instr.has_argument():
          print(f"{instr.arg} ", end="")

          if instr._is_relative:
            print(f"(to {instr.reference})", end="")

        print()


def patch_code(code: types.CodeType,
               trace_dataflow: bool,
               nested: bool = False) -> types.CodeType:
  """Returns code, patched with Atheris instrumentation.

  Args:
    code: The byte code to instrument.
    trace_dataflow: Whether to trace dataflow or not.
    nested: If False, reserve counters, and patch modules. Recursive calls to
      this function are considered nested.
  """
  inst = Instrumentor(code)

  # If this code object has already been instrumented, skip it
  for const in inst.consts:
    # This avoids comparison between str and bytes (BytesWarning).
    if isinstance(const, str) and const == "__ATHERIS_INSTRUMENTED__":
      return code

  inst.trace_control_flow()

  if trace_dataflow:
    inst.trace_data_flow()
    # Note that the user still needs to add "str" to enabled_hooks to actually
    # enable tracing
    inst.trace_str_flow()

  # Repeat this for all nested code objects
  for i in range(len(inst.consts)):
    if isinstance(inst.consts[i], types.CodeType):
      if (inst.consts[i].co_name == "<lambda>" or
          (not nested and inst.consts[i].co_name == "<module>") or
          inst.consts[i].co_name[0] != "<" or
          inst.consts[i].co_name[-1] != ">"):
        inst.consts[i] = patch_code(inst.consts[i], trace_dataflow, nested=True)

  return inst.to_code()


T = TypeVar("T")


def instrument_func(func: Callable[..., T]) -> Callable[..., T]:
  """Add Atheris instrumentation to a specific function."""
  func.__code__ = patch_code(func.__code__, True, True)

  return func


def _is_instrumentable(obj: Any) -> bool:
  """Returns True if this object can be instrumented."""
  try:
    # Only callables can be instrumented
    if not hasattr(obj, "__call__"):
      return False
    # Only objects with a __code__ member of type CodeType can be instrumented
    if not hasattr(obj, "__code__"):
      return False
    if not isinstance(obj.__code__, types.CodeType):
      return False
    # Only code in a real module can be instrumented
    if not hasattr(obj, "__module__"):
      return False
    if obj.__module__ not in sys.modules:
      return False
    # Bound methods can't be instrumented - instrument the real func instead
    if hasattr(obj, "__self__"):
      return False
    # Only Python functions and methods can be instrumented, nothing native
    if (not isinstance(obj, types.FunctionType)) and (not isinstance(
        obj, types.MethodType)):
      return False
  except Exception:  # pylint: disable=broad-except
    # If accessing any of those fields produced an exception, the object
    # probably can't be instrumented
    return False

  return True


def instrument_all() -> None:
  """Add Atheris instrementation to all Python code already imported.

  This function is experimental.

  This function is able to instrument core library functions that can't be
  instrumented by instrument_func or instrument_imports, as those functions are
  used in the implementation of the instrumentation.
  """
  progress_renderer = None

  funcs = [obj for obj in gc.get_objects() if _is_instrumentable(obj)]
  if sys.stderr.isatty():
    sys.stderr.write("INFO: Instrumenting functions: ")
    progress_renderer = utils.ProgressRenderer(sys.stderr, len(funcs))
  else:
    sys.stderr.write(f"INFO: Instrumenting {len(funcs)} functions...\n")

  for i in range(len(funcs)):
    func = funcs[i]
    try:
      instrument_func(func)
    except Exception as e:  # pylint: disable=broad-except
      if progress_renderer:
        progress_renderer.drop()
      sys.stderr.write(f"ERROR: Failed to instrument function {func}: {e}\n")
    if progress_renderer:
      progress_renderer.count = i + 1

  if progress_renderer:
    progress_renderer.drop()
  else:
    print("INFO: Instrumentation complete.")
