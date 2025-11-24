# Copyright 2025 Google LLC
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
import collections
import dataclasses
import dis
import gc
import sys
import types
from typing import Any, Callable, List, Set, TypeVar, Union

from . import utils
from .version_dependent import args_terminator_after_callable
from .version_dependent import args_terminator_before_callable
from .version_dependent import cache_count
from .version_dependent import cache_info
from .version_dependent import call
from .version_dependent import CALLABLE_STACK_ENTRIES
from .version_dependent import CMP_OP_SHIFT_AMOUNT
from .version_dependent import CONDITIONAL_JUMPS
from .version_dependent import ExceptionTable
from .version_dependent import ExceptionTableEntry
from .version_dependent import generate_exceptiontable
from .version_dependent import get_code_object
from .version_dependent import get_instructions
from .version_dependent import get_lnotab
from .version_dependent import get_name
from .version_dependent import HAVE_ABS_REFERENCE
from .version_dependent import HAVE_REL_REFERENCE
from .version_dependent import INSERT_AFTER_INSTRS
from .version_dependent import jump_arg_bytes
from .version_dependent import offset_delta_to_jump_arg
from .version_dependent import parse_exceptiontable
from .version_dependent import rel_reference_scale
from .version_dependent import requires_bool_coersion
from .version_dependent import REVERSE_CMP_OP
from .version_dependent import rot_n

_TARGET_MODULE = "atheris"
_COVERAGE_FUNCTION = "_trace_branch"
_COMPARE_FUNCTION = "_trace_cmp"
_HOOK_STR_FUNCTION = "_hook_str"

# Debugging tool. If set to a list of integers, only instrument the blocks
# at that index.
debug_instrument_only_blocks: List[int] | None = None


class UncalculatedArgSentinel:
  """Tracks args with values that need to be calculated.

  Used for jump instructions to indicate that we don't know the exact arg value
  yet - it depends on the offset where the destination ends up.
  """

  def __eq__(self, other):
    if isinstance(other, UncalculatedArgSentinel):
      return True
    if self is other:
      return True
    raise AssertionError(
        "Attempt to use the argument of a jump instruction directly. Use"
        " .reference instead."
    )

  def __ne__(self, other):
    return not self.__eq__(other)


_UncalculatedArgSentinel = UncalculatedArgSentinel()


@dataclasses.dataclass
class Instruction:
  """A single instruction.

  EXTENDED_ARGs and CACHEs are not represented as their own instructions.
  """

  opcode: int
  arg: int | None | UncalculatedArgSentinel
  positions: dis.Positions | None
  reference: Union["Instruction", None] = None
  referers: List["Instruction"] = dataclasses.field(default_factory=list)
  exceptiontable_referers: List["ReferenceExceptionTableEntry"] = (
      dataclasses.field(default_factory=list)
  )
  # This instruction appears before the first function RESUME.
  before_resume: bool = False

  # used for __repr__ to allow the instruction to know its own index
  full_instruction_list: List["Instruction"] = dataclasses.field(
      default_factory=list
  )

  @property
  def mnemonic(self) -> str:
    return dis.opname[self.opcode]

  @mnemonic.setter
  def mnemonic(self, value: str):
    self.opcode = dis.opmap[value]

  @property
  def length(self) -> int:
    """Returns the number of true instructions in this instruction.

    Includes EXTENDED_ARGs and CACHEs.
    """
    ret: int = 1
    ret += cache_count(self.mnemonic)
    if self.arg is not None and self.arg is not _UncalculatedArgSentinel:
      if self.arg > 2**8 - 1:
        ret += 1
      if self.arg > 2**16 - 1:
        ret += 1
      if self.arg > 2**24 - 1:
        ret += 1
    return ret

  @property
  def size(self) -> int:
    """Returns the number of bytes taken up by this instruction.

    Includes EXTENDED_ARGs and CACHEs.
    """
    return self.length * Instruction.get_fixed_size()

  def _get_arg_size(self) -> int:
    """Get the number of bytes taken up by this instruction + EXTENDED_ARGs."""
    if self.arg is None:
      return 2
    if self.arg is _UncalculatedArgSentinel:
      raise ValueError(
          "Attempt to get the arg-size of an instruction with an uncalculated"
          " arg."
      )
    if self.arg >= (1 << 24):
      return 8
    elif self.arg >= (1 << 16):
      return 6
    elif self.arg >= (1 << 8):
      return 4
    else:
      return 2

  def to_bytes(self) -> bytes:
    """Returns this instruction as bytes."""
    size = self._get_arg_size()
    arg = self.arg or 0
    ret = [self.opcode, arg & 0xFF]

    for _ in range(size // 2 - 1):
      arg >>= 8
      ret = [dis.opmap["EXTENDED_ARG"], arg & 0xFF] + ret

    ret += [dis.opmap["CACHE"], 0] * cache_count(self.mnemonic)

    assert len(ret) == self.size

    return bytes(ret)

  def get_stack_effect(self) -> int:
    # dis.stack_effect does not work for EXTENDED_ARG and NOP
    if self.mnemonic in ["EXTENDED_ARG", "NOP"]:
      return 0

    stack_effect_arg = None
    if self.arg is _UncalculatedArgSentinel:
      stack_effect_arg = 0
    elif self.has_argument():
      stack_effect_arg = self.arg

    return dis.stack_effect(self.opcode, stack_effect_arg)

  def has_argument(self) -> bool:
    return self.opcode >= dis.HAVE_ARGUMENT

  @classmethod
  def get_fixed_size(cls) -> int:
    return 2

  def __hash__(self) -> int:
    return id(self)

  def debug_index(self) -> int | None:
    """Returns the index of this instruction in the full instruction list.

    Very slow; only use for debugging.
    """
    if self in self.full_instruction_list:
      return self.full_instruction_list.index(self)
    return None

  def _debug_index_str(self) -> str:
    debug_index = self.debug_index()
    if debug_index is not None:
      return f"{debug_index}"
    return "??"

  def __repr__(self) -> str:
    ret = f"{self._debug_index_str()}\t{self.mnemonic}"

    if self.arg is _UncalculatedArgSentinel:
      ret += "\t"
    elif self.arg is not None:
      ret += f"\t{self.arg}"

    if self.reference is not None:
      ret += (
          f"\t>>{self.reference.mnemonic}@{self.reference._debug_index_str()}"
      )

    if self.referers:
      ret = ">> " + ret
    else:
      ret = "   " + ret

    return ret

  def __eq__(self, other):
    return id(self) == id(other)

  def make_nop(self) -> None:
    """Turns this instruction into a NOP."""
    self.opcode = dis.opmap["NOP"]
    self.arg = 0
    self.reference = None

  def expanded_instructions(self) -> List["Instruction"]:
    """Returns a list of all instructions that make up this instruction.

    Includes EXTENDED_ARGs and CACHEs as separate entries. All instructions will
    be of length 1; calling .length or .size on the child instructions may
    produce incorrect results.
    """
    ret: List["Instruction"] = []
    b = self.to_bytes()
    for i in range(0, len(b), 2):
      ret.append(
          Instruction(
              opcode=b[i],
              arg=b[i + 1],
              positions=self.positions,
              reference=None,
              referers=[],
              full_instruction_list=[],
          )
      )
    return ret


def _generate_instruction(
    op: int | str,
    arg: int | None | Instruction,
    copyfrom_instruction: Instruction | None = None,
) -> Instruction:
  """Generates an Instruction object with the provided opcode and argument."""
  if isinstance(op, str):
    op = dis.opmap[op]

  positions = None
  full_instruction_list = None
  if copyfrom_instruction is not None:
    positions = copyfrom_instruction.positions
    full_instruction_list = copyfrom_instruction.full_instruction_list

  if isinstance(arg, Instruction):
    return Instruction(
        opcode=op,
        arg=_UncalculatedArgSentinel,
        positions=positions,
        full_instruction_list=full_instruction_list,
        reference=arg,
    )
  else:
    return Instruction(
        opcode=op,
        arg=arg,
        positions=positions,
        full_instruction_list=full_instruction_list,
        reference=None,
    )


@dataclasses.dataclass
class ReferenceExceptionTableEntry:
  """Holds an exception table entry. Refers to instructions, not offsets."""

  start: Instruction
  end: Instruction
  target: Instruction
  depth: int
  lasti: bool

  def __repr__(self):
    return (
        f"(start={self.start} end={self.end} target={self.target} depth={self.depth} lasti={self.lasti})"
    )

  def __str__(self):
    return self.__repr__()

  def __eq__(self, other):
    return (
        self.start == other.start
        and self.end == other.end
        and self.target == other.target
        and self.depth == other.depth
        and self.lasti == other.lasti
    )


class Instrumentor:
  """A class for instrumenting bytecode."""

  def __init__(self, code: types.CodeType):
    self.consts: List[Any] = list(code.co_consts)
    self._names: List[str] = list(code.co_names)
    self.num_counters = 0
    self._code: types.CodeType = code

    try:
      self._disassemble()
    except Exception as e:
      raise RuntimeError(f"Failed to disassemble bytecode; code={code}") from e

  def _disassemble(self) -> None:
    """Disassembles the bytecode into a list of Instruction objects."""
    self.instructions: List[Instruction] = []
    instructions_by_offset: dict[int, Instruction] = {}
    offset_by_instruction: dict[Instruction, int] = {}

    # Used to ensure that our calculations for instruction sizes are correct.
    debug_instr_sizes: dict[Instruction, int] = collections.defaultdict(int)

    # First pass: translate instructions into a list of Instruction objects.
    # EXTENDED_ARGs and CACHEs are combined with the instruction they apply to
    # into a single object.

    # These are stored between iterations because EXTENDED_ARGs are combined
    # with the instruction that follows them.
    # offset will always point to the first EXTENDED_ARG.
    arg = 0
    offset = None
    instruction_length = 0
    before_resume = True

    instructions = list(get_instructions(self._code))
    for instruction in instructions:
      # If we encountered a CACHE instruction, we actually just increase the
      # length of the previous instruction.
      # Not present in 3.13+.
      if instruction.opname == "CACHE":
        debug_instr_sizes[self.instructions[-1]] += 1
        continue

      if offset is None:
        offset = instruction.offset

      instruction_length += 1

      ci = cache_info(instruction)
      if ci is not None:
        for info in ci:
          instruction_length += info[1]

      if instruction.opname == "EXTENDED_ARG":
        arg |= instruction.arg  # type: ignore[operator]
        arg <<= 8

        continue

      if instruction.arg is None:
        arg = None
      else:
        arg |= instruction.arg  # type: ignore[operator]

      instr = Instruction(
          opcode=instruction.opcode,
          positions=instruction.positions,
          arg=arg,
          reference=None,
          full_instruction_list=self.instructions,
          before_resume=before_resume,
      )

      assert instr.mnemonic == instruction.opname
      if instruction.opname == "RESUME" and instruction.arg == 0:
        assert before_resume
        before_resume = False

      self.instructions.append(instr)
      instructions_by_offset[offset] = instr
      offset_by_instruction[instr] = offset
      debug_instr_sizes[instr] = instruction_length

      arg = 0
      offset = None
      instruction_length = 0

    # Debug pass: ensure our calculations for CACHE offsets are correct.
    for instr in self.instructions:
      assert instr.length == debug_instr_sizes[instr]

    # Second pass: calculate the reference fields.
    for instruction in self.instructions:
      assert instruction.reference is None
      if instruction.mnemonic in HAVE_REL_REFERENCE:
        destination_offset = (
            offset_by_instruction[instruction]
            + instruction.size
            + jump_arg_bytes(instruction.arg)
            * rel_reference_scale(instruction.mnemonic)
        )

      elif instruction.mnemonic in HAVE_ABS_REFERENCE:
        destination_offset = jump_arg_bytes(instruction.arg)

      else:
        continue

      instruction.reference = instructions_by_offset[destination_offset]
      instruction.reference.referers.append(instruction)
      instruction.arg = _UncalculatedArgSentinel

    ## Exception Table Handling

    raw_exception_table = parse_exceptiontable(self._code)

    # end_offset in an exception table entry is exclusive, meaning it could
    # point past-the-end. If that's the case, add a dummy NOP instruction to the
    # end of the code. That keeps this past-the-end-ness contained into this one
    # function.
    past_the_end_offset = instructions[-1].offset + Instruction.get_fixed_size()
    for raw_entry in raw_exception_table.entries:

      if raw_entry.end_offset > past_the_end_offset:
        raise ValueError(
            f"End offset {raw_entry.end_offset} is too far past the end of the"
            " code, which is of length"
            f" {len(self.instructions) * Instruction.get_fixed_size()}."
        )
      if raw_entry.end_offset == past_the_end_offset:
        self.instructions.append(
            _generate_instruction("NOP", None, self.instructions[-1])
        )
        instructions_by_offset[past_the_end_offset] = self.instructions[-1]
        offset_by_instruction[self.instructions[-1]] = past_the_end_offset

        break

    # Convert the exception table entries from offsets to instruction
    # references.
    exceptiontable = []
    for raw_entry in raw_exception_table.entries:
      entry = ReferenceExceptionTableEntry(
          start=instructions_by_offset[raw_entry.start_offset],
          end=instructions_by_offset[raw_entry.end_offset],
          target=instructions_by_offset[raw_entry.target],
          depth=raw_entry.depth,
          lasti=raw_entry.lasti,
      )
      exceptiontable.append(entry)

    self.exceptiontable = exceptiontable

  def _calc_jump_arg(
      self, instruction: Instruction, offset: int, dest_offset: int
  ):
    """Calculates the argument of a jump instruction to jump to the provided offset."""

    if instruction.mnemonic in HAVE_ABS_REFERENCE:
      return offset
    elif instruction.mnemonic in HAVE_REL_REFERENCE:
      return offset_delta_to_jump_arg(
          (dest_offset - (offset + instruction.size))
          * rel_reference_scale(instruction.mnemonic)
      )

  def _get_name(self, name: str) -> int:
    """Returns an offset to `name` in co_names, appending if necessary."""
    return get_name(self._names, name)

  def _get_const(self, constant: Union[int, str, types.ModuleType]) -> int:
    """Returns the index of `constant` in self.consts, inserting if needed."""
    for i in range(len(self.consts)):
      if (
          isinstance(self.consts[i], type(constant))
          and self.consts[i] == constant
      ):
        return i

    self.consts.append(constant)
    return len(self.consts) - 1

  def _get_counter(self) -> int:
    # Atheris must be imported here to avoid a circular dependency.
    import atheris  # pylint: disable=g-import-not-at-top

    counter = atheris._reserve_counter()
    return self._get_const(counter)

  def _generate_trace_branch_invocation(
      self, copyfrom_instruction: Instruction
  ):
    """Builds the bytecode that calls atheris._trace_branch()."""
    to_insert: List[Instruction] = []
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cov = self._get_name(_COVERAGE_FUNCTION)

    for op, arg in args_terminator_before_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_atheris, copyfrom_instruction)
    )
    to_insert.append(
        _generate_instruction("LOAD_ATTR", name_cov, copyfrom_instruction)
    )

    for op, arg in args_terminator_after_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction(
            "LOAD_CONST", self._get_counter(), copyfrom_instruction
        )
    )

    for op, arg in call(1):
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("POP_TOP", None, copyfrom_instruction)
    )

    return to_insert

  def _generate_cmp_invocation(
      self,
      cmp_arg: int,
      copyfrom_instruction: Instruction,
      coerce_to_bool: bool,
  ):
    """Builds the bytecode that calls atheris._trace_cmp().

    Only call this if the two objects being compared are non-constants.

    Generates the following bytecode:
    LOAD_CONST        atheris
    LOAD_ATTR         _trace_cmp
    SWAP...           ; repeated SWAPs to arrange the stack in the correct order
    LOAD_CONST        cmp_arg; the comparison operation as a number (<, etc.)
    LOAD_CONST        counter; a unique counter to distinguish this comparison
    LOAD_CONST        False; this is not a constant cmp.
    CALL

    Args:
      cmp_arg: The comparison operation.
      copyfrom_instruction: Metadata like positions is copied from this.
      coerce_to_bool: If set, insert an instruction to cast the result to bool.

    Returns:
      The instructions to insert.
    """

    to_insert = []  # type: List[Instruction]
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cmp = self._get_name(_COMPARE_FUNCTION)
    const_cmp_arg = self._get_const(cmp_arg)
    const_counter = self._get_counter()
    const_false = self._get_const(False)

    for op, arg in args_terminator_before_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_atheris, copyfrom_instruction)
    )
    to_insert.append(
        _generate_instruction("LOAD_ATTR", name_cmp, copyfrom_instruction)
    )

    for op, arg in args_terminator_after_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    for op, arg in rot_n(2 + CALLABLE_STACK_ENTRIES, CALLABLE_STACK_ENTRIES):
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_cmp_arg, copyfrom_instruction)
    )
    to_insert.append(
        _generate_instruction("LOAD_CONST", const_counter, copyfrom_instruction)
    )
    to_insert.append(
        _generate_instruction("LOAD_CONST", const_false, copyfrom_instruction)
    )

    for op, arg in call(5):
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    if coerce_to_bool:
      to_insert.append(
          _generate_instruction("TO_BOOL", None, copyfrom_instruction)
      )

    return to_insert

  def _generate_const_cmp_invocation(
      self,
      cmp_arg: int,
      copyfrom_instruction: Instruction,
      switch: bool,
      coerce_to_bool: bool,
  ):
    """Builds the bytecode that calls atheris._trace_cmp().

    Only call this if one of the objects being compared is a constant coming
    from co_consts. If `switch` is true the constant is the second argument and
    needs to be switched with the first argument.

    Generates the following bytecode:
    LOAD_CONST        atheris
    LOAD_ATTR         _trace_cmp
    SWAP...           ; repeated SWAPs to arrange the stack in the correct order
    SWAP...           ; if `switch` only: SWAP the argument order
    LOAD_CONST        cmp_arg; the comparison operation as a number (<, etc.)
    LOAD_CONST        counter; a unique counter to distinguish this comparison
    LOAD_CONST        False; this is not a constant cmp.
    CALL

    Args:
      cmp_arg: The comparison operation.
      copyfrom_instruction: Metadata like positions is copied from this.
      switch: bool whether the second arg is constant instead of the first.

    Returns:
      The number of bytes to insert, and the instructions.
    """
    to_insert = []  # type: List[Instruction]
    const_atheris = self._get_const(sys.modules[_TARGET_MODULE])
    name_cmp = self._get_name(_COMPARE_FUNCTION)
    const_counter = self._get_counter()
    const_true = self._get_const(True)

    # TODO(ipudney): Perhaps this should be done in the C++ with a 'switch'
    # parameter passed in; operator overloading could theoretically make this
    # wrong (such as if someone overrode __le__ differently than __ge__).
    if switch:
      const_op = self._get_const(REVERSE_CMP_OP[cmp_arg >> CMP_OP_SHIFT_AMOUNT])
    else:
      const_op = self._get_const(cmp_arg)

    for op, arg in args_terminator_before_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_atheris, copyfrom_instruction)
    )
    to_insert.append(
        _generate_instruction("LOAD_ATTR", name_cmp, copyfrom_instruction)
    )

    for op, arg in args_terminator_after_callable():
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    for op, arg in rot_n(2 + CALLABLE_STACK_ENTRIES, CALLABLE_STACK_ENTRIES):
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    if switch:
      for op, arg in rot_n(2):
        to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_op, copyfrom_instruction)
    )

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_counter, copyfrom_instruction)
    )

    to_insert.append(
        _generate_instruction("LOAD_CONST", const_true, copyfrom_instruction)
    )

    for op, arg in call(5):
      to_insert.append(_generate_instruction(op, arg, copyfrom_instruction))

    if coerce_to_bool:
      to_insert.append(
          _generate_instruction("TO_BOOL", None, copyfrom_instruction)
      )

    return to_insert

  def _insert_at(
      self,
      to_insert: List[Instruction],
      target: Instruction,
  ) -> None:
    """Inserts `to_insert` before `target`, updating referers to point to the first `to_insert` instruction."""
    pos = self.instructions.index(target)
    self.instructions[pos:pos] = to_insert

    for referer in target.referers:
      referer.reference = to_insert[0]
      to_insert[0].referers.append(referer)
    target.referers = []

    for referer in target.exceptiontable_referers:
      if referer.start == target:
        referer.start = to_insert[0]
        to_insert[0].exceptiontable_referers.append(referer)
      if referer.end == target:
        referer.end = to_insert[0]
        to_insert[0].exceptiontable_referers.append(referer)
    target.exceptiontable_referers = []

  def trace_control_flow(self) -> None:
    """Instrument every basic block in the bytecode."""
    # Find all the places to instrument.
    # First is start of the function.
    locations_to_instrument: Set[Instruction] = set()

    def queue_for_instrumentation(index):
      # This queues the instruction at index to be instrumented, or if it's in
      # INSERT_AFTER_INSTRS, the next instruction after it.
      # This will never insert two instrumentation blocks in a row.
      # This technically could be improved, because the 'skipping' from
      # INSERT_AFTER_INSTRS could result in references that were to two
      # *different* instructions now being treated as references to the same,
      # making their basic blocks indistinguishable. The solution would be to
      # add separate instrumentation blocks that can distinguish between the
      # different reference situations.
      # Similarly, a special case could be created whereby the JUMP_BACKWARD for
      # a for loop doesn't add any instrumentation to FOR_ITER (and in fact
      # jumps directly to the FOR_ITER even if instrumentation was added for it
      # elsewhere). This would avoid a current double-instrumentation situation:
      # the JUMP_BACKWARD jumps to instrumentation before the FOR_ITER, but
      # because the FOR_ITER is a conditional jump, instrumentation is also
      # added after it, so every loop iteration triggers twice.
      while (
          self.instructions[index].before_resume
          or self.instructions[index].mnemonic in INSERT_AFTER_INSTRS
      ):
        if self.instructions[index].before_resume:
          index += 1
        else:
          index += INSERT_AFTER_INSTRS[self.instructions[index].mnemonic]
        if index >= len(self.instructions):
          return

      locations_to_instrument.add(self.instructions[index])

    # Queue the first instruction.
    queue_for_instrumentation(0)

    # Then, find any jump destination or instruction following a
    # conditional jump. These are the starts of basic blocks.
    for i, instruction in enumerate(self.instructions):
      if instruction.referers:
        queue_for_instrumentation(i)

      if instruction.mnemonic in CONDITIONAL_JUMPS:
        queue_for_instrumentation(i + 1)

    # Apply instrumentation.
    for i, instruction in enumerate(locations_to_instrument):
      if (
          debug_instrument_only_blocks is not None
          and i not in debug_instrument_only_blocks
      ):
        continue
      self._insert_at(
          self._generate_trace_branch_invocation(instruction), instruction
      )

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
    """
    stack_size = 0
    seen_consts = []

    for c, instr in enumerate(self.instructions):
      if instr.mnemonic == "LOAD_CONST":
        seen_consts.append(stack_size)
      elif instr.mnemonic == "COMPARE_OP" and (
          instr.arg >> CMP_OP_SHIFT_AMOUNT
      ) < len(dis.cmp_op):
        requires_coersion: bool = requires_bool_coersion(instr.arg)

        # Determine the two values on the top of the stack before COMPARE_OP
        consts_on_stack = [
            c for c in seen_consts if stack_size - 2 <= c < stack_size
        ]
        tos_is_constant = stack_size - 1 in consts_on_stack
        tos1_is_constant = stack_size - 2 in consts_on_stack

        if not (tos_is_constant and tos1_is_constant):
          # Both items are non-constants
          if (not tos_is_constant) and (not tos1_is_constant):
            to_insert = self._generate_cmp_invocation(
                instr.arg, instr, requires_coersion
            )

          # One item is constant, one is non-constant
          else:
            to_insert = self._generate_const_cmp_invocation(
                instr.arg, instr, tos_is_constant, requires_coersion
            )

          self._insert_at(to_insert, instr)
          stack_size += to_insert[0].get_stack_effect()

          instr.make_nop()

      stack_size += instr.get_stack_effect()
      seen_consts = [c for c in seen_consts if c < stack_size]

  def to_code(self) -> types.CodeType:
    """Returns the instrumented code object."""
    code = bytes()
    stacksize = 0

    # Compute offsets and fix up the arguments for jump instructions.
    changed: bool = True
    offset_to_instruction: dict[int, Instruction] = {}
    instruction_to_offset: dict[Instruction, int] = {}

    # The size of each jump instruction depends on the distance it's jumping,
    # because values >255 require EXTENDED_ARG instructions before them.
    # This means that the very act of computing offsets can change those offsets
    # by adding extra instructions. This repeatedly computes the offsets until
    # they stop changing.
    while changed:
      changed = False
      offset = 0

      for instr in self.instructions:
        offset_to_instruction[offset] = instr
        instruction_to_offset[instr] = offset
        offset += instr.size
      del offset

      for instr in self.instructions:
        if instr.reference is None:
          continue
        old_arg = instr.arg
        instr.arg = self._calc_jump_arg(
            instr,
            instruction_to_offset[instr],
            instruction_to_offset[instr.reference],
        )
        if old_arg is _UncalculatedArgSentinel or instr.arg != old_arg:
          changed = True

    for instr in self.instructions:
      code += instr.to_bytes()
      stacksize = max(stacksize, stacksize + instr.get_stack_effect())

    # Transform the exception table from instruction-reference-based back to
    # offset-based.
    raw_table = ExceptionTable([])
    for entry in self.exceptiontable:
      raw_entry = ExceptionTableEntry(
          instruction_to_offset[entry.start],
          instruction_to_offset[entry.end],
          instruction_to_offset[entry.target],
          entry.depth,
          entry.lasti,
      )
      raw_table.entries.append(raw_entry)

    co_exceptiontable = generate_exceptiontable(self._code, raw_table.entries)

    expanded_instructions = []
    for instr in self.instructions:
      expanded_instructions.extend(instr.expanded_instructions())

    return get_code_object(
        self._code,
        stacksize,
        code,
        tuple(self.consts + ["__ATHERIS_INSTRUMENTED__"]),
        tuple(self._names),
        get_lnotab(self._code, self.instructions),
        co_exceptiontable,
    )


def patch_code(
    code: types.CodeType,
    trace_dataflow: bool,
    trace_control_flow: bool = True,
    nested: bool = False,
) -> types.CodeType:
  """Returns code, patched with Atheris instrumentation.

  Args:
    code: The byte code to instrument.
    trace_dataflow: Whether to trace dataflow or not.
    trace_control_flow: Whether to trace control flow (basic blocks) or not.
    nested: If False, reserve counters, and patch modules. Recursive calls to
      this function are considered nested.
  """

  # If this code object has already been instrumented, skip it
  for const in code.co_consts:
    # This avoids comparison between str and bytes (BytesWarning).
    if isinstance(const, str) and const == "__ATHERIS_INSTRUMENTED__":
      return code

  inst = Instrumentor(code)

  if trace_control_flow:
    inst.trace_control_flow()

  if trace_dataflow:
    inst.trace_data_flow()
    # Note that the user still needs to add "str" to enabled_hooks to actually
    # enable tracing
  #  inst.trace_str_flow()

  # Repeat this for all nested code objects
  for i in range(len(inst.consts)):
    if isinstance(inst.consts[i], types.CodeType):
      if (
          inst.consts[i].co_name == "<lambda>"
          or (not nested and inst.consts[i].co_name == "<module>")
          or inst.consts[i].co_name[0] != "<"
          or inst.consts[i].co_name[-1] != ">"
      ):
        inst.consts[i] = patch_code(inst.consts[i], trace_dataflow, nested=True)

  ret = inst.to_code()
  return ret


T = TypeVar("T")


def instrument_func(func: Callable[..., T]) -> Callable[..., T]:
  """Add Atheris instrumentation to a specific function."""
  if isinstance(func, types.MethodType):
    return instrument_func(func.__func__)

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
    if not isinstance(obj, (types.FunctionType, types.MethodType)):
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
