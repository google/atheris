// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file contains a reimplementation of Python's code for generating
// exception tables and codetables in 3.11. It will likely need to be updated
// for every new Python version.
// Much of this code is copied, as directly as possible, from this file:
// https://github.com/python/cpython/blob/3.11/Python/compile.c
// Only relevant code has been copied - various irrelevant functions and members
// have been removed.

#include "codetable_gen.h"

#include <Python.h>
#include <opcode.h>

#include <iostream>

#if PY_MAJOR_VERSION >= 3 && PY_MINOR_VERSION >= 11

namespace atheris {

uint8_t opcode_caches[256];
static bool dummy_initializer = []() {
  memset(opcode_caches, 0, 256);
  opcode_caches[BINARY_SUBSCR] = 4;
  opcode_caches[STORE_SUBSCR] = 1;
  opcode_caches[UNPACK_SEQUENCE] = 1;
  opcode_caches[STORE_ATTR] = 4;
  opcode_caches[LOAD_ATTR] = 4;
  opcode_caches[COMPARE_OP] = 2;
  opcode_caches[LOAD_GLOBAL] = 5;
  opcode_caches[BINARY_OP] = 1;
  opcode_caches[LOAD_METHOD] = 10;
  opcode_caches[PRECALL] = 1;
  opcode_caches[CALL] = 4;
  return true;
}();

typedef enum _PyCodeLocationInfoKind {
  /* short forms are 0 to 9 */
  PY_CODE_LOCATION_INFO_SHORT0 = 0,
  /* one lineforms are 10 to 12 */
  PY_CODE_LOCATION_INFO_ONE_LINE0 = 10,
  PY_CODE_LOCATION_INFO_ONE_LINE1 = 11,
  PY_CODE_LOCATION_INFO_ONE_LINE2 = 12,

  PY_CODE_LOCATION_INFO_NO_COLUMNS = 13,
  PY_CODE_LOCATION_INFO_LONG = 14,
  PY_CODE_LOCATION_INFO_NONE = 15
} _PyCodeLocationInfoKind;

static inline int write_varint(uint8_t* ptr, unsigned int val) {
  int written = 1;
  while (val >= 64) {
    *ptr++ = 64 | (val & 63);
    val >>= 6;
    written++;
  }
  *ptr = val;
  return written;
}

static inline int write_signed_varint(uint8_t* ptr, int val) {
  if (val < 0) {
    val = ((-val) << 1) | 1;
  } else {
    val = val << 1;
  }
  return write_varint(ptr, val);
}

static inline int write_location_entry_start(uint8_t* ptr, int code,
                                             int length) {
  assert((code & 15) == code);
  *ptr = 128 | (code << 3) | (length - 1);
  return 1;
}

typedef struct location_ {
  int lineno;
  int end_lineno;
  int col_offset;
  int end_col_offset;
} location;

struct instr {
  int i_opcode;
  int i_oparg;
  location i_loc;
};

struct assembler {
  int a_lineno; /* lineno of last emitted instruction */

  PyObject* a_linetable; /* bytes containing location info */
  int a_location_off;    /* offset of last written location info frame */

  PyObject* a_except_table; /* bytes containing exception table */
  int a_except_table_off;   /* offset into exception table */
};

static int instr_size(struct instr* instruction) {
  int opcode = instruction->i_opcode;
#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION == 12
  assert(!IS_PSEUDO_OPCODE(opcode));
  #endif
  int oparg = HAS_ARG(opcode) ? instruction->i_oparg : 0;
  int extended_args = (0xFFFFFF < oparg) + (0xFFFF < oparg) + (0xFF < oparg);
  int caches = opcode_caches[opcode];
  return extended_args + 1 + caches;
}

static void write_location_byte(struct assembler* a, int val) {
  PyBytes_AS_STRING(a->a_linetable)[a->a_location_off] = val & 255;
  a->a_location_off++;
}

static uint8_t* location_pointer(struct assembler* a) {
  return (uint8_t*)PyBytes_AS_STRING(a->a_linetable) + a->a_location_off;
}

static void write_location_first_byte(struct assembler* a, int code,
                                      int length) {
  a->a_location_off +=
      write_location_entry_start(location_pointer(a), code, length);
}

static void write_location_varint(struct assembler* a, unsigned int val) {
  uint8_t* ptr = location_pointer(a);
  a->a_location_off += write_varint(ptr, val);
}

static void write_location_signed_varint(struct assembler* a, int val) {
  uint8_t* ptr = location_pointer(a);
  a->a_location_off += write_signed_varint(ptr, val);
}

static void write_location_info_short_form(struct assembler* a, int length,
                                           int column, int end_column) {
  assert(length > 0 && length <= 8);
  int column_low_bits = column & 7;
  int column_group = column >> 3;
  assert(column < 80);
  assert(end_column >= column);
  assert(end_column - column < 16);
  write_location_first_byte(a, PY_CODE_LOCATION_INFO_SHORT0 + column_group,
                            length);
  write_location_byte(a, (column_low_bits << 4) | (end_column - column));
}

static void write_location_info_oneline_form(struct assembler* a, int length,
                                             int line_delta, int column,
                                             int end_column) {
  assert(length > 0 && length <= 8);
  assert(line_delta >= 0 && line_delta < 3);
  assert(column < 128);
  assert(end_column < 128);
  write_location_first_byte(a, PY_CODE_LOCATION_INFO_ONE_LINE0 + line_delta,
                            length);
  write_location_byte(a, column);
  write_location_byte(a, end_column);
}

static void write_location_info_long_form(struct assembler* a, struct instr* i,
                                          int length) {
  assert(length > 0 && length <= 8);
  write_location_first_byte(a, PY_CODE_LOCATION_INFO_LONG, length);
  write_location_signed_varint(a, i->i_loc.lineno - a->a_lineno);
  assert(i->i_loc.end_lineno >= i->i_loc.lineno);
  write_location_varint(a, i->i_loc.end_lineno - i->i_loc.lineno);
  write_location_varint(a, i->i_loc.col_offset + 1);
  write_location_varint(a, i->i_loc.end_col_offset + 1);
}

static void write_location_info_none(struct assembler* a, int length) {
  write_location_first_byte(a, PY_CODE_LOCATION_INFO_NONE, length);
}

static void write_location_info_no_column(struct assembler* a, int length,
                                          int line_delta) {
  write_location_first_byte(a, PY_CODE_LOCATION_INFO_NO_COLUMNS, length);
  write_location_signed_varint(a, line_delta);
}

#define THEORETICAL_MAX_ENTRY_SIZE 25 /* 1 + 6 + 6 + 6 + 6 */

static int write_location_info_entry(struct assembler* a, struct instr* i,
                                     int isize) {
  Py_ssize_t len = PyBytes_GET_SIZE(a->a_linetable);
  if (a->a_location_off + THEORETICAL_MAX_ENTRY_SIZE >= len) {
    assert(len > THEORETICAL_MAX_ENTRY_SIZE);
    if (_PyBytes_Resize(&a->a_linetable, len * 2) < 0) {
      return 0;
    }
  }
  if (i->i_loc.lineno < 0) {
    write_location_info_none(a, isize);
    return 1;
  }
  int line_delta = i->i_loc.lineno - a->a_lineno;
  int column = i->i_loc.col_offset;
  int end_column = i->i_loc.end_col_offset;
  assert(column >= -1);
  assert(end_column >= -1);
  if (column < 0 || end_column < 0) {
    if (i->i_loc.end_lineno == i->i_loc.lineno || i->i_loc.end_lineno == -1) {
      write_location_info_no_column(a, isize, line_delta);
      a->a_lineno = i->i_loc.lineno;
      return 1;
    }
  } else if (i->i_loc.end_lineno == i->i_loc.lineno) {
    if (line_delta == 0 && column < 80 && end_column - column < 16 &&
        end_column >= column) {
      write_location_info_short_form(a, isize, column, end_column);
      return 1;
    }
    if (line_delta >= 0 && line_delta < 3 && column < 128 && end_column < 128) {
      write_location_info_oneline_form(a, isize, line_delta, column,
                                       end_column);
      a->a_lineno = i->i_loc.lineno;
      return 1;
    }
  }
  write_location_info_long_form(a, i, isize);
  a->a_lineno = i->i_loc.lineno;
  return 1;
}

static int assemble_emit_location(struct assembler* a, struct instr* i) {
  int isize = instr_size(i);
  while (isize > 8) {
    if (!write_location_info_entry(a, i, 8)) {
      return 0;
    }
    isize -= 8;
  }
  return write_location_info_entry(a, i, isize);
}

template <typename T>
T cast_if_not_none(py::handle h, T deflt) {
  if (h.is_none()) return deflt;
  return h.cast<T>();
}

instr ToNativeInstr(py::handle py_instruction) {
  struct instr native_instruction;
  native_instruction.i_opcode = py_instruction.attr("opcode").cast<int>();
  native_instruction.i_oparg = py_instruction.attr("arg").cast<int>();

  py::handle py_location = py_instruction.attr("positions");
  if (py_location.is_none()) {
    native_instruction.i_loc.lineno = -1;
    native_instruction.i_loc.end_lineno = -1;
    native_instruction.i_loc.col_offset = -1;
    native_instruction.i_loc.end_col_offset = -1;
    return native_instruction;
  }

  native_instruction.i_loc.lineno =
      cast_if_not_none<int>(py_location.attr("lineno"), -1);
  native_instruction.i_loc.end_lineno =
      cast_if_not_none<int>(py_location.attr("end_lineno"), -1);
  native_instruction.i_loc.col_offset =
      cast_if_not_none<int>(py_location.attr("col_offset"), -1);
  native_instruction.i_loc.end_col_offset =
      cast_if_not_none<int>(py_location.attr("end_col_offset"), -1);

  return native_instruction;
}

py::bytes GenerateCodetable(py::object original_code,
                            std::vector<py::object>& listing) {
  assembler assembler;
  assembler.a_linetable = PyBytes_FromStringAndSize(NULL, 32);
  assembler.a_lineno = original_code.attr("co_firstlineno").cast<int>();
  assembler.a_location_off = 0;

  for (py::object& py_instruction : listing) {
    if (py_instruction.attr("opcode").cast<int>() == CACHE) {
      continue;
    }
    instr native_instruction = ToNativeInstr(py_instruction);

    if (!assemble_emit_location(&assembler, &native_instruction)) {
      std::cerr << "Failed to assemble" << std::endl;
      break;
    }
  }

  _PyBytes_Resize(&assembler.a_linetable, assembler.a_location_off);
  return py::object(assembler.a_linetable, false);
}

struct basicblock {
  /* depth of stack upon entry of block, computed by stackdepth() */
  int b_startdepth;
  /* instruction offset for block, computed by assemble_jump_offsets() */
  int b_offset;
  /* Basic block is an exception handler that preserves lasti */
  unsigned b_preserve_lasti : 1;
};

static inline void write_except_byte(struct assembler* a, int byte) {
  unsigned char* p = (unsigned char*)PyBytes_AS_STRING(a->a_except_table);
  p[a->a_except_table_off++] = byte;
}

#define CONTINUATION_BIT 64

static void assemble_emit_exception_table_item(struct assembler* a, int value,
                                               int msb) {
  assert((msb | 128) == 128);
  assert(value >= 0 && value < (1 << 30));
  if (value >= 1 << 24) {
    write_except_byte(a, (value >> 24) | CONTINUATION_BIT | msb);
    msb = 0;
  }
  if (value >= 1 << 18) {
    write_except_byte(a, ((value >> 18) & 0x3f) | CONTINUATION_BIT | msb);
    msb = 0;
  }
  if (value >= 1 << 12) {
    write_except_byte(a, ((value >> 12) & 0x3f) | CONTINUATION_BIT | msb);
    msb = 0;
  }
  if (value >= 1 << 6) {
    write_except_byte(a, ((value >> 6) & 0x3f) | CONTINUATION_BIT | msb);
    msb = 0;
  }
  write_except_byte(a, (value & 0x3f) | msb);
}

/* See Objects/exception_handling_notes.txt for details of layout */
#define MAX_SIZE_OF_ENTRY 20

static int assemble_emit_exception_table_entry(struct assembler* a, int start,
                                               int end, basicblock* handler) {
  Py_ssize_t len = PyBytes_GET_SIZE(a->a_except_table);
  if (a->a_except_table_off + MAX_SIZE_OF_ENTRY >= len) {
    if (_PyBytes_Resize(&a->a_except_table, len * 2) < 0) return 0;
  }
  int size = end - start;
  assert(end > start);
  int target = handler->b_offset;
  int depth = handler->b_startdepth - 1;
  if (handler->b_preserve_lasti) {
    depth -= 1;
  }
  assert(depth >= 0);
  int depth_lasti = (depth << 1) | handler->b_preserve_lasti;
  assemble_emit_exception_table_item(a, start, (1 << 7));
  assemble_emit_exception_table_item(a, size, 0);
  assemble_emit_exception_table_item(a, target, 0);
  assemble_emit_exception_table_item(a, depth_lasti, 0);
  return 1;
}

py::bytes GenerateExceptiontable(
    py::object original_code,
    std::vector<py::object>& exception_table_entries) {
  assembler assembler;
  assembler.a_except_table = PyBytes_FromStringAndSize(NULL, 16);
  assembler.a_except_table_off = 0;
  assembler.a_lineno = original_code.attr("co_firstlineno").cast<int>();

  for (py::object& table_entries : exception_table_entries) {
    basicblock handler;
    handler.b_startdepth = table_entries.attr("depth").cast<int>() + 1;
    handler.b_offset = table_entries.attr("target").cast<int>() / 2;
    handler.b_preserve_lasti = table_entries.attr("lasti").cast<int>();
    if (handler.b_preserve_lasti) handler.b_startdepth += 1;
    int start = table_entries.attr("start_offset").cast<int>() / 2;
    int end = table_entries.attr("end_offset").cast<int>() / 2 + 1;

    if (!assemble_emit_exception_table_entry(&assembler, start, end,
                                             &handler)) {
      std::cerr << "Got error in assemble_emit_exception_table_entry"
                << std::endl;
      return py::none();
    }
  }

  _PyBytes_Resize(&assembler.a_except_table, assembler.a_except_table_off);
  return py::object(assembler.a_except_table, false);
}

}  // namespace atheris

#else

namespace atheris {

pybind11::bytes GenerateCodetable(pybind11::object original_code,
                                  std::vector<pybind11::object>& listing) {
  return pybind11::bytes();
}

pybind11::bytes GenerateExceptiontable(
    pybind11::object original_code,
    std::vector<pybind11::object>& exception_table_entries) {
  return pybind11::bytes();
}

}  // namespace atheris

#endif
