// Copyright 2020 Google LLC
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

#include "tracer.h"

#include <Python.h>
#include <frameobject.h>
#include <opcode.h>
#include <pystate.h>

#include <cstddef>
#include <deque>
#include <iostream>
#include <unordered_map>

#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "util.h"

namespace atheris {

struct PcTableEntry {
  uintptr_t pc;
  uintptr_t flags;
};

// Represents a "module" in the libFuzzer sense. The buffers in a module are
// dynamically allocated and never deleted.
struct Module {
  // The length of the counters, fake_instruction_buffer, and pcs arrays.
  size_t capacity;

  // The fraction of size that has been used
  size_t size;

  // A collection of 8-bit counters, one for each Python trace key.
  uint8_t* counters;
  // A range of unused memory. We will generate fake "program counters" to point
  // into this range. By allocating this memory, we can guarantee that they will
  // never conflict with legitimate program counter values.
  uint32_t* fake_instruction_buffer;
  // Those program counters and metadata.
  PcTableEntry* pcs;

  // Whether the PCs in this module are marked as being function entires or not.
  bool is_function_entry;
};

extern "C" {
void __sanitizer_cov_pcs_init(const uintptr_t* pcs_beg,
                              const uintptr_t* pcs_end);

void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);

void __sanitizer_cov_trace_pc_indir(uintptr_t callee);

void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);

void __sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                  const void* s2, size_t n, int result);
}

NO_SANITIZE
Module MakeModule(int capacity, bool is_function_entry) {
  Module module;
  module.size = 0;
  module.capacity = capacity;

  module.counters = new uint8_t[capacity];
  module.fake_instruction_buffer = new uint32_t[capacity];
  memset(module.fake_instruction_buffer, 0, sizeof(uint32_t) * capacity);
  module.pcs = new PcTableEntry[capacity];
  module.is_function_entry = is_function_entry;

  for (int i = 0; i < capacity; ++i) {
    module.pcs[i].pc =
        reinterpret_cast<uintptr_t>(module.fake_instruction_buffer + i);
  }

  for (int i = 0; i < capacity; ++i) {
    module.pcs[i].flags = is_function_entry;
  }

  __sanitizer_cov_8bit_counters_init(module.counters,
                                     module.counters + capacity);
  __sanitizer_cov_pcs_init((uintptr_t*)(module.pcs),
                           (uintptr_t*)(module.pcs + capacity));

  return module;
}

using TraceKey = size_t;

struct ModuleEntry {
  Module* module = nullptr;
  size_t idx = 0;
};

auto& reg_modules = *new std::deque<Module>{};
auto& func_modules = *new std::deque<Module>{};

auto& key_to_reg_module = *new std::unordered_map<TraceKey, ModuleEntry>();
auto& key_to_func_module = *new std::unordered_map<TraceKey, ModuleEntry>();

bool tracer_setup = false;

NO_SANITIZE
std::pair<const ModuleEntry*, bool /*is_new*/> FindOrAddModuleData(
    TraceKey key, bool is_func_entry) {
  PyGILState_Ensure();

  auto& map = (is_func_entry ? key_to_func_module : key_to_reg_module);
  auto& ret = map[key];

  if (ret.module) return {&ret, false};

  auto& deq = (is_func_entry ? func_modules : reg_modules);
  ret.module = &deq.back();
  ret.idx = ret.module->size++;
  if (ret.module->capacity == ret.module->size) {
    deq.push_back(MakeModule(ret.module->capacity * 2, is_func_entry));
  }

  return {&ret, true};
}

NO_SANITIZE
void MarkEntryVisited(const ModuleEntry& entry) {
  unsigned char& ctr = entry.module->counters[entry.idx];
  ++ctr;
  if (ctr == 0) --ctr;
}

int printed_funcs = 0;
int max_printed_funcs = 1;

void PrintFunc(PyFrameObject* frame) {
  std::cerr << "\tNEW_PY_FUNC[" << printed_funcs << "/" << max_printed_funcs
            << "]: " << py::handle(frame->f_code->co_name).cast<std::string>()
            << "() "
            << py::handle(frame->f_code->co_filename).cast<std::string>() << ":"
            << frame->f_lineno << std::endl;
}

#ifdef HAS_OPCODE_TRACE

NO_SANITIZE
bool As64(int64_t* out, PyObject* integer) {
  if (PyErr_Occurred()) {
    std::cerr << "Unsupported call to As64 in exception handling." << std::endl;
    exit(1);
  }

  int overflowed = 0;
  *out = PyLong_AsLongLongAndOverflow(integer, &overflowed);
  if (*out == -1 && PyErr_Occurred()) {
    PyErr_Clear();
    return false;
  }
  if (!overflowed) return true;
  return false;
}

// Manual memcmp: if we called real memcmp, it might (or might not)
// trigger its own hooks, depending on how Atheris was compiled.
NO_SANITIZE
int NoSanitizeMemcmp(const void* left, const void* right, size_t n) {
  int differ = 0;
  for (int i = 0; i < n; ++i) {
    differ += reinterpret_cast<const char*>(left)[i];
    differ -= reinterpret_cast<const char*>(right)[i];
    if (differ) return differ;
  }
  return differ;
}

// This function produces a memcmp event for comparing unicode strings. This
// converts the strings to utf-8 before comparison when possible, which produces
// significantly better results even though there's an encoding step every time.
NO_SANITIZE
void TraceCompareUnicode(PyObject* left, PyObject* right,
                         const ModuleEntry& entry, PyFrameObject* frame) {
  void* pc = entry.module->fake_instruction_buffer + entry.idx;

  PyUnicode_READY(left);
  PyUnicode_READY(right);

  py::bytes left_utf8 = UnicodeToUtf8(left);
  py::bytes right_utf8 = UnicodeToUtf8(right);

  uint64_t left_size = PyBytes_Size(left_utf8.ptr());
  uint64_t right_size = PyBytes_Size(right_utf8.ptr());
  __sanitizer_cov_trace_cmp8(left_size, right_size);
  if (left_size == right_size) {
    const void* left_bytes = PyBytes_AsString(left_utf8.ptr());
    const void* right_bytes = PyBytes_AsString(right_utf8.ptr());
    int differ = NoSanitizeMemcmp(left_bytes, right_bytes, left_size);
    __sanitizer_weak_hook_memcmp(pc, left_bytes, right_bytes, left_size,
                                 differ);
  }
}

NO_SANITIZE
void TraceCompareOp(const ModuleEntry& entry, PyFrameObject* frame) {
  void* pc = entry.module->fake_instruction_buffer + entry.idx;

  PyObject* left = frame->f_stacktop[-2];
  PyObject* right = frame->f_stacktop[-1];
  if (frame->f_stacktop - frame->f_valuestack < 2) {
    std::cerr << Colorize(
        STDERR_FILENO,
        "Attempt to trace COMPARE_OP with <2 items on the stack.");
    exit(1);
  }

  if (PyLong_Check(left)) {
    if (PyLong_Check(right)) {
      // Integer-integer comparison. If both integers fit into 64 bits, report
      // an integer comparison.
      int64_t left_int;
      int64_t right_int;
      if (As64(&left_int, left) && As64(&right_int, right)) {
        __sanitizer_cov_trace_cmp8(left_int, right_int);
        return;
      }
    }
  }

  // If comparing bytes, report a memcmp. Report that we're comparing the size,
  // and then if that passes, compare the contents ourselves and report the
  // results.
  if (PyBytes_Check(left)) {
    if (PyBytes_Check(right)) {
      uint64_t left_size = PyBytes_Size(left);
      uint64_t right_size = PyBytes_Size(right);
      __sanitizer_cov_trace_cmp8(left_size, right_size);
      if (left_size == right_size) {
        const void* left_bytes = PyBytes_AsString(left);
        const void* right_bytes = PyBytes_AsString(right);
        int differ = NoSanitizeMemcmp(left_bytes, right_bytes, left_size);
        __sanitizer_weak_hook_memcmp(pc, left_bytes, right_bytes, left_size,
                                     differ);
      }
      return;
    }
  }

  if (PyUnicode_Check(left)) {
    if (PyUnicode_Check(right)) {
      TraceCompareUnicode(left, right, entry, frame);
      return;
    }
  }
}

NO_SANITIZE
int Tracer(void* pyobj, PyFrameObject* frame, int what, PyObject* arg_unused) {
  frame->f_trace_opcodes = true;

  if (!tracer_setup) return 0;

  TraceKey key = 0;
  if (what == PyTrace_CALL) {
    key = CompositeHash(frame->f_lineno, what, frame->f_code);
  }
  if (what == PyTrace_OPCODE) {
    key = CompositeHash(frame->f_lineno, what, frame->f_lasti, frame->f_code);
  }

  // With opcode tracing, we only need to track CALL and OPCODE events.
  // Anything else (e.g. LINE events) is redundant, as we'll also get one or
  // more OPCODE events for those lines.
  if (what == PyTrace_CALL || what == PyTrace_OPCODE) {
    auto entry_data = FindOrAddModuleData(key, what == PyTrace_CALL);
    MarkEntryVisited(*entry_data.first);

    if (what == PyTrace_OPCODE) {
      unsigned int opcode =
          PyBytes_AsString(frame->f_code->co_code)[frame->f_lasti];
      if (opcode == COMPARE_OP) {
        TraceCompareOp(*entry_data.first, frame);
      }
    }

    if (what == PyTrace_CALL && entry_data.second &&
        printed_funcs < max_printed_funcs) {
      ++printed_funcs;
      PrintFunc(frame);
    }
  }

  return 0;
}

#endif  // HAS_OPCODE_TRACE

NO_SANITIZE
int TracerNoOpcodes(void* pyobj, PyFrameObject* frame, int what,
                    PyObject* arg_unused) {
  if (!tracer_setup) return 0;

  // When not using OPCODE tracing, trace every kind of event we can.
  auto key = CompositeHash(frame->f_lineno, what, frame->f_code);
  auto entry_data = FindOrAddModuleData(key, what == PyTrace_CALL);
  MarkEntryVisited(*entry_data.first);

  if (what == PyTrace_CALL && entry_data.second &&
      printed_funcs < max_printed_funcs) {
    ++printed_funcs;
    PrintFunc(frame);
  }

  return 0;
}

NO_SANITIZE
void SetupTracer(int max_print_funcs, bool enable_opcode_tracing) {
  reg_modules.push_back(MakeModule(512, false));
  func_modules.push_back(MakeModule(512, true));
  max_printed_funcs = max_print_funcs;

  TraceThisThread(enable_opcode_tracing);

#ifdef HAS_OPCODE_TRACE

  if (enable_opcode_tracing) {
    std::cerr << "INFO: Configured for Python tracing with opcodes."
              << std::endl;
  } else {
    std::cerr << "INFO: Configured for Python tracing without opcodes."
              << std::endl;
  }

#else

  if (enable_opcode_tracing) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Opcode tracing requested, but this feature is only "
                          "supported on Python 3.8+. Option will be ignored.")
              << std::endl;
  }
  std::cerr << "INFO: Configured for Python tracing." << std::endl;

#endif

  tracer_setup = true;
}

void TraceThisThread(bool enable_opcode_tracing) {
#ifdef HAS_OPCODE_TRACE
  if (enable_opcode_tracing) {
    PyEval_SetTrace((Py_tracefunc)Tracer, (PyObject*)nullptr);
  } else {
    PyEval_SetTrace((Py_tracefunc)TracerNoOpcodes, (PyObject*)nullptr);
  }
#else
  PyEval_SetTrace((Py_tracefunc)TracerNoOpcodes, (PyObject*)nullptr);
#endif
}

// Called before every TestOneInput.
NO_SANITIZE
void TracerStartInput() { printed_funcs = 0; }

}  // namespace atheris
