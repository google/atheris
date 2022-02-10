// Copyright 2020 Google LLC
// Copyright 2021 Fraunhofer FKIE
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

extern "C" {
void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2);
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);
void __sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                  const void* s2, size_t n, int result);
}

namespace atheris {

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
void TraceCompareUnicode(PyObject* left, PyObject* right, void* pc) {
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
void TraceRegexMatch(py::handle generated_match, py::handle re_obj) {
  PyUnicode_READY(generated_match.ptr());
  py::bytes utf8 = UnicodeToUtf8(generated_match.ptr());
  const char* generated = PyBytes_AsString(utf8.ptr());
  const uint64_t size = PyBytes_Size(utf8.ptr());
  // Libfuzzer doesn't _really_ care about the program counter location so we'll
  // give one based on the regex pattern hash.
  const ssize_t fake_pc = py::hash(re_obj.ptr());

  // We specify -1 as the last argument to let the mutator know that these bytes
  // need to be emitted. This basically means that the `memcmp` is different.
  __sanitizer_weak_hook_memcmp((char*)fake_pc, generated, generated, size, -1);
}

// This function hooks COMPARE_OP, inserts calls for dataflow tracing
// and performs an actual comparison at the end.
// pc is a pointer belonging exclusively to the current comparison.
// left and right are the objects to compare.
// opid is one of Py_LT, Py_LE, Py_EQ, Py_NE, Py_GT, or Py_GE.
// left_is_const states whether the left argument is a constant.
// When two values are compared, only one constant can be involved
// otherwise this function wouldn't get called. And if a constant
// is involved it is always brought to the left because
// __sanitizer_cov_trace_const_cmp8 expects the first argument to be the
// constant.
NO_SANITIZE
PyObject* TraceCompareOp(void* pc, PyObject* left, PyObject* right, int opid,
                         bool left_is_const) {
  if (PyLong_Check(left) && PyLong_Check(right)) {
    // Integer-integer comparison. If both integers fit into 64 bits, report
    // an integer comparison.
    int64_t left_int;
    int64_t right_int;
    if (As64(&left_int, left) && As64(&right_int, right)) {
      if (left_is_const) {
        __sanitizer_cov_trace_const_cmp8(left_int, right_int);
      } else {
        __sanitizer_cov_trace_cmp8(left_int, right_int);
      }
    }
  } else if (PyBytes_Check(left) && PyBytes_Check(right)) {
    // If comparing bytes, report a memcmp. Report that we're comparing the
    // size, and then if that passes, compare the contents ourselves and report
    // the results.
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
  } else if (PyUnicode_Check(left) && PyUnicode_Check(right)) {
    TraceCompareUnicode(left, right, pc);
  }

  return PyObject_RichCompare(left, right, opid);
}

}  // namespace atheris
