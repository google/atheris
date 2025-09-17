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

// This module defines an opcode-level tracer.
// call debug.EnableTracing() to activate this module.
// call debug.TrackFunc(func) to mark a function as tracked; each line and
// opcode it executes will be printed to stdout.

#include <Python.h>

#include <iostream>

#include "pybind11/cast.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

#if PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION < 12
#error "Debugging tool only supports Python 3.12+"
#endif

namespace py = pybind11;

std::unordered_set<PyCodeObject*>& tracked_funcs =
    *new std::unordered_set<PyCodeObject*>();

// Mark a function as being tracked - its lines and opcodes will be printed
// when tracing.
void TrackFunc(py::object func) {
  PyCodeObject* code = (PyCodeObject*)func.ptr();
  if (!PyCode_Check(code)) {
    // If func is an object with a __code__ attribute, use that.
    if (PyObject_HasAttrString(func.ptr(), "__code__")) {
      func = func.attr("__code__");
      code = (PyCodeObject*)func.ptr();
      if (!PyCode_Check(code)) {
        throw py::type_error("func.__code__ must be a code object");
      }
    } else {
      throw py::type_error(
          "func must be a code object or have a .__code__ attribute.");
    }
  }
  tracked_funcs.insert(code);
  func.release();
}

std::vector<std::string> CalculateOpcodeNames() {
  py::module_ dis = py::module_::import("dis");
  py::list opname = dis.attr("opname");
  return opname.cast<std::vector<std::string>>();
}

#define PY_MONITORING_SYS_TRACE_ID 7
extern "C" {
int _PyMonitoring_SetLocalEvents(PyCodeObject* code, int tool_id,
                                 uint32_t events);
}

int tracer(PyObject* obj, PyFrameObject* frame, int what, PyObject* arg) {
  static const std::vector<std::string>& opcode_names =
      *new std::vector<std::string>(CalculateOpcodeNames());

  PyObject* py_frame = (PyObject*)frame;

  static PyObject* attr_name = PyUnicode_FromString("f_trace_opcodes");
  PyObject_SetAttr(py_frame, attr_name, Py_True);

  if (what == PyTrace_LINE || what == PyTrace_OPCODE) {
    auto code = PyFrame_GetCode(frame);

    if (tracked_funcs.find(code) == tracked_funcs.end()) {
      Py_DECREF(code);
      return 0;
    }

    uint32_t events = 0b111111111;
    if (0 != _PyMonitoring_SetLocalEvents(code, PY_MONITORING_SYS_TRACE_ID,
                                          events)) {
      Py_DECREF(code);
      throw py::error_already_set();
    }

    PyObject* name_pystr = PyObject_Str(code->co_name);
    PyObject* filename_pystr = PyObject_Str(code->co_filename);
    std::string name = py::str(name_pystr).cast<std::string>();
    std::string filename = py::str(filename_pystr).cast<std::string>();
    Py_DECREF(name_pystr);
    Py_DECREF(filename_pystr);

    if (what == PyTrace_LINE) {
      std::cerr << name << ":" << PyFrame_GetLineNumber(frame) << std::endl;

    } else if (what == PyTrace_OPCODE) {
      int opcode_index = PyFrame_GetLasti(frame);
      PyBytesObject* co_code = (PyBytesObject*)PyCode_GetCode(code);
      int opcode = (unsigned char)PyBytes_AS_STRING(co_code)[opcode_index];
      Py_DECREF(co_code);
      const char* opcode_name = opcode_names[opcode].c_str();

      std::cerr << "  offset: " << opcode_index << ", opcode: " << opcode
                << "\t" << opcode_name << std::endl;
    }

    Py_DECREF(code);
  }

  return 0;
}

// Activate the tracer defined in this module.
void EnableTracing() { PyEval_SetTrace(tracer, nullptr); }

PYBIND11_MODULE(debug, m) {
  m.def("EnableTracing", &EnableTracing);
  m.def("TrackFunc", &TrackFunc);
}
