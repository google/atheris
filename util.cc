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

#include "util.h"

#include <stdio.h>
#include <unistd.h>

#include <exception>
#include <iostream>
#include <sstream>

#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include <dlfcn.h>

namespace atheris {

namespace py = pybind11;

// If the specified file is connected to a terminal, colorize the message in
// bold red. Otherwise, just return the message.
std::string Colorize(int fileno, const std::string& message) {
  if (isatty(fileno)) {
    return "\u001b[31m\u001b[1m" + message + "\u001b[0m";
  } else {
    return message;
  }
}

void PrintPythonException(const py::error_already_set& ex, std::ostream& os) {
  // Strip out some extra, redundant information pybind11 includes
  std::string what = ex.what();
  what = what.substr(0, what.find("\n\nAt:\n"));

  os << what << std::endl;

  py::module traceback = py::module::import("traceback");
  py::handle format_tb = traceback.attr("format_tb");
  py::object stack = format_tb.call(ex.trace());
  auto printable_stack = stack.cast<std::vector<std::string>>();
  os << "Traceback (most recent call last):\n";
  for (const std::string& str : printable_stack) {
    os << str;
  }
  os << std::endl;
}

std::string GetExceptionType(const pybind11::error_already_set& ex) {
  return ex.type().attr("__name__").str();
}

std::string GetExceptionMessage(const pybind11::error_already_set& ex) {
  return ex.value().str();
}

bool StartsWith(const char* text, const char* prefix) {
  while (*prefix) {
    if (*text != *prefix) return false;
    ++text;
    ++prefix;
  }
  return true;
}

#if PY_MAJOR_VERSION >= 3

py::object UnicodeFromKindAndData(int kind, const void* buffer, ssize_t size) {
  return py::object(py::handle(PyUnicode_FromKindAndData(kind, buffer, size)),
                    false);
}

#else

py::object UnicodeFromKindAndData(int kind, const void* buffer, ssize_t size) {
  int little_endian = -1;
  PyObject* ret = nullptr;
  if (kind == 4) {
    ret = PyUnicode_DecodeUTF32(reinterpret_cast<const char*>(buffer), size * 4,
                                nullptr, &little_endian);
  } else if (kind == 2) {
    // For UTF-16, we cannot use DecodeUTF16 because we might not want surrogate
    // pair bytes decoded.
    ret = PyUnicode_FromUnicode(nullptr, size);
    auto* new_buf = PyUnicode_AsUnicode(ret);

    for (int i = 0; i < size; ++i, ++new_buf) {
      *new_buf = reinterpret_cast<const uint16_t*>(buffer)[i];
    }
  } else if (kind == 1) {
    ret = PyUnicode_DecodeASCII(reinterpret_cast<const char*>(buffer), size,
                                nullptr);
  }

  return py::object(py::handle(ret), false);
}

#endif  // PY_MAJOR_VERSION >= 3

py::bytes UnicodeToUtf8(py::handle unicode) {
  if (!PyUnicode_Check(unicode.ptr())) {
    return py::bytes();
  }

  PyObject *type, *value, *traceback;
  PyErr_Fetch(&type, &value, &traceback);

  // Fast path: just call Python's built-in function
  PyObject* obj = PyUnicode_AsUTF8String(unicode.ptr());

  if (obj) {
    PyErr_Restore(type, value, traceback);
    auto ret = py::cast<py::bytes>(obj);
    Py_DECREF(obj);
    return ret;
  }

  PyErr_Clear();
  PyErr_Restore(type, value, traceback);

  // Slow path: go via Python.
  py::object new_obj = unicode.attr("encode").call("utf-8", "surrogatepass");
  return py::cast<py::bytes>(new_obj);
}

extern "C" __attribute__((__visibility__("default"))) void
GetDynamicLocationSentinel() {}

std::string GetDynamicLocation() {
  Dl_info dl_info;
  if (!dladdr((void*)&GetDynamicLocationSentinel, &dl_info)) {
    return "<Not a shared object>";
  }
  return (dl_info.dli_fname);
}

}  // namespace atheris
