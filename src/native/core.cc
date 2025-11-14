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

#include <Python.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <exception>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <string_view>

#include "counters.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "timeout.h"
#include "tracer.h"
#include "util.h"

using UserCb = int (*)(const uint8_t* Data, size_t Size);

NO_SANITIZE
std::optional<int64_t> to_int64(PyObject* obj) {
  PyObject *type, *value, *traceback;
  PyErr_Fetch(&type, &value, &traceback);

  int64_t result = PyLong_AsLongLong(obj);

  if (PyErr_Occurred()) {
    PyErr_Clear();
    // Restore the original error state.
    PyErr_Restore(type, value, traceback);
    return std::nullopt;
  } else {
    PyErr_Restore(type, value, traceback);
    return result;
  }
}

extern "C" {
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size));
size_t LLVMFuzzerMutate(uint8_t* Data, size_t Size, size_t MaxSize);
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);
}

NO_SANITIZE
std::string GetLibFuzzerSymbolsLocation() {
  Dl_info dl_info;
  if (!dladdr((void*)&LLVMFuzzerRunDriver, &dl_info)) {
    return "<Not a shared object>";
  }
  return (dl_info.dli_fname);
}

NO_SANITIZE
std::string GetCoverageSymbolsLocation() {
  Dl_info dl_info;
  if (!dladdr((void*)&__sanitizer_cov_8bit_counters_init, &dl_info)) {
    return "<Not a shared object>";
  }
  return (dl_info.dli_fname);
}

namespace atheris {

namespace py = pybind11;

std::function<void(py::bytes data)>& test_one_input_global =
    *new std::function<void(py::bytes data)>([](py::bytes data) -> void {
      std::cerr << "You must call Setup() before Fuzz()." << std::endl;
      throw std::runtime_error("You must call Setup() before Fuzz().");
    });
int64_t runs = -1;  // Default from libFuzzer, means infinite
int64_t completed_runs = 0;
int64_t fuzzer_start_time;

NO_SANITIZE
void Init() {
  if (!&LLVMFuzzerRunDriver) {
    throw std::runtime_error(
        "LLVMFuzzerRunDriver symbol not found. This means "
        "you had an old version of Clang installed when "
        "you built Atheris.");
  }

  if (GetCoverageSymbolsLocation() != GetLibFuzzerSymbolsLocation()) {
    std::cerr << Colorize(
        STDERR_FILENO,
        "WARNING: Coverage symbols are being provided by a library other than "
        "libFuzzer. This will result in broken Python code coverage and "
        "severely impacted native extension code coverage. Symbols are coming "
        "from this library: " +
            GetCoverageSymbolsLocation() +
            "\nYou can likely resolve this issue by linking libFuzzer into "
            "Python directly, and using `atheris_no_libfuzzer` instead of "
            "`atheris`. See using_sanitizers.md for details.");
  }
}

// These versions of _trace_branch and _trace_cmp are called after fuzzing has
// begun.

NO_SANITIZE
void _trace_branch(uint64_t idx) { IncrementCounter(idx); }

NO_SANITIZE
py::handle _trace_cmp(py::handle left, py::handle right, int opid, uint64_t idx,
                      bool left_is_const) {
  // Give `idx` as a fake pc.
  PyObject* ret = TraceCompareOp(reinterpret_cast<void*>(idx), left.ptr(),
                                 right.ptr(), opid, left_is_const);

  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}


NO_SANITIZE
bool OnFirstTestOneInput() {
  SetupTimeoutAlarm();
  return true;
}

// Initialize 8bit-counter and PC arrays when needed.
NO_SANITIZE
void UpdateCounterArrays() {
  const auto alloc = AllocateCountersAndPcs();
  if (alloc.counters_start && alloc.counters_end) {
    __sanitizer_cov_8bit_counters_init(alloc.counters_start,
                                       alloc.counters_end);
  }
  if (alloc.pctable_start && alloc.pctable_end) {
    __sanitizer_cov_pcs_init(alloc.pctable_start, alloc.pctable_end);
  }
}

extern "C" {

#if PY_MINOR_VERSION < 13

PyCFunction original_unicode_startswith = nullptr;
PyCFunction original_unicode_endswith = nullptr;
PyCFunction original_bytes_startswith = nullptr;
PyCFunction original_bytes_endswith = nullptr;

NO_SANITIZE
static PyObject* hooked_withfunc(PyObject* self, PyObject* args,
                                 PyCFunction original, bool is_endswith) {
  int64_t start = 0;
  int64_t end = std::numeric_limits<int64_t>::max();
  if (args == nullptr || !PyTuple_Check(args)) {
    return original(self, args);
  }

  PyObject* prefix = PyTuple_GetItem(args, 0);

  if (PyTuple_Size(args) > 1 && !Py_IsNone(PyTuple_GetItem(args, 1))) {
    std::optional<int64_t> opt_start = to_int64(PyTuple_GetItem(args, 1));
    if (!opt_start) {
      return original(self, args);
    }
    start = *opt_start;
  }
  if (PyTuple_Size(args) > 2 && !Py_IsNone(PyTuple_GetItem(args, 2))) {
    std::optional<int64_t> opt_end = to_int64(PyTuple_GetItem(args, 2));
    if (!opt_end) {
      return original(self, args);
    }
    end = *opt_end;
  }
  TraceWith(self, prefix, start, end, is_endswith);

  return original(self, args);
}

static PyObject* hooked_unicode_startswith(PyObject* self, PyObject* args) {
  return hooked_withfunc(self, args, original_unicode_startswith, false);
}

static PyObject* hooked_unicode_endswith(PyObject* self, PyObject* args) {
  return hooked_withfunc(self, args, original_unicode_endswith, true);
}

static PyObject* hooked_bytes_startswith(PyObject* self, PyObject* args) {
  return hooked_withfunc(self, args, original_bytes_startswith, false);
}

static PyObject* hooked_bytes_endswith(PyObject* self, PyObject* args) {
  std::cerr << "hooked_bytes_endswith" << std::endl;
  return hooked_withfunc(self, args, original_bytes_endswith, true);
}

#else  // 3.13 or greater changed the calling convention

PyCFunctionFast original_unicode_startswith = nullptr;
PyCFunctionFast original_unicode_endswith = nullptr;
PyCFunctionFast original_bytes_startswith = nullptr;
PyCFunctionFast original_bytes_endswith = nullptr;

static PyObject* hooked_withfunc(PyObject* self, PyObject** args,
                                 Py_ssize_t nargs, PyCFunctionFast original,
                                 bool is_endswith) {
  int64_t start = 0;
  int64_t end = std::numeric_limits<int64_t>::max();
  if (args == nullptr || nargs < 1) {
    return original(self, args, nargs);
  }

  PyObject* prefix = args[0];

  if (nargs > 1 && !Py_IsNone(args[1])) {
    std::optional<int64_t> opt_start = to_int64(args[1]);
    if (!opt_start) {
      return original(self, args, nargs);
    }
    start = *opt_start;
  }
  if (nargs > 2 && !Py_IsNone(args[2])) {
    std::optional<int64_t> opt_end = to_int64(args[2]);
    if (!opt_end) {
      return original(self, args, nargs);
    }
    end = *opt_end;
  }
  TraceWith(self, prefix, start, end, is_endswith);

  return original(self, args, nargs);
}

static PyObject* hooked_unicode_startswith(PyObject* self, PyObject** args,
                                           Py_ssize_t nargs) {
  return hooked_withfunc(self, args, nargs, original_unicode_startswith, false);
}

static PyObject* hooked_unicode_endswith(PyObject* self, PyObject** args,
                                         Py_ssize_t nargs) {
  return hooked_withfunc(self, args, nargs, original_unicode_endswith, true);
}

static PyObject* hooked_bytes_startswith(PyObject* self, PyObject** args,
                                         Py_ssize_t nargs) {
  return hooked_withfunc(self, args, nargs, original_bytes_startswith, false);
}

static PyObject* hooked_bytes_endswith(PyObject* self, PyObject** args,
                                       Py_ssize_t nargs) {
  return hooked_withfunc(self, args, nargs, original_bytes_endswith, true);
}
#endif

}  // extern "C"

NO_SANITIZE
void hook_str_module() {
  if (original_unicode_startswith != nullptr) {
    return;
  }

  PyObject* tmp_str = PyUnicode_FromString("foo");
  PyMethodDef* tp_methods = tmp_str->ob_type->tp_methods;
  while (tp_methods->ml_name) {
    if (tp_methods->ml_name == std::string_view("startswith")) {
      original_unicode_startswith =
          reinterpret_cast<decltype(original_unicode_startswith)>(
              tp_methods->ml_meth);
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          hooked_unicode_startswith);
      std::cerr << "[INFO] Hooked str.startswith" << std::endl;
    }
    if (tp_methods->ml_name == std::string_view("endswith")) {
      original_unicode_endswith =
          reinterpret_cast<decltype(original_unicode_endswith)>(
              tp_methods->ml_meth);
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          hooked_unicode_endswith);
      std::cerr << "[INFO] Hooked str.endswith" << std::endl;
    }
    tp_methods++;
  }
  Py_DECREF(tmp_str);

  PyObject* tmp_bytes = PyBytes_FromString("foo");
  tp_methods = tmp_bytes->ob_type->tp_methods;
  while (tp_methods->ml_name) {
    if (tp_methods->ml_name == std::string_view("startswith")) {
      original_bytes_startswith =
          reinterpret_cast<decltype(original_bytes_startswith)>(
              tp_methods->ml_meth);
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          hooked_bytes_startswith);
      std::cerr << "[INFO] Hooked bytes.startswith" << std::endl;
    }
    if (tp_methods->ml_name == std::string_view("endswith")) {
      original_bytes_endswith =
          reinterpret_cast<decltype(original_bytes_endswith)>(
              tp_methods->ml_meth);
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          hooked_bytes_endswith);
      std::cerr << "[INFO] Hooked bytes.endswith" << std::endl;
    }
    tp_methods++;
  }
  Py_DECREF(tmp_bytes);
}

void unhook_str_module() {
  PyObject* tmp_str = PyUnicode_FromString("foo");
  PyMethodDef* tp_methods = tmp_str->ob_type->tp_methods;
  while (tp_methods->ml_name) {
    if (original_unicode_startswith != nullptr &&
        tp_methods->ml_name == std::string_view("startswith")) {
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          original_unicode_startswith);
      original_unicode_startswith = nullptr;
      std::cerr << "[INFO] Unhooked str.startswith" << std::endl;
    }
    if (original_unicode_endswith != nullptr &&
        tp_methods->ml_name == std::string_view("endswith")) {
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          original_unicode_endswith);
      original_unicode_endswith = nullptr;
      std::cerr << "[INFO] Unhooked str.endswith" << std::endl;
    }
    tp_methods++;
  }
  Py_DECREF(tmp_str);

  PyObject* tmp_bytes = PyBytes_FromString("foo");
  tp_methods = tmp_bytes->ob_type->tp_methods;
  while (tp_methods->ml_name) {
    if (original_bytes_startswith != nullptr &&
        tp_methods->ml_name == std::string_view("startswith")) {
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          original_bytes_startswith);
      original_bytes_startswith = nullptr;
      std::cerr << "[INFO] Unhooked bytes.startswith" << std::endl;
    }
    if (original_bytes_endswith != nullptr &&
        tp_methods->ml_name == std::string_view("endswith")) {
      tp_methods->ml_meth = reinterpret_cast<decltype(tp_methods->ml_meth)>(
          original_bytes_endswith);
      original_bytes_endswith = nullptr;
      std::cerr << "[INFO] Unhooked bytes.endswith" << std::endl;
    }
    tp_methods++;
  }
  Py_DECREF(tmp_bytes);
}

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
  static bool dummy = OnFirstTestOneInput();
  (void)dummy;
  RefreshTimeout();

  UpdateCounterArrays();

  try {
    test_one_input_global(py::bytes(reinterpret_cast<const char*>(data), size));
  } catch (py::error_already_set& ex) {
    std::string exception_type = GetExceptionType(ex);
    if (exception_type == "KeyboardInterrupt" ||
        exception_type == "exceptions.KeyboardInterrupt") {
      // Unfortunately, this can occur in the transition between Python and C++,
      // in which case it's impossible to catch in Python. Exit here instead.
      std::cout << Colorize(STDOUT_FILENO, "KeyboardInterrupt: stopping.")
                << std::endl;
      GracefulExit(130);
    }
    std::cout << Colorize(STDOUT_FILENO,
                          "\n === Uncaught Python exception: ===\n");
    PrintPythonException(ex, std::cout);
    GracefulExit(-1, /*prevent_crash_report=*/false);
  }

  --runs;
  ++completed_runs;
  if (!runs) {
    // We've completed all requested runs.
    uint64_t elapsed_time =
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count() -
        fuzzer_start_time;
    std::cerr << "Done " << completed_runs << " in " << elapsed_time
              << " second(s)" << std::endl;
    GracefulExit(0);
  }

  return 0;
}

NO_SANITIZE
void start_fuzzing(const std::vector<std::string>& args,
                   const std::function<void(py::bytes data)>& test_one_input) {
  test_one_input_global = test_one_input;

  bool registered_alarm = SetupPythonSigaction();

  std::vector<char*> arg_array;
  arg_array.reserve(args.size() + 1);
  for (const std::string& arg : args) {
    // We care about certain arguments. Other arguments are passed through to
    // libFuzzer.
    if (arg.substr(0, 9) == "-timeout=") {
      if (!registered_alarm) {
        std::cerr << "WARNING: -timeout ignored." << std::endl;
      }
      SetTimeout(std::stoi(arg.substr(9, std::string::npos)));
    }
    if (arg.substr(0, 14) == "-atheris_runs=") {
      // We want to handle 'runs' ourselves so we can exit gracefully rather
      // than letting libFuzzer call _exit().
      // This is a different flag from -runs because -runs sometimes has other
      // unrelated behavior. For example, if you set -runs when running with
      // a fixed set of inputs, *each* input will be run that many times. The
      // -atheris_runs= flag always performs precisely the specified number of
      // runs.
      runs = std::stoll(arg.substr(14, std::string::npos));
      continue;
    }
    if (arg.substr(0, 14) == "-max_counters=") {
      int max = std::stoll(arg.substr(14, std::string::npos));
      SetMaxCounters(max);
      continue;
    }

    arg_array.push_back(const_cast<char*>(arg.c_str()));
  }

  arg_array.push_back(nullptr);
  char** args_ptr = &arg_array[0];
  int args_size = arg_array.size() - 1;

  fuzzer_start_time = std::chrono::duration_cast<std::chrono::seconds>(
                          std::chrono::system_clock::now().time_since_epoch())
                          .count();

  GracefulExit(LLVMFuzzerRunDriver(&args_size, &args_ptr, &TestOneInput));
}

NO_SANITIZE
py::bytes Mutate(py::bytes data, size_t max_size) {
  std::string d = data;
  size_t old_size = d.size();
  d.resize(max_size);
  size_t new_size = LLVMFuzzerMutate(
      const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(d.data())),
      old_size, max_size);
  return py::bytes(d.data(), new_size);
}

#ifndef ATHERIS_MODULE_NAME
#define ATHERIS_MODULE_NAME core_with_libfuzzer
#endif  // ATHERIS_MODULE_NAME

PYBIND11_MODULE(ATHERIS_MODULE_NAME, m) {
  Init();

  m.def("start_fuzzing", &start_fuzzing);
  m.def("_trace_branch", &_trace_branch);
  m.def("_reserve_counter", ReserveCounter);
  m.def("_reserve_counters", ReserveCounters);
  m.def("_trace_cmp", &_trace_cmp, py::return_value_policy::move);
  m.def("_trace_regex_match", &TraceRegexMatch);
  m.def("hook_str_module", &hook_str_module);
  m.def("unhook_str_module", &unhook_str_module);
  // Exposed for testing.
  m.def("UpdateCounterArrays", &UpdateCounterArrays);

  m.def("Mutate", &Mutate);
}

}  // namespace atheris
