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
#include <sstream>

#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "timeout.h"
#include "tracer.h"
#include "util.h"

struct PCTableEntry {
  void* pc;
  long flags;
};

using UserCb = int (*)(const uint8_t* Data, size_t Size);

extern "C" {
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size));
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
      _exit(-1);
    });
std::vector<unsigned char>& counters = *new std::vector<unsigned char>();
std::vector<struct PCTableEntry>& pctable =
    *new std::vector<struct PCTableEntry>();

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

// These versions of _trace_branch, _trace_cmp, and _reserve_counters are called
// after fuzzing has begun.

NO_SANITIZE
void _trace_branch(uint64_t idx) {
  if (idx < counters.size()) {
    counters[idx]++;
  }
}

NO_SANITIZE
py::handle _trace_cmp(py::handle left, py::handle right, int opid, uint64_t idx,
                      bool left_is_const) {
  PyObject* ret = TraceCompareOp(&counters[0] + idx, left.ptr(), right.ptr(),
                                 opid, left_is_const);

  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}

NO_SANITIZE
void _reserve_counters(uint64_t num) {
  std::cerr << Colorize(
                   STDERR_FILENO,
                   "Tried to reserve counters after fuzzing has been started.")
            << std::endl
            << Colorize(STDERR_FILENO,
                        "This is not supported. Instrument the modules before "
                        "calling atheris.Fuzz().")
            << std::endl;
  _exit(-1);
}

NO_SANITIZE
bool OnFirstTestOneInput() {
  SetupTimeoutAlarm();
  return true;
}

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
  static bool dummy = OnFirstTestOneInput();
  (void)dummy;
  RefreshTimeout();

  try {
    test_one_input_global(py::bytes(reinterpret_cast<const char*>(data), size));
    return 0;
  } catch (py::error_already_set& ex) {
    std::string exception_type = GetExceptionType(ex);
    if (exception_type == "KeyboardInterrupt" ||
        exception_type == "exceptions.KeyboardInterrupt") {
      // Unfortunately, this can occur in the transition between Python and C++,
      // in which case it's impossible to catch in Python. Exit here instead.
      std::cout << Colorize(STDOUT_FILENO, "KeyboardInterrupt: stopping.")
                << std::endl;
      _exit(130);  // Prevent libFuzzer from thinking this is a crash.
    }
    std::cout << Colorize(STDOUT_FILENO,
                          "\n === Uncaught Python exception: ===\n");
    PrintPythonException(ex, std::cout);
    exit(-1);
  }
}

NO_SANITIZE
void start_fuzzing(const std::vector<std::string>& args,
                   const std::function<void(py::bytes data)>& test_one_input,
                   uint64_t num_counters) {
  test_one_input_global = test_one_input;

  bool registered_alarm = SetupPythonSigaction();

  std::vector<char*> arg_array;
  arg_array.reserve(args.size() + 1);
  for (const std::string& arg : args) {
    // We specially care about timeouts.
    if (arg.substr(0, 9) == "-timeout=") {
      if (!registered_alarm) {
        std::cerr << "WARNING: -timeout ignored." << std::endl;
      }
      SetTimeout(std::stoi(arg.substr(9, std::string::npos)));
    }

    arg_array.push_back(const_cast<char*>(arg.c_str()));
  }

  arg_array.push_back(nullptr);
  char** args_ptr = &arg_array[0];
  int args_size = arg_array.size() - 1;

  if (num_counters) {
    counters.resize(num_counters, 0);
    __sanitizer_cov_8bit_counters_init(&counters[0],
                                       &counters[0] + counters.size());

    pctable.resize(num_counters);

    for (int i = 0; i < pctable.size(); ++i) {
      pctable[i].pc = reinterpret_cast<void*>(i + 1);
      pctable[i].flags = 0;
    }

    __sanitizer_cov_pcs_init(
        reinterpret_cast<uint8_t*>(&pctable[0]),
        reinterpret_cast<uint8_t*>(&pctable[0] + pctable.size()));
  }

  exit(LLVMFuzzerRunDriver(&args_size, &args_ptr, &TestOneInput));
}

#ifndef ATHERIS_MODULE_NAME
#define ATHERIS_MODULE_NAME core_with_libfuzzer
#endif  // ATHERIS_MODULE_NAME

PYBIND11_MODULE(ATHERIS_MODULE_NAME, m) {
  Init();

  m.def("start_fuzzing", &start_fuzzing);
  m.def("_trace_branch", &_trace_branch);
  m.def("_reserve_counters", &_reserve_counters);
  m.def("_trace_cmp", &_trace_cmp, py::return_value_policy::move);
}

}  // namespace atheris
