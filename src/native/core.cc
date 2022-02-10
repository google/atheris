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

#include "counters.h"
#include "macros.h"
#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"
#include "timeout.h"
#include "tracer.h"
#include "util.h"

using UserCb = int (*)(const uint8_t* Data, size_t Size);

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

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
  static bool dummy = OnFirstTestOneInput();
  (void)dummy;
  RefreshTimeout();
  const auto alloc = AllocateCountersAndPcs();
  if (alloc.counters_start && alloc.counters_end) {
    __sanitizer_cov_8bit_counters_init(alloc.counters_start,
                                       alloc.counters_end);
  }
  if (alloc.pctable_start && alloc.pctable_end) {
    __sanitizer_cov_pcs_init(alloc.pctable_start, alloc.pctable_end);
  }

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

  m.def("Mutate", &Mutate);
}

}  // namespace atheris
