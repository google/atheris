// Copyright 2021 Google LLC
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

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

#include <Python.h>
#include <exception>
#include <iostream>
#include <sstream>

#include "atheris.h"
#include "macros.h"
#include "util.h"
#include "tracer.h"

struct PCTableEntry {
    void* pc;
    long  flags;
};

using UserCb = int (*)(const uint8_t* Data, size_t Size);              
                              
extern "C" {
  int LLVMFuzzerRunDriver(int* argc, char*** argv, int (*UserCb)(const uint8_t* Data, size_t Size));
  void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
  void __sanitizer_cov_pcs_init(uint8_t *pcs_beg, uint8_t *pcs_end);
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

namespace {

std::function<void(py::bytes data)>& test_one_input_global =
    *new std::function<void(py::bytes data)>([](py::bytes data) -> void {
      std::cerr << "You must call Setup() before Fuzz()." << std::endl;
      _exit(-1);
    });

std::vector<std::string>& args_global = *new std::vector<std::string>();
std::vector<unsigned char>& counters = *new std::vector<unsigned char>();
std::vector<struct PCTableEntry>& pctable = *new std::vector<struct PCTableEntry>();
bool setup_called = false;
bool fuzz_called = false;

}  // namespace

NO_SANITIZE
void _trace_branch(unsigned long long idx) {
  if (idx < counters.size()) {
    counters[idx]++;
  }
}

NO_SANITIZE
void _reserve_counters(unsigned long long num) {
  if (fuzz_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Tried to reserve counters after fuzzing has been started.")
              << std::endl
              << Colorize(STDERR_FILENO,
                          "This is not supported. Instrument _all_ modules before calling atheris.Fuzz().")
              << std::endl;
    _exit(-1);
  }

  if (num > 0) {
    counters.resize(counters.size() + num, 0);
    
    int old_pctable_size = pctable.size();
    pctable.resize(old_pctable_size + num);
    
    for (int i = old_pctable_size; i < pctable.size(); ++i) {
      pctable[i].pc = reinterpret_cast<void*>(i + 1);
      pctable[i].flags = 0;
    }
  }
}

NO_SANITIZE
py::handle _cmp(py::handle left, py::handle right, int opid, unsigned long long idx, bool left_is_const) {
  PyObject* ret = TraceCompareOp(&counters[0] + idx, left.ptr(), right.ptr(), opid, left_is_const);
  
  if (ret == nullptr) {
    throw py::error_already_set();
  } else {
    return ret;
  }
}

NO_SANITIZE
void Init() {
  if (!&LLVMFuzzerRunDriver) {
    throw std::runtime_error(
        "LLVMFuzzerRunDriver symbol not found. This means "
        "you had an old version of Clang installed when "
        "you built Atheris.");
  }
}

NO_SANITIZE
std::vector<std::string> Setup(
    const std::vector<std::string>& args,
    const std::function<void(py::bytes data)>& test_one_input) {
  if (setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must not be called more than once.")
              << std::endl;
    exit(1);
  }
  setup_called = true;

  args_global = args;
  test_one_input_global = test_one_input;

  // Strip libFuzzer arguments (single dash).
  std::vector<std::string> ret;
  for (const std::string& arg : args) {
    if (arg.size() > 1 && arg[0] == '-' && arg[1] != '-') {
      continue;
    }
    ret.push_back(arg);
  }
  
  if (GetCoverageSymbolsLocation() != GetLibFuzzerSymbolsLocation()) {
    std::cerr << Colorize(STDERR_FILENO, "WARNING: Coverage symbols are being provided by a library other than libFuzzer. This will result in broken Python code coverage and severely impacted native extension code coverage. Symbols are coming from this library: " + GetCoverageSymbolsLocation() + "\nYou can likely resolve this issue by linking libFuzzer into Python directly, and using `atheris_no_libfuzzer` instead of `atheris`. See using_sanitizers.md for details.");
  }

  return ret;
}

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
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
void Fuzz() {
  if (!setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must be called before Fuzz() can be called.")
              << std::endl;
    exit(1);
  }
  
  fuzz_called = true;

  std::vector<char*> args;
  args.reserve(args_global.size() + 1);
  for (const std::string& arg : args_global) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);
  char** args_ptr = &args[0];
  int args_size = args_global.size();
  
  if (!counters.empty()) {
    __sanitizer_cov_8bit_counters_init(&counters[0], &counters[0] + counters.size());
    __sanitizer_cov_pcs_init(reinterpret_cast<uint8_t*>(&pctable[0]), reinterpret_cast<uint8_t*>(&pctable[0] + pctable.size()));
  }

  exit(LLVMFuzzerRunDriver(&args_size, &args_ptr, &TestOneInput));
}

}  // namespace atheris
