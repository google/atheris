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

#include <exception>
#include <iostream>
#include <sstream>

#include "atheris.h"
#include "macros.h"
#include "util.h"
#include "tracer.h"

using UserCb = int (*)(const uint8_t* Data, size_t Size);              
                              
extern "C" {
  int LLVMFuzzerRunDriver(int* argc, char*** argv, int (*UserCb)(const uint8_t* Data, size_t Size));
  void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
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

bool setup_called = false;

unsigned long long num_counters = 0;
unsigned char* counters = NULL;

}  // namespace

NO_SANITIZE
void _loc(unsigned long long idx) {
  if (counters && idx < num_counters) {
    counters[idx]++;
  }
}

NO_SANITIZE
void _reg(unsigned long long num) {
  num_counters += num;
}

NO_SANITIZE
py::handle _cmp (py::handle left, py::handle right, int opid, unsigned long long idx, bool left_is_const) {
  return TraceCompareOp(counters + idx, left.ptr(), right.ptr(), opid, left_is_const);
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
    const std::function<void(py::bytes data)>& test_one_input,
    py::kwargs kwargs) {
  if (setup_called) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Setup() must not be called more than once.")
              << std::endl;
    exit(1);
  }
  setup_called = true;

  args_global = args;
  test_one_input_global = test_one_input;

  int print_funcs = 2;

  // Parse out any libFuzzer flags we also care about.
  for (const std::string& arg : args) {
    if (arg.substr(0, 13) == "-print_funcs=") {
      print_funcs = std::stoul(arg.substr(13, std::string::npos));
    }
  }

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

  std::vector<char*> args;
  args.reserve(args_global.size() + 1);
  for (const std::string& arg : args_global) {
    args.push_back(const_cast<char*>(arg.c_str()));
  }
  args.push_back(nullptr);
  char** args_ptr = &args[0];
  int args_size = args_global.size();
  
  if (num_counters) {
    counters = new unsigned char[num_counters];
    memset(counters, 0, num_counters);
    __sanitizer_cov_8bit_counters_init(counters, counters + num_counters);
  }

  exit(LLVMFuzzerRunDriver(&args_size, &args_ptr, &TestOneInput));
}

}  // namespace atheris
