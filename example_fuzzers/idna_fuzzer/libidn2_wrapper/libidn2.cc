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

#include <idn2.h>

#include <iostream>

#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace libidn2_wrapper {

namespace py = pybind11;

py::bytes encode(const std::string& arg, bool uts46, bool transitional,
                       bool nfc, bool std3) {
  char* result;
  int flags = 0;

  if (nfc) {
    flags |= IDN2_NFC_INPUT;
  }

  if (uts46) {
    if (transitional)
      flags |= IDN2_TRANSITIONAL;
    else
      flags |= IDN2_NONTRANSITIONAL;
  }

  if (std3) {
    flags |= IDN2_USE_STD3_ASCII_RULES;
  }
  int err = idn2_to_ascii_8z(arg.c_str(), &result, flags);
  if (err != IDNA_SUCCESS) {
    throw std::runtime_error(idn2_strerror(err));
  }
  py::bytes ret(result);
  idn2_free(result);
  return ret;
}

std::string decode(const std::string& arg, bool uts46, bool std3) {
  char* result;
  int err = idn2_to_unicode_8z8z(arg.c_str(), &result, 0);
  if (err != IDNA_SUCCESS) {
    throw std::runtime_error(idn2_strerror(err));
  }
  std::string ret(result);
  idn2_free(result);
  return ret;
}

PYBIND11_MODULE(libidn2, m) {
  m.def("encode", &encode,
        py::arg("arg"),
        py::arg("uts46") = false,
        py::arg("transitional") = false,
        py::arg("nfc") = false,
        py::arg("std3") = false);
  m.def("decode", &decode,
        py::arg("arg"),
        py::arg("uts46") = false,
        py::arg("std3") = false);
}

}  // namespace libidn2_wrapper
