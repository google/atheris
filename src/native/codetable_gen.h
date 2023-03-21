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

#ifndef THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_CODETABLE_GEN_H_
#define THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_CODETABLE_GEN_H_

#include <Python.h>

#include "pybind11/pybind11.h"

namespace atheris {

namespace py = pybind11;

py::bytes GenerateCodetable(py::object original_code,
                            std::vector<py::object>& listing);

py::bytes GenerateExceptiontable(
    py::object original_code, std::vector<py::object>& exception_table_entries);

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_SRC_NATIVE_CODETABLE_GEN_H_
