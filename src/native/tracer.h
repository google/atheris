/*
 * Copyright 2020 Google LLC
 * Copyright 2021 Fraunhofer FKIE
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ATHERIS_TRACER_H_
#define ATHERIS_TRACER_H_

#include <Python.h>

#include "pybind11/pybind11.h"

namespace atheris {

PyObject* TraceCompareOp(void* pc, PyObject* left, PyObject* right, int opid,
                         bool left_is_const);

// Passes `generated_match` (str) to the backend fuzzer in a way that it will be
// emitted by the fuzzer. `re_obj` is the compiled regex object.
void TraceRegexMatch(std::string generated_match, pybind11::handle re_obj);

}  // namespace atheris

#endif  // ATHERIS_TRACER_H_
