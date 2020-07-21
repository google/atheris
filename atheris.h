/*
 * Copyright 2020 Google LLC
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

// Compatible fuzzing engines must implement the functions specified in this
// header, and exactly one of them must be linked. See atheris.cc for
// documentation on the behavior of these functions.

#ifndef THIRD_PARTY_PY_ATHERIS_ATHERIS_H_
#define THIRD_PARTY_PY_ATHERIS_ATHERIS_H_

#include <functional>
#include <string>
#include <vector>

#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace atheris {

void Init();

std::vector<std::string> Setup(
    const std::vector<std::string>& args,
    const std::function<void(pybind11::bytes data)>& test_one_input,
    pybind11::kwargs kwargs);

void Fuzz();

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_LIBFUZZER_H_
