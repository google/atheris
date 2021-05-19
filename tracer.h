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

#ifndef THIRD_PARTY_PY_ATHERIS_TRACER_H_
#define THIRD_PARTY_PY_ATHERIS_TRACER_H_

#include <Python.h>

namespace atheris {

PyObject* TraceCompareOp(void* pc, PyObject* left, PyObject* right, int opid,
                         bool left_is_const);

}  // namespace atheris

#endif  // THIRD_PARTY_PY_ATHERIS_TRACER_H_
