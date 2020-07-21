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

#ifndef THIRD_PARTY_PY_ATHERIS_MACROS_H_
#define THIRD_PARTY_PY_ATHERIS_MACROS_H_

#define NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))

#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
#else
#define NO_SANITIZE_MEMORY
#endif  // __has_attribute(no_sanitize)
#else
#define NO_SANITIZE_MEMORY
#endif  // __has_attribute

#define NO_SANITIZE NO_SANITIZE_ADDRESS NO_SANITIZE_MEMORY

#endif  // THIRD_PARTY_PY_ATHERIS_MACROS_H_
