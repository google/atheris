#ifndef ATHERIS_CUSTOM_CROSSOVER_H_
#define ATHERIS_CUSTOM_CROSSOVER_H_

#include <stddef.h>
#include <stdint.h>

#include "pybind11/functional.h"
#include "pybind11/pybind11.h"
#include "pybind11/stl.h"

namespace atheris {

namespace py = pybind11;

void _set_custom_crossover(
    const std::function<py::bytes(py::bytes data1, py::bytes data2,
                                  size_t max_out_size, unsigned int seed)>&
        custom_crossover_func);

}  // namespace atheris

#endif  // ATHERIS_CUSTOM_CROSSOVER_H_
