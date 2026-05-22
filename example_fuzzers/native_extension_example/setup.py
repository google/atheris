#!/usr/bin/python3

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, Extension
import sys


class get_pybind_include(object):

  def __str__(self):
    import pybind11
    return pybind11.get_include()


extra_compile_args = ['-std=c++17']
extra_link_args = []
if sys.platform == 'darwin':
  darwin_opts = ['-stdlib=libc++', '-mmacosx-version-min=10.7']
  extra_compile_args += darwin_opts
  extra_link_args += darwin_opts

setup(
    name='dummy',
    version='0.0.1',
    description='Intentionally buggy native extension for Atheris demos',
    ext_modules=[
        Extension(
            'dummy',
            ['dummy.cc'],
            include_dirs=[get_pybind_include()],
            language='c++',
            extra_compile_args=extra_compile_args,
            extra_link_args=extra_link_args,
        ),
    ],
    setup_requires=['pybind11>=2.5.0'],
    zip_safe=False,
)
