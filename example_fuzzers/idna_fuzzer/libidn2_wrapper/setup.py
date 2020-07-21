# Copyright 2020 Google LLC
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
from setuptools.command.build_ext import build_ext
import sys
import setuptools

__version__ = '0.0.1'


class get_pybind_include(object):

  def __str__(self):
    import pybind11
    return pybind11.get_include()


ext_modules = [
    Extension(
        'libidn2',
        ['libidn2.cc'],
        include_dirs=[
            # Path to pybind11 headers
            get_pybind_include(),
        ],
        language='c++'),
]


class BuildExt(build_ext):
  """A custom build extension for adding compiler-specific options."""
  c_opts = {
      'unix': [],
  }
  l_opts = {
      'unix': ['-lidn2'],
  }

  if sys.platform == 'darwin':
    darwin_opts = ['-stdlib=libc++', '-mmacosx-version-min=10.7']
    c_opts['unix'] += darwin_opts
    l_opts['unix'] += darwin_opts

  def build_extensions(self):
    ct = self.compiler.compiler_type
    opts = self.c_opts.get(ct, [])
    link_opts = self.l_opts.get(ct, [])
    if ct == 'unix':
      opts.append('--std=c++11')

    for ext in self.extensions:
      ext.define_macros = [('VERSION_INFO',
                            '"{}"'.format(self.distribution.get_version()))]
      ext.extra_compile_args = opts
      ext.extra_link_args = link_opts
    build_ext.build_extensions(self)


setup(
    name='libidn2',
    version=__version__,
    author='Ian Eldred Pudney',
    author_email='puddles@google.com',
    url='',
    description='A simple wrapper around libidn2, for use with idna_fuzzer.py',
    long_description='',
    ext_modules=ext_modules,
    setup_requires=['pybind11>=2.5.0'],
    cmdclass={'build_ext': BuildExt},
    zip_safe=False,
)
