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

"""Setuptools for Atheris."""

import os
import shutil
import subprocess
import sys
import tempfile

import setuptools
from setuptools import Extension
from setuptools import setup
from setuptools.command.build_ext import build_ext

__version__ = os.getenv("ATHERIS_VERSION", "1.0.8")

if len(sys.argv) > 1 and sys.argv[1] == "print_version":
  print(__version__)
  quit()

clang_install_instructions = """download and build the latest version of Clang:
    git clone https://github.com/llvm/llvm-project.git
    cd llvm-project
    mkdir build
    cd build
    cmake -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' -G "Unix Makefiles" ../llvm
    make -j 100  # This step is very slow
Then, set $CLANG_BIN="$(pwd)/bin/clang" and run pip again.
You should use this same Clang for building any Python extensions you plan to fuzz.
"""

too_old_error = """Your libFuzzer version is too old; set either $CLANG_BIN to point to a more recent Clang, or $LIBFUZZER_VERSION to point directly to a more recent libFuzzer .a file. If needed, """ + clang_install_instructions

no_libfuzzer_error = """Failed to find libFuzzer; set either $CLANG_BIN to point to your Clang binary, or $LIBFUZZER_LIB to point directly to your libFuzzer .a file. If needed, """ + clang_install_instructions

if sys.platform == "darwin":
  too_old_error = ("Your libFuzzer version is too old.\nPlease" +
                   clang_install_instructions + "Do not use Apple "
                   "Clang; Apple Clang does not come with libFuzzer.")
  no_libfuzzer_error = ("Failed to find libFuzzer; you may be building using "
                        "Apple Clang. Apple Clang does not come with "
                        "libFuzzer.\nPlease " + clang_install_instructions)


class PybindIncludeGetter(object):
  """Helper class to determine the pybind11 include path.

    The purpose of this class is to postpone importing pybind11
    until it is actually installed, so that the ``get_include()``
    method can be invoked.
  """

  def __str__(self):
    import pybind11  # pylint: disable=g-import-not-at-top
    return pybind11.get_include()


def check_libfuzzer_version(libfuzzer):
  """Verifies that the specified libFuzzer is of a sufficiently high version."""
  current_path = os.path.dirname(os.path.realpath(__file__))
  try:
    version = subprocess.check_output(
        [current_path + "/setup_utils/check_libfuzzer_version.sh", libfuzzer])
  except subprocess.CalledProcessError as e:
    sys.stderr.write("Failed to check libFuzzer version: %s" % e.stderr)
    sys.stderr.write("Assuming libFuxzzer is up-to-date.")
    return "up-to-date"
  version = version.strip().decode("utf-8")
  return version


def upgrade_libfuzzer(libfuzzer):
  """Hacky code for upgrading libFuzzer to be compatible with Atheris."""
  current_path = os.path.dirname(os.path.realpath(__file__))
  try:
    new_libfuzzer = subprocess.check_output(
        [current_path + "/setup_utils/upgrade_libfuzzer.sh", libfuzzer])
  except subprocess.CalledProcessError as e:
    sys.stderr.write("libFuzzer upgrade failed: %s" % e.stderr)
    return libfuzzer
  new_libfuzzer = new_libfuzzer.strip().decode("utf-8")
  return new_libfuzzer


def get_libfuzzer_lib():
  """Returns path to the libFuzzer .a library."""
  libfuzzer_lib = os.getenv("LIBFUZZER_LIB", "")
  if libfuzzer_lib:
    return libfuzzer_lib
  current_path = os.path.dirname(os.path.realpath(__file__))
  try:
    libfuzzer = subprocess.check_output(
        [current_path + "/setup_utils/find_libfuzzer.sh"])
  except subprocess.CalledProcessError as e:
    sys.stderr.write(no_libfuzzer_error + "\n")
    raise RuntimeError(no_libfuzzer_error)
  libfuzzer = libfuzzer.strip().decode("utf-8")
  return libfuzzer


ext_modules = [
    Extension(
        "atheris",
        sorted([
            "atheris.cc",
            "libfuzzer.cc",
            "tracer.cc",
            "util.cc",
            "fuzzed_data_provider.cc",
        ]),
        include_dirs=[
            # Path to pybind11 headers
            PybindIncludeGetter(),
        ],
        language="c++"),
    Extension(
        "atheris_no_libfuzzer",
        sorted([
            "atheris.cc",
            "libfuzzer.cc",
            "tracer.cc",
            "util.cc",
            "fuzzed_data_provider.cc",
        ]),
        include_dirs=[
            # Path to pybind11 headers
            PybindIncludeGetter(),
        ],
        language="c++"),
]


# cf http://bugs.python.org/issue26689
def has_flag(compiler, flagname):
  """Return a boolean indicating whether a flag name."""

  with tempfile.NamedTemporaryFile("w", suffix=".cpp", delete=False) as f:
    f.write("int main (int argc, char **argv) { return 0; }")
    fname = f.name
  try:
    compiler.compile([fname], extra_postargs=[flagname])
  except setuptools.distutils.errors.CompileError:
    return False
  finally:
    try:
      os.remove(fname)
    except OSError:
      pass
  return True


def cpp_flag(compiler):
  """Return the highest-supported -std=c++[11/14/17] compiler flag."""
  if os.getenv("FORCE_MIN_VERSION"):
    # Use for testing, to make sure Atheris supports C++11
    flags = ["-std=c++11"]
  elif os.getenv("FORCE_VERSION"):
    flags = ["-std=c++" + os.getenv("FORCE_VERSION")]
  else:
    flags = [
      #"-std=c++17",  C++17 disabled unless explicitly requested, to work
      # around https://github.com/pybind/pybind11/issues/1818
      "-std=c++14",
      "-std=c++11"]

  for flag in flags:
    if has_flag(compiler, flag):
      return flag

  raise RuntimeError("Unsupported compiler -- at least C++11 support "
                     "is needed!")


class BuildExt(build_ext):
  """A custom build extension for adding compiler-specific options."""

  def build_extensions(self):
    libfuzzer = get_libfuzzer_lib()
    orig_libfuzzer = libfuzzer
    orig_libfuzzer_name = os.path.basename(libfuzzer)
    version = check_libfuzzer_version(libfuzzer)

    if sys.platform == "darwin" and version != "up-to-date":
      raise RuntimeError(too_old_error)

    if version == "outdated-unrecoverable":
      raise RuntimeError(too_old_error)

    elif version == "outdated-recoverable":
      sys.stderr.write("Your libFuzzer version is too old, but it's possible "
                       "to attempt an in-place upgrade. Trying that now.\n")
      libfuzzer = upgrade_libfuzzer(libfuzzer)
      if check_libfuzzer_version(libfuzzer) != "up-to-date":
        sys.stderr.write("Upgrade failed.")
        raise RuntimeError(too_old_error)
    elif version != "up-to-date":
      raise RuntimeError("Unexpected up-to-date status: " + version)

    sys.stderr.write("Your libFuzzer is up-to-date.\n")

    c_opts = []
    l_opts = []

    if sys.platform == "darwin":
      darwin_opts = ["-stdlib=libc++", "-mmacosx-version-min=10.7"]
      c_opts += darwin_opts
      l_opts += darwin_opts

    ct = self.compiler.compiler_type
    if ct == "unix":
      c_opts.append(cpp_flag(self.compiler))

    for ext in self.extensions:
      ext.define_macros = [("VERSION_INFO",
                            "'{}'".format(self.distribution.get_version())),
                           ("ATHERIS_MODULE_NAME", ext.name)]
      ext.extra_compile_args = c_opts
      if ext.name == "atheris_no_libfuzzer":
        ext.extra_link_args = l_opts
      else:
        ext.extra_link_args = l_opts + [libfuzzer]
    build_ext.build_extensions(self)

    try:
      self.deploy_file(libfuzzer, orig_libfuzzer_name)
    except Exception as e:
      sys.stderr.write(str(e))
      sys.stderr.write("\n")
      pass

    # Deploy versions of ASan and UBSan that have been merged with libFuzzer
    asan_name = orig_libfuzzer.replace(".fuzzer_no_main-", ".asan-")
    merged_asan_name = "asan_with_fuzzer.so"
    self.merge_deploy_libfuzzer_sanitizer(
        libfuzzer, asan_name, merged_asan_name,
        "asan_preinit.cc.o asan_preinit.cpp.o")

    ubsan_name = orig_libfuzzer.replace(".fuzzer_no_main-",
                                        ".ubsan_standalone-")
    merged_ubsan_name = "ubsan_with_fuzzer.so"
    self.merge_deploy_libfuzzer_sanitizer(
        libfuzzer, ubsan_name, merged_ubsan_name,
        "ubsan_init_standalone_preinit.cc.o ubsan_init_standalone_preinit.cpp.o"
    )

    ubsanxx_name = orig_libfuzzer.replace(".fuzzer_no_main-",
                                          ".ubsan_standalone_cxx-")
    merged_ubsanxx_name = "ubsan_cxx_with_fuzzer.so"
    self.merge_deploy_libfuzzer_sanitizer(
        libfuzzer, ubsanxx_name, merged_ubsanxx_name,
        "ubsan_init_standalone_preinit.cc.o ubsan_init_standalone_preinit.cpp.o"
    )

  def deploy_file(self, name, target_filename):
    atheris = self.get_ext_fullpath("atheris")
    dest_file = os.path.join(os.path.dirname(atheris), target_filename)

    shutil.copy(name, dest_file)

  def merge_libfuzzer_sanitizer(self, libfuzzer, sanitizer, strip_preinit):
    """Generate a .so that contains both libFuzzer and a sanitizer."""
    current_path = os.path.dirname(os.path.realpath(__file__))

    new_sanitizer = subprocess.check_output([
        os.path.join(current_path, "setup_utils/merge_libfuzzer_sanitizer.sh"),
        libfuzzer, sanitizer, strip_preinit
    ])

    return new_sanitizer.strip().decode("utf-8")

  def merge_deploy_libfuzzer_sanitizer(self, libfuzzer, lib_name,
                                       merged_lib_name, preinit):
    try:
      merged_lib = self.merge_libfuzzer_sanitizer(libfuzzer, lib_name, preinit)
      self.deploy_file(merged_lib, merged_lib_name)
    except Exception as e:
      sys.stderr.write(str(e))
      sys.stderr.write("\n")
      pass


setup(
    name="atheris",
    version=__version__,
    author="Ian Eldred Pudney",
    author_email="puddles@google.com",
    url="https://pypi.org/project/atheris/",
    description="A coverage-guided fuzzer for Python and Python extensions.",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    ext_modules=ext_modules,
    setup_requires=["pybind11>=2.5.0"],
    cmdclass={"build_ext": BuildExt},
    zip_safe=False,
)
