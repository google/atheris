"""Setuptools for libprotobuf_mutator bindings for Atheris."""

import os
import shutil
import subprocess
import sys

import setuptools
from setuptools import setup
from distutils import spawn
from distutils.command import build
import setuptools.command.build_ext


class BuildExtCommand(setuptools.command.build_ext.build_ext):
  """Build C++ extensions and public protos with Bazel."""

  def python_bin_path_args(self):
    return ["--define", f"PYTHON_BIN_PATH='{sys.executable}'"]

  def env(self):
    ret = os.environ.copy()
    ret["PYTHON_BIN_PATH"] = sys.executable
    return ret

  def finalize_options(self):
    super().finalize_options()
    bazel = spawn.find_executable("bazel")
    if not bazel:
      raise RuntimeError(
          "Could not find 'bazel' binary. Please visit "
          "https://docs.bazel.build/versions/master/install.html for "
          "installation instruction.")
    self._bazel_cmd = [bazel]

  def run(self):
    if self.dry_run:
      return
    ext = self.extensions[0]
    ext_full_path = self.get_ext_fullpath(ext.name)
    subprocess.check_call(
        self._bazel_cmd + ["build"] + self.python_bin_path_args() +
        ["-c", "opt", "--cxxopt=-std=c++17", "//:_mutator.so"],
        # Bazel should be invoked in a directory containing bazel WORKSPACE
        # file, which is the root directory.
        cwd=os.path.dirname(os.path.realpath(__file__)),
        env=self.env())
    built_ext_path = "bazel-bin/_mutator.so"
    os.makedirs(os.path.dirname(ext_full_path), exist_ok=True)
    print("Copying extension %s -> %s" % (
        built_ext_path,
        ext_full_path,
    ))
    shutil.copyfile(built_ext_path, ext_full_path)


setup(
    name="atheris_libprotobuf_mutator",
    version="0.1.0",
    author="fuzzing@google.com",
    author_email="fuzzing@google.com",
    url="https://github.com/google/libprotobuf-mutator/",
    description="libprotobuf-mutator bindings for Python using Atheris.",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    py_modules=[
        "atheris_libprotobuf_mutator.helpers",
        "atheris_libprotobuf_mutator.__init__"
    ],
    ext_modules=[
        setuptools.Extension(
            "atheris_libprotobuf_mutator._mutator", sources=[])
    ],
    cmdclass={
        "build_ext": BuildExtCommand,
    },
    zip_safe=False,
)
