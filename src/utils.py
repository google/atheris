# Copyright 2021 Fraunhofer FKIE
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

import sys
import os


def path():
  dir, _ = os.path.split(sys.modules["atheris"].__file__)
  dir, _ = os.path.split(dir)
  return dir


class ProgressRenderer:
  """Displays an updating progress meter in the terminal."""

  def __init__(self, stream, total_count):
    assert stream.isatty()
    self.stream = stream

    self._count = 0
    self.total_count = total_count

    self._current_width = 0
    self.render()

  def render(self):
    self.erase()
    done_percent = int(100 * self._count / self.total_count)
    message = f"[{self._count}/{self.total_count}] {done_percent}%"
    self.stream.write(message)
    self.stream.flush()
    self._current_width = len(message)

  def erase(self):
    self.stream.write(("\b" * self._current_width) +
                      (" " * self._current_width) +
                      ("\b" * self._current_width))
    self.stream.flush()
    self._current_width = 0

  def drop(self):
    self._current_width = 0
    sys.stderr.write("\n")

  @property
  def count(self):
    return self._count

  @count.setter
  def count(self, new_count):
    self._count = new_count
    self.render()
