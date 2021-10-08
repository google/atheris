# Copyright 2021 Google LLC
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

import atheris
import atexit
import fcntl
import os
import sys
import time
import unittest
import re


def _set_nonblocking(fd):
  """Set the specified fd to a nonblocking mode."""
  oflags = fcntl.fcntl(fd, fcntl.F_GETFL)
  nflags = oflags | os.O_NONBLOCK
  fcntl.fcntl(fd, fcntl.F_SETFL, nflags)


def _fuzztest_child(test_one_input, pipe, args, enabled_hooks):
  os.close(pipe[0])
  os.dup2(pipe[1], 1)
  os.dup2(pipe[1], 2)

  try:
    for hook in enabled_hooks:
        atheris.enabled_hooks.add(hook)
    atheris.Setup([sys.argv[0]] + args, test_one_input)
    atheris.Fuzz()

    # To avoid running tests multiple times due to fork(), never allow control
    # flow to proceed past here. Report that we're exiting gracefully so that
    # tests can verify that's what happened.
  except SystemExit as e:
    print("Exiting gracefully.")
    sys.stdout.flush()
    os._exit(e.code)
  finally:
    print("Exiting gracefully.")
    sys.stdout.flush()
    os._exit(0)


def run_fuzztest(test_one_input, expected_output=None, timeout=10, args=[], enabled_hooks=[]):
  """Fuzz test_one_input() in a subprocess.

  This forks a child, and in the child, runs atheris.Setup(test_one_input) and
  atheris.Fuzz(). Expects the fuzzer to quickly find a crash.

  Args:
    test_one_input: a callable that takes a bytes.
    expected_output: bytes. If specified, the output of the fuzzer must contain
      this data.
    timeout: float. Time until the fuzzing is aborted and an assertion failure
      is raised.
    args: additional command-line arguments to pass to the fuzzing run.
  """
  pipe = os.pipe()

  pid = os.fork()
  if pid == 0:
    _fuzztest_child(test_one_input, pipe, args, enabled_hooks)

  os.close(pipe[1])
  _set_nonblocking(pipe[0])

  stdout = b""
  start_time = time.time()
  while True:
    data = b""
    try:
      data = os.read(pipe[0], 1024)
    except BlockingIOError:
      pass

    sys.stderr.buffer.write(data)
    stdout += data

    if len(data) != 0:
      continue

    wpid = os.waitpid(pid, os.WNOHANG)

    if wpid == (0, 0):
      # Process not done yet
      if time.time() > start_time + timeout:
        raise TimeoutError("Fuzz target failed to exit within expected time.")
      time.sleep(0.1)
      continue

    # Process done, get any remaining output.
    with os.fdopen(pipe[0], "rb") as f:
      data = f.read()
    sys.stderr.buffer.write(data)
    stdout += data
    break

  if expected_output:
    if expected_output not in stdout:
      raise AssertionError("Fuzz target did not produce the expected output "
                           f"{expected_output}; actually got:\n{stdout}")


def fail_immediately(data):
  raise RuntimeError("Failed immediately")


@atheris.instrument_func
def many_branches(data):
  if len(data) < 4:
    return
  if data[0] != 12:
    return
  if data[1] != 5:
    return
  if data[2] != 0:
    return
  if data[3] != 123:
    return

  raise RuntimeError("Many branches")


@atheris.instrument_func
def never_fail(data):
  for d in data:
    if d == 0:
      pass
    elif d == 1:
      pass
    elif d == 2:
      pass


@atheris.instrument_func
def bytes_comparison(data):
  if data == b"foobarbazbiz":
    raise RuntimeError("Was foobarbazbiz")


@atheris.instrument_func
def string_comparison(data):
  try:
    if data.decode("utf-8") == "foobarbazbiz":
      raise RuntimeError("Was foobarbazbiz")
  except UnicodeDecodeError:
    pass


@atheris.instrument_func
def utf8_comparison(data):
  try:
    decoded = data.decode("utf-8")
    if decoded == "⾐∾ⶑ➠":
      raise RuntimeError(f"Was random unicode '{decoded}'")
  except UnicodeDecodeError:
    pass


@atheris.instrument_func
def timeout_py(data):
  del data
  time.sleep(100000000)


@atheris.instrument_func
def regex_match(data):
  if re.search(b"(Sun|Mon)day", data) is not None:
    raise RuntimeError("Was RegEx Match")


class IntegrationTests(unittest.TestCase):

  def testFails(self):
    run_fuzztest(fail_immediately, expected_output=b"Failed immediately")

  def testManyBranches(self):
    run_fuzztest(many_branches, expected_output=b"Many branches", timeout=30)

  def testBytesComparison(self):
    run_fuzztest(bytes_comparison, expected_output=b"Was foobarbazbiz")

  def testStringComparison(self):
    run_fuzztest(string_comparison, expected_output=b"Was foobarbazbiz")

  def testUtf8Comparison(self):
    run_fuzztest(utf8_comparison, expected_output=b"Was random unicode")

  def testTimeoutPy(self):
    """This test verifies that timeout messages are recorded from -timeout."""
    run_fuzztest(
        timeout_py,
        args=["-timeout=1"],
        expected_output=b"most recent call first")
    run_fuzztest(
        timeout_py,
        args=["-timeout=1"],
        expected_output=b"ERROR: libFuzzer: timeout after")

  def testRegExMatch(self):
    run_fuzztest(
        regex_match,
        expected_output=b"Was RegEx Match",
        enabled_hooks=["RegEx"])

  def testExitsGracefullyOnPyFail(self):
    run_fuzztest(fail_immediately, expected_output=b"Exiting gracefully.")

  def testExitsGracefullyOnRunsOut(self):
    run_fuzztest(
        never_fail, args=["-atheris_runs=2"],
        expected_output=b"Exiting gracefully.")

  def testRunsOutCount(self):
    run_fuzztest(never_fail, args=["-atheris_runs=3"],
                 expected_output=b"Done 3 in ")

if __name__ == "__main__":
  unittest.main()
