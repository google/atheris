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

import fcntl
import os
import sys
import time

import atheris


def _set_nonblocking(fd):
  """Set the specified fd to a nonblocking mode."""
  oflags = fcntl.fcntl(fd, fcntl.F_GETFL)
  nflags = oflags | os.O_NONBLOCK
  fcntl.fcntl(fd, fcntl.F_SETFL, nflags)


def _fuzztest_child(test_one_input, custom_setup, setup_kwargs, pipe, args,
                    enabled_hooks):
  """Fuzzing target to run as a separate process."""
  os.close(pipe[0])
  os.dup2(pipe[1], 1)
  os.dup2(pipe[1], 2)

  if not setup_kwargs:
    setup_kwargs = {}

  try:
    if enabled_hooks:
      for hook in enabled_hooks:
        atheris.enabled_hooks.add(hook)
    custom_setup(
        [sys.argv[0]] + (args if args else []),
        test_one_input,
        **setup_kwargs)
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


def run_fuzztest(test_one_input,
                 custom_setup=None,
                 setup_kwargs=None,
                 expected_output=None,
                 timeout=10,
                 args=None,
                 enabled_hooks=None):
  """Fuzz test_one_input() in a subprocess.

  This forks a child, and in the child, runs atheris.Setup(test_one_input) and
  atheris.Fuzz(). Expects the fuzzer to quickly find a crash.

  Args:
    test_one_input: a callable that takes a bytes.
    custom_setup: a custom setup function, if None atheris.Setup is used.
    setup_kwargs: arguments to pass to the setup function.
    expected_output: bytes. If specified, the output of the fuzzer must contain
      this data.
    timeout: float. Time until the fuzzing is aborted and an assertion failure
      is raised.
    args: additional command-line arguments to pass to the fuzzing run.
    enabled_hooks: list of hooks.

  Raises:
    TimeoutError: when the target fuzz did not complete in the expected time.
  """
  pipe = os.pipe()

  pid = os.fork()
  if pid == 0:
    _fuzztest_child(test_one_input, custom_setup or atheris.Setup,
                    setup_kwargs, pipe, args, enabled_hooks)

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

    if data:
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
