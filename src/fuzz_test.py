import atheris
import fcntl
import os
import sys
import time
import unittest


def _set_nonblocking(fd):
  """Set the specified fd to a nonblocking mode."""
  oflags = fcntl.fcntl(fd, fcntl.F_GETFL)
  nflags = oflags | os.O_NONBLOCK
  fcntl.fcntl(fd, fcntl.F_SETFL, nflags)


def _fuzztest_child(test_one_input, pipe, args):
  os.close(pipe[0])
  os.dup2(pipe[1], 1)
  os.dup2(pipe[1], 2)

  atheris.Setup([sys.argv[0]] + args, test_one_input)
  atheris.Fuzz()
  assert False  # Does not return


def run_fuzztest(test_one_input, expected_output=None, timeout=10, args=[]):
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
    _fuzztest_child(test_one_input, pipe, args)

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
      raise AssertionError(
          f"Fuzz target did not produce the expected output {expected_output}; actually got:\n{stdout}"
      )


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
    if data.decode("utf-8") == "⾐∾ⶑ➠":
      raise RuntimeError("Was random unicode")
  except UnicodeDecodeError:
    pass


@atheris.instrument_func
def timeout_py(data):
  del data
  time.sleep(100000000)


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


if __name__ == "__main__":
  unittest.main()
