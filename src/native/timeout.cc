#include "timeout.h"

#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <iostream>
#include <stdexcept>
#include <string>

#include "macros.h"
#include "pybind11/pybind11.h"
#include "util.h"

namespace atheris {

namespace py = pybind11;

int64_t timeout_secs = 300;
std::atomic<int64_t> unit_start_time(
    std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch())
        .count());

sighandler_t libfuzzer_alarm_signal = SIG_DFL;
sighandler_t python_alarm_signal = nullptr;

NO_SANITIZE
void SetTimeout(int timeout_secs) { ::atheris::timeout_secs = timeout_secs; }

NO_SANITIZE
bool is_null_or_default(sighandler_t h) {
  return h == nullptr || h == SIG_DFL || h == SIG_IGN;
}

// A back SIGALRM signal handler, registered inside of HandleAlarm, to call
// libFuzzer's handler if the Python handler never gets called.
NO_SANITIZE
void LibfuzzerAlarmSignalCallback(int signum) {
  std::cout << "ALARM: Did not return to Python execution within 1 second "
               "after timeout. This likely means your fuzzer timed out in "
               "native code. "
               "Falling back to native timeout handling."
            << std::endl;

  if (is_null_or_default(libfuzzer_alarm_signal)) {
    _exit(1);
  }
  libfuzzer_alarm_signal(signum);
}

// Our SIGALRM signal handler.
NO_SANITIZE
void HandleAlarm(int signum) {
  int64_t current_time =
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  int64_t duration = current_time - unit_start_time;

  if (duration > timeout_secs) {
    std::cout << Colorize(STDOUT_FILENO,
                          "\n === Timeout: " + std::to_string(duration) +
                              "s elapsed, timeout=" +
                              std::to_string(timeout_secs) + "s ===")
              << std::endl;

    // Queue the python backtrace-printing handler.
    python_alarm_signal(signum);

    // If the handler doesn't get called in 1 second, fall back to the libFuzzer
    // handler.
    struct sigaction action;
    checked_sigaction(SIGALRM, nullptr, &action);

    action.sa_handler = LibfuzzerAlarmSignalCallback;
    checked_sigaction(SIGALRM, &action, nullptr);

    alarm(1);  // Set 1 second until alarm.
  }
}

NO_SANITIZE
void signal_or_exit(sighandler_t handler, int signum) {
  if (is_null_or_default(handler)) {
    exit(1);
  }
  handler(signum);
}

// Returns the old handle in the `signum` signal replacing it with `new_handle`.
NO_SANITIZE
sighandler_t replace_handle(int signum, sighandler_t new_handle) {
  struct sigaction action;
  checked_sigaction(signum, nullptr, &action);
  auto old_handle = action.sa_handler;
  action.sa_handler = new_handle;
  checked_sigaction(signum, &action, nullptr);
  return old_handle;
}

NO_SANITIZE
void SetupTimeoutAlarm() {
  // If python_alarm_signal isn't set, either SetupPythonSigaction wasn't called
  // or it returned false. Timeouts are unsupported.
  if (!python_alarm_signal) return;

  unit_start_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();

  // set up our timer. The `timeout_secs / 2 + 1` comes from libFuzzer. The
  // signal handler will check that the timeout has actually been exceeded
  // before exiting. This means that a test case will be guaranteed to timeout
  // after exceeding the timeout by 50%, not 100%.
  struct itimerval tim {
    {timeout_secs / 2 + 1, 0}, { timeout_secs / 2 + 1, 0 }
  };
  if (setitimer(ITIMER_REAL, &tim, nullptr)) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Failed to set timer - will not detect timeouts.")
              << std::endl;
  }

  libfuzzer_alarm_signal = replace_handle(SIGALRM, HandleAlarm);
}

void PrintPythonCallbacks(int signum, py::object frame) {
  // Cancel any further queued alarm.
  alarm(0);

  // Print the Python trace.
  auto faulthandler = py::module::import("faulthandler");
  faulthandler.attr("dump_traceback")();
  signal_or_exit(libfuzzer_alarm_signal, signum);
}

bool SetupPythonSigaction() {
  // So, we want to print the Python stack on a timeout event. However, this is
  // not safe during a native signal handler. Instead, we register a Python
  // signal handler, and then invoke that from within our native signal handler.
  // The registered Python handler doesn't actually trigger until execution
  // returns to the Python interpreter (the real handler just sets a flag),
  // which is why this is safe. However, if code execution fails to return to
  // the Python interpreter (such as an infinite loop in native code), it will
  // never run. We then have a choice: eiher we try printing the Python trace
  // from within the handler anyway, which is technically unsafe; or we just
  // print the native trace. We print the native trace for now, but this might
  // change in the future.

  struct sigaction orig_action;
  checked_sigaction(SIGALRM, nullptr, &orig_action);

  // If someone has provided a SIGALRM handler, we shouldn't override that -
  // print a warning and break.
  if (!is_null_or_default(orig_action.sa_handler)) {
    std::cerr << "WARNING: SIGALRM handler already defined at address "
              << reinterpret_cast<void*>(orig_action.sa_handler)
              << ". Fuzzer timeout will not work." << std::endl;
    return false;
  }

  auto signal_module = py::module::import("signal");
  signal_module.attr("signal")(SIGALRM, py::cpp_function(PrintPythonCallbacks));

  struct sigaction action;
  checked_sigaction(SIGALRM, nullptr, &action);

  python_alarm_signal = action.sa_handler;

  // Clear the handler that was just registered. This ensures libFuzzer will
  // register its own signal handler. (It has the same behavior as here, where
  // it won't register a handler if one is already registered.)
  if (sigaction(SIGALRM, &orig_action, nullptr)) {
    std::cerr << "sigaction (get): " << strerror(errno) << std::endl;
    exit(1);
  }

  checked_sigaction(SIGALRM, nullptr, &action);

  return true;
}

NO_SANITIZE
void RefreshTimeout() {
  unit_start_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
}

}  // namespace atheris
