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

NO_SANITIZE
void SetTimeout(int timeout_secs) { ::atheris::timeout_secs = timeout_secs; }

NO_SANITIZE
void HandleAlarm(int signum) {
  auto module = py::module::import("faulthandler");

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
    module.attr("dump_traceback")();
    std::cerr << "\n" << std::endl;

    // Call the original signal handler, if present (it should be).
    // Otherwise, exit.
    if (libfuzzer_alarm_signal == SIG_DFL ||
        libfuzzer_alarm_signal == SIG_IGN) {
      exit(1);
    }

    libfuzzer_alarm_signal(signum);
  }
}

NO_SANITIZE
void SetupTimeoutAlarm() {
  unit_start_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();

  // set up our timer.
  struct itimerval tim {
    {timeout_secs / 2 + 1, 0}, { timeout_secs / 2 + 1, 0 }
  };
  if (setitimer(ITIMER_REAL, &tim, nullptr)) {
    std::cerr << Colorize(STDERR_FILENO,
                          "Failed to set timer - will not detect timeouts.")
              << std::endl;
  }

  struct sigaction action;
  if (sigaction(SIGALRM, nullptr, &action)) {
    std::cerr << "sigaction (get): " << strerror(errno) << std::endl;
    exit(1);
  }

  libfuzzer_alarm_signal = action.sa_handler;

  action.sa_handler = HandleAlarm;
  if (sigaction(SIGALRM, &action, nullptr)) {
    std::cerr << "sigaction (set): " << strerror(errno) << std::endl;
    exit(1);
  }
}

NO_SANITIZE
void RefreshTimeout() {
  unit_start_time = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
}

}  // namespace atheris
