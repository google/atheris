#ifndef ATHERIS_TIMEOUT_H_
#define ATHERIS_TIMEOUT_H_

namespace atheris {
void SetTimeout(int timeout_secs);

// Call just before the FuzzerDriver. Stores the Python signal handler for
// SIGALRM, and clears SIGALRM. Returns false if there's already a signal
// handler set.
bool SetupPythonSigaction();

// Call on the first TestOneInput. Saves the libFuzzer SIGALRM handler and
// replaces it with our signal handler, which may shell out to the Python and/or
// libFuzzer signal handlers.
void SetupTimeoutAlarm();

// Call on every TestOneInput.
void RefreshTimeout();

}  // namespace atheris

#endif  // ATHERIS_TIMEOUT_H_
