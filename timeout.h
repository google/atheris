#ifndef ATHERIS_TIMEOUT_H_
#define ATHERIS_TIMEOUT_H_

namespace atheris {
void SetTimeout(int timeout_secs);
void SetupTimeoutAlarm();
void RefreshTimeout();

}  // namespace atheris

#endif  // ATHERIS_TIMEOUT_H_
