// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "pybind11/embed.h"
#include "pybind11/eval.h"
#include "pybind11/pybind11.h"
#include "testing/base/public/gmock.h"
#include "testing/base/public/gunit.h"

namespace atheris {

namespace py = pybind11;

namespace {

TEST(Colorize, No) {
  // Make an FD that's not a TTY.
  int pipefd[2];
  pipe(pipefd);

  EXPECT_EQ("foo", Colorize(pipefd[0], "foo"));

  close(pipefd[0]);
  close(pipefd[1]);
}

TEST(Colorize, Yes) {
  // Make an FD that's a TTY.
  int hostfd, childfd;
  char name[256];

  openpty(&hostfd, &childfd, &name[0], nullptr, nullptr);

  EXPECT_NE("foo", Colorize(childfd, "foo"));

  close(hostfd);
  close(childfd);
}

TEST(StartsWith, No) { EXPECT_FALSE(StartsWith("foo", "bar")); }

TEST(StartsWith, YesPrefix) { EXPECT_TRUE(StartsWith("barfoo", "bar")); }

TEST(StartsWith, YesExact) { EXPECT_TRUE(StartsWith("foo", "foo")); }

TEST(StartsWith, NoTooShort) { EXPECT_FALSE(StartsWith("fo", "foo")); }

TEST(StartsWith, NoEndsWith) { EXPECT_FALSE(StartsWith("barfoo", "foo")); }

TEST(PrintPythonException, Basic) {
  py::scoped_interpreter interpreter{};

  bool catch_triggered = false;

  try {
    py::exec("raise RuntimeError('foo')");
  } catch (py::error_already_set& ex) {
    catch_triggered = true;

    std::stringstream tmp;
    PrintPythonException(ex, tmp);

    EXPECT_EQ(tmp.str().substr(0, strlen("RuntimeError: foo")),
              "RuntimeError: foo");

    // Make sure the traceback messages appear, but don't enforce anything about
    // exact module or line numbers.
    EXPECT_NE(tmp.str().find("File "), std::string::npos);
    EXPECT_NE(tmp.str().find(", line"), std::string::npos);
    EXPECT_NE(tmp.str().find(", in"), std::string::npos);
  }

  ASSERT_TRUE(catch_triggered);
}

TEST(GetExceptionType, Basic) {
  py::scoped_interpreter interpreter{};

  bool catch_triggered = false;

  try {
    py::exec("raise RuntimeError('foo')");
  } catch (py::error_already_set& ex) {
    catch_triggered = true;

    std::stringstream tmp;

    EXPECT_EQ("RuntimeError", GetExceptionType(ex));
  }

  ASSERT_TRUE(catch_triggered);
}

TEST(GetExceptionMessage, Basic) {
  py::scoped_interpreter interpreter{};

  bool catch_triggered = false;

  try {
    py::exec("raise RuntimeError('foo')");
  } catch (py::error_already_set& ex) {
    catch_triggered = true;

    std::stringstream tmp;

    EXPECT_EQ("foo", GetExceptionMessage(ex));
  }

  ASSERT_TRUE(catch_triggered);
}

}  // namespace
}  // namespace atheris
