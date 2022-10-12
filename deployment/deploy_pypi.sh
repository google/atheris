#!/bin/bash
# Copyright 2020 Google LLC
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

set -e

function upload_to() {
  PYPY_INSTANCE="$1"
  python3 -m twine upload --repository "${PYPY_INSTANCE?}" dist/*
}

function download_from_test_pypi() {
  TMP_DIR="$1"
  OLD_DIR="$(pwd)"
  python3 -m pip download --index-url 'https://test.pypi.org/simple/' --no-binary=:all: atheris -d "${TMP_DIR?}" 1>/dev/null
  cd "${TMP_DIR}"
  tar vxf $(ls *.tar*) >/dev/null
  UNPACKED_DIR="$(ls *.tar* | sed s/\\.tar.*//)"
  echo "${PWD?}/${UNPACKED_DIR?}"
  cd "${OLD_DIR}"
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "${DIR}/../"

(
  set -e -x
  rm -rf dist/
  rm -rf atheris.egg-info/
  rm -rf .eggs/
  rm -rf build/
  rm -rf tmp/
)

# Verify that we're pushing a valid git state
git_status="$(git status --porcelain --ignored)"
if [[ ! -z "${git_status?}" ]]; then
  >&2 echo "Git working directory not clean - please ensure it's pristine before deploying (including any gitignored files)."
  >&2 echo "to reproduce, run 'git status --porcelain --ignored'. Current status is:"
  >&2 echo "${git_status?}"
  exit 1
fi

if [[ -z "${ATHERIS_VERSION}" ]]; then
  export ATHERIS_VERSION=$(python3 ./setup.py print_version)
fi

USER_SPECIFIED_PYPI="$1"
(
  set -e -x
  # Build and push
  if [ "$(uname)" == "Darwin" ]; then
    deployment/build_wheels_mac.sh
  else
    python3 setup.py sdist
    deployment/build_wheels.sh
  fi

  TEST_OUTPUT="$(./run_tests.sh 2>&1)"
  if [ "$(echo "${TEST_OUTPUT?}" | tail -n1)" != "OK" ]; then
    echo "tests failed :(. exiting"
    exit 1
  fi
  # Validate args - dev or prod
  if [ -z "${USER_SPECIFIED_PYPI}" ]; then
    # Take hash after building so that we can verify nothing has changed later on.
    ORIGINAL_CONTENTS="$(ls -alR --full-time dist/)"
    upload_to "testpypi"
    echo "upload to testpypi complete."
    TMP_DIR="$(mktemp -d)"
    TEST_PYPY_ATHERIS="$(download_from_test_pypi ${TMP_DIR?})"
    TEST_OUTPUT="$(./run_tests.sh "${TEST_PYPY_ATHERIS}" 2>&1)"
    if [ "$(echo "${TEST_OUTPUT?}" | tail -n1)" != "OK" ]; then
      echo "tests failed :(. exiting"
      exit 1
    fi

    NEW_CONTENTS="$(ls -alR --full-time dist/)"
    if [ "${ORIGINAL_CONTENTS?}" != "${NEW_CONTENTS?}" ]; then
      echo "Not deploying to pypi because files in dist have changed since pushing to test pypi."
      diff -u <(echo "${ORIGINAL_CONTENTS}") <(echo "${NEW_CONTENTS}")
      exit 1
    fi
    upload_to "pypi"
  else
    echo "pushing to ${USER_SPECIFIED_PYPI?}"
    upload_to "${USER_SPECIFIED_PYPI?}"
  fi
)

if [[ -z "${USER_SPECIFIED_PYPI}" || "${USER_SPECIFIED_PYPI?}" == "pypi" ]]; then
  (
    set -e -x
    git tag -a "${ATHERIS_VERSION?}" -m "Atheris version ${ATHERIS_VERSION?}"
  )
  echo "Tag ${ATHERIS_VERSION?} created. Please push tag to git."
fi
