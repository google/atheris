set -e

cd "${KOKORO_ARTIFACTS_DIR}/git/atheris"
export CLANG_BIN=clang-12
./run_tests.sh