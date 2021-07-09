# Building LLVM
git clone https://github.com/llvm/llvm-project.git
cd llvm-project
mkdir build
cd build
cmake -DLLVM_ENABLE_PROJECTS='clang;compiler-rt' -G "Unix Makefiles" ../llvm
make -j 10  # This step is very slow

# Installing Atheris
CLANG_BIN="$(pwd)/bin/clang" pip3 install atheris