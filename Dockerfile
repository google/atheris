# Copyright 2020 Valeriy Soloviov
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

# Dockerfile extending the generic Python image with atheris inside.

# To build the image, it is necessary that docker build be invoked from the
# parent folder of this file.
# Example container execution command:
#
# $ git clone https://github.com/google/atheris.git
# $ cd atheris
# $ docker build -t local/atheris .
# $ docker run -ti --rm local/atheris \
#   -v <PathToTheSourceFilesFolder>:/usr/src/app \
#   -it python /usr/src/app/<YourSourceFile>
#
FROM python:3.8-buster

# Default to the development branch of LLVM (currently 12)
# User can override this to a stable branch (like 10 or 11)
ARG LLVM_VERSION=12
ARG IMAGE_VERSION=0.0.0-local
ARG BUILD_DATE=unknown
ARG COMMIT_HASH=unknown

# Configure image labels
LABEL \
    org.opencontainers.image.ref.name="google/atheris" \
    org.opencontainers.image.description="Atheris: A Coverage-Guided, Native Python Fuzzer" \
    org.opencontainers.image.documentation="https://github.com/google/atheris" \
    org.opencontainers.image.licenses="Apache License 2.0" \
    org.opencontainers.image.source="https://github.com/google/atheris" \
    org.opencontainers.image.title="Atheris" \
    org.opencontainers.image.url="https://github.com/google/atheris" \
    org.opencontainers.image.vendor="Google" \
    org.opencontainers.image.version=$IMAGE_VERSION \
    org.opencontainers.image.created=$BUILD_DATE \
    org.opencontainers.image.revision=$COMMIT_HASH

# Install the latest Clang/lld packages from apt.llvm.org
# Delete all the apt list files at the end
RUN set -eux; \
    curl https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
    echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster main" | tee -a /etc/apt/sources.list && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get update -qq && \
    apt-get install --no-install-recommends -y \
        curl \
        vim \
        clang-${LLVM_VERSION} \
        lld-${LLVM_VERSION} \
        llvm-${LLVM_VERSION} && \
    chmod -f +x /usr/lib/llvm-${LLVM_VERSION}/bin/* && \
    update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-${LLVM_VERSION} 999 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-${LLVM_VERSION} 999 && \
    pip install atheris hypothesis && \
    rm -rf /var/lib/apt/lists/*

# Uncomment this to build from the sources
# WORKDIR /usr/src/atheris
# COPY . .
# RUN set -eux; \
#     CLANG_BIN="/usr/bin/clang"  pip install -e .
### Test build from sources
###  python example_fuzzers/fuzzing_example.py

WORKDIR /usr/src/app
