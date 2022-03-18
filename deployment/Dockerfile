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

FROM quay.io/pypa/manylinux2014_x86_64

# Clang needs to be able to find python3
RUN set -e -x -v; \
	ln -s /opt/python/cp38-cp38/bin/python /usr/bin/python3

RUN set -e -x -v; \
	yum install -y cmake;

RUN set -e -x -v; \
	cd /root; \
	git clone https://github.com/llvm/llvm-project.git;

RUN set -e -x -v; \
	cd /root/llvm-project; \
	cmake -S llvm -B build -G "Unix Makefiles" -DLLVM_ENABLE_PROJECTS="clang;compiler-rt";
RUN set -e -x -v; \
	cd /root/llvm-project/build; \
	make compiler-rt;

RUN set -e -x -v; \
	python3 -m pip install auditwheel;

WORKDIR /atheris

CMD export LIBFUZZER_LIB="/root/llvm-project/build/lib/clang/$(ls /root/llvm-project/build/lib/clang/)/lib/linux/libclang_rt.fuzzer_no_main-x86_64.a"; \
	/opt/python/cp36-cp36m/bin/python3 setup.py bdist_wheel -d /tmp/dist && \
	/opt/python/cp37-cp37m/bin/python3 setup.py bdist_wheel -d /tmp/dist && \
	/opt/python/cp38-cp38/bin/python3 setup.py bdist_wheel -d /tmp/dist && \
	/opt/python/cp39-cp39/bin/python3 setup.py bdist_wheel -d /tmp/dist && \
	/opt/python/cp310-cp310/bin/python3 setup.py bdist_wheel -d /tmp/dist && \
	( cd /tmp/dist && find /tmp/dist/* | xargs -I{} auditwheel repair --plat manylinux2014_x86_64 {} ) && \
	mkdir -p /atheris/dist && cp /tmp/dist/wheelhouse/* /atheris/dist/
