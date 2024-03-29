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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

sudo docker build -t atheris-builder ./
sudo docker run -it --env ATHERIS_VERSION="$ATHERIS_VERSION" --mount type=bind,source=$PWD/../,target=/atheris atheris-builder

# chown the resulting dirs so that they can be read by the deployment script.
for d in .eggs atheris.egg-info build dist tmp; do
    sudo chown -R $USER ../$d
done