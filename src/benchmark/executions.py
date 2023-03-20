# Copyright 2021 Google LLC
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
"""Benchmarks for Atheris execs/sec performance."""
# In Google, must be built with --config=asan-fuzzer.

import atheris
import contextlib

# Use new atheris instrumentation only if on new atheris
if "instrument_func" in dir(atheris):
  instrument_func = atheris.instrument_func
  instrument_imports = atheris.instrument_imports
  instrument_all = atheris.instrument_all
else:

  def instrument_func(x):
    return x

  def instrument_all():
    pass

  @contextlib.contextmanager
  def instrument_imports(*args, **kwargs):
    yield None


with instrument_imports():
  import fcntl
  import os
  import sys
  import time
  import re
  import json
  import zipfile
  import io


def _set_nonblocking(fd):
  """Set the specified fd to a nonblocking mode."""
  oflags = fcntl.fcntl(fd, fcntl.F_GETFL)
  nflags = oflags | os.O_NONBLOCK
  fcntl.fcntl(fd, fcntl.F_SETFL, nflags)


def _benchmark_child(test_one_input, num_runs, pipe, args, inst_all):
  os.close(pipe[0])
  os.dup2(pipe[1], 1)
  os.dup2(pipe[1], 2)

  if inst_all:
    instrument_all()

  counter = [0]
  start = time.time()

  def wrapped_test_one_input(data):
    counter[0] += 1
    if counter[0] == num_runs:
      print(f"\nbenchmark_duration={time.time() - start}")
      os._exit(0)
    test_one_input(data)

  atheris.Setup([sys.argv[0]] + args, wrapped_test_one_input)
  atheris.Fuzz()
  assert False  # Does not return


def run_benchmark(test_one_input,
                  num_runs,
                  timeout=10,
                  inst_all=False,
                  args=[]):
  """Fuzz test_one_input() in a subprocess.

  This forks a child, and in the child, runs atheris.Setup(test_one_input) and
  atheris.Fuzz(). Expects the fuzzer to quickly find a crash.

  Args:
    test_one_input: a callable that takes a bytes.
    timeout: float. Time until the fuzzing is aborted and an assertion failure
      is raised.
    args: additional command-line arguments to pass to the fuzzing run.
  """
  pipe = os.pipe()

  pid = os.fork()
  if pid == 0:
    _benchmark_child(test_one_input, num_runs, pipe, args, inst_all)

  os.close(pipe[1])
  _set_nonblocking(pipe[0])

  stdout = b""
  start_time = time.time()
  while True:
    data = b""
    try:
      data = os.read(pipe[0], 1024)
    except BlockingIOError:
      pass

    stdout += data

    if len(data) != 0:
      continue

    wpid = os.waitpid(pid, os.WNOHANG)

    if wpid == (0, 0):
      # Process not done yet
      if time.time() > start_time + timeout:
        raise TimeoutError("Fuzz target failed to exit within expected time.")
      time.sleep(0.1)
      continue

    # Process done, get any remaining output.
    with os.fdopen(pipe[0], "rb") as f:
      data = f.read()
    stdout += data
    break

  result_line = re.search(b"benchmark_duration=[0-9.]+", stdout)
  time_taken = float(result_line[0].split(b"=")[1])
  runs_per_sec = num_runs / time_taken

  sys.stdout.write(
      f"{test_one_input.__name__}\truns={num_runs}\ttime={time_taken:.2f}s\texecs/sec={runs_per_sec:.2f}\n"
  )


@instrument_func
def low_cyclomatic(data):
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9
  x = 0
  x = 1
  x = 2
  x = 3
  x = 4
  x = 5
  x = 6
  x = 7
  x = 8
  x = 9


@instrument_func
def high_cyclomatic(data):
  for c in data:
    if c == 0:
      c = 38
    if c == 1:
      c = 201
    if c == 2:
      c = 192
    if c == 3:
      c = 70
    if c == 4:
      c = 184
    if c == 5:
      c = 100
    if c == 6:
      c = 85
    if c == 7:
      c = 0
    if c == 8:
      c = 18
    if c == 9:
      c = 183
    if c == 10:
      c = 140
    if c == 11:
      c = 216
    if c == 12:
      c = 60
    if c == 13:
      c = 139
    if c == 14:
      c = 133
    if c == 15:
      c = 252
    if c == 16:
      c = 148
    if c == 17:
      c = 156
    if c == 18:
      c = 73
    if c == 19:
      c = 137
    if c == 20:
      c = 167
    if c == 21:
      c = 44
    if c == 22:
      c = 90
    if c == 23:
      c = 50
    if c == 24:
      c = 169
    if c == 25:
      c = 216
    if c == 26:
      c = 182
    if c == 27:
      c = 231
    if c == 28:
      c = 192
    if c == 29:
      c = 14
    if c == 30:
      c = 236
    if c == 31:
      c = 158
    if c == 32:
      c = 38
    if c == 33:
      c = 36
    if c == 34:
      c = 101
    if c == 35:
      c = 75
    if c == 36:
      c = 81
    if c == 37:
      c = 105
    if c == 38:
      c = 217
    if c == 39:
      c = 33
    if c == 40:
      c = 200
    if c == 41:
      c = 124
    if c == 42:
      c = 161
    if c == 43:
      c = 81
    if c == 44:
      c = 6
    if c == 45:
      c = 231
    if c == 46:
      c = 156
    if c == 47:
      c = 213
    if c == 48:
      c = 203
    if c == 49:
      c = 121
    if c == 50:
      c = 217
    if c == 51:
      c = 170
    if c == 52:
      c = 217
    if c == 53:
      c = 249
    if c == 54:
      c = 201
    if c == 55:
      c = 81
    if c == 56:
      c = 205
    if c == 57:
      c = 206
    if c == 58:
      c = 50
    if c == 59:
      c = 131
    if c == 60:
      c = 223
    if c == 61:
      c = 24
    if c == 62:
      c = 220
    if c == 63:
      c = 83
    if c == 64:
      c = 15
    if c == 65:
      c = 186
    if c == 66:
      c = 126
    if c == 67:
      c = 68
    if c == 68:
      c = 94
    if c == 69:
      c = 101
    if c == 70:
      c = 85
    if c == 71:
      c = 229
    if c == 72:
      c = 10
    if c == 73:
      c = 7
    if c == 74:
      c = 57
    if c == 75:
      c = 124
    if c == 76:
      c = 111
    if c == 77:
      c = 230
    if c == 78:
      c = 192
    if c == 79:
      c = 111
    if c == 80:
      c = 237
    if c == 81:
      c = 106
    if c == 82:
      c = 126
    if c == 83:
      c = 149
    if c == 84:
      c = 28
    if c == 85:
      c = 204
    if c == 86:
      c = 241
    if c == 87:
      c = 113
    if c == 88:
      c = 161
    if c == 89:
      c = 136
    if c == 90:
      c = 189
    if c == 91:
      c = 156
    if c == 92:
      c = 195
    if c == 93:
      c = 123
    if c == 94:
      c = 64
    if c == 95:
      c = 93
    if c == 96:
      c = 45
    if c == 97:
      c = 167
    if c == 98:
      c = 218
    if c == 99:
      c = 211
    if c == 100:
      c = 19
    if c == 101:
      c = 94
    if c == 102:
      c = 207
    if c == 103:
      c = 128
    if c == 104:
      c = 209
    if c == 105:
      c = 13
    if c == 106:
      c = 71
    if c == 107:
      c = 39
    if c == 108:
      c = 218
    if c == 109:
      c = 124
    if c == 110:
      c = 51
    if c == 111:
      c = 204
    if c == 112:
      c = 94
    if c == 113:
      c = 171
    if c == 114:
      c = 1
    if c == 115:
      c = 190
    if c == 116:
      c = 1
    if c == 117:
      c = 248
    if c == 118:
      c = 216
    if c == 119:
      c = 10
    if c == 120:
      c = 162
    if c == 121:
      c = 204
    if c == 122:
      c = 152
    if c == 123:
      c = 196
    if c == 124:
      c = 146
    if c == 125:
      c = 227
    if c == 126:
      c = 191
    if c == 127:
      c = 182
    if c == 128:
      c = 100
    if c == 129:
      c = 74
    if c == 130:
      c = 82
    if c == 131:
      c = 129
    if c == 132:
      c = 207
    if c == 133:
      c = 51
    if c == 134:
      c = 168
    if c == 135:
      c = 81
    if c == 136:
      c = 101
    if c == 137:
      c = 108
    if c == 138:
      c = 30
    if c == 139:
      c = 66
    if c == 140:
      c = 21
    if c == 141:
      c = 135
    if c == 142:
      c = 248
    if c == 143:
      c = 49
    if c == 144:
      c = 203
    if c == 145:
      c = 20
    if c == 146:
      c = 135
    if c == 147:
      c = 197
    if c == 148:
      c = 212
    if c == 149:
      c = 159
    if c == 150:
      c = 173
    if c == 151:
      c = 195
    if c == 152:
      c = 152
    if c == 153:
      c = 158
    if c == 154:
      c = 27
    if c == 155:
      c = 61
    if c == 156:
      c = 209
    if c == 157:
      c = 155
    if c == 158:
      c = 55
    if c == 159:
      c = 87
    if c == 160:
      c = 229
    if c == 161:
      c = 143
    if c == 162:
      c = 200
    if c == 163:
      c = 220
    if c == 164:
      c = 164
    if c == 165:
      c = 97
    if c == 166:
      c = 92
    if c == 167:
      c = 65
    if c == 168:
      c = 253
    if c == 169:
      c = 249
    if c == 170:
      c = 23
    if c == 171:
      c = 1
    if c == 172:
      c = 154
    if c == 173:
      c = 248
    if c == 174:
      c = 89
    if c == 175:
      c = 144
    if c == 176:
      c = 109
    if c == 177:
      c = 233
    if c == 178:
      c = 46
    if c == 179:
      c = 174
    if c == 180:
      c = 101
    if c == 181:
      c = 130
    if c == 182:
      c = 116
    if c == 183:
      c = 103
    if c == 184:
      c = 142
    if c == 185:
      c = 229
    if c == 186:
      c = 217
    if c == 187:
      c = 207
    if c == 188:
      c = 146
    if c == 189:
      c = 24
    if c == 190:
      c = 153
    if c == 191:
      c = 149
    if c == 192:
      c = 48
    if c == 193:
      c = 77
    if c == 194:
      c = 187
    if c == 195:
      c = 205
    if c == 196:
      c = 75
    if c == 197:
      c = 171
    if c == 198:
      c = 122
    if c == 199:
      c = 37
    if c == 200:
      c = 92
    if c == 201:
      c = 63
    if c == 202:
      c = 71
    if c == 203:
      c = 81
    if c == 204:
      c = 101
    if c == 205:
      c = 216
    if c == 206:
      c = 32
    if c == 207:
      c = 55
    if c == 208:
      c = 219
    if c == 209:
      c = 204
    if c == 210:
      c = 63
    if c == 211:
      c = 16
    if c == 212:
      c = 6
    if c == 213:
      c = 49
    if c == 214:
      c = 158
    if c == 215:
      c = 228
    if c == 216:
      c = 237
    if c == 217:
      c = 123
    if c == 218:
      c = 161
    if c == 219:
      c = 15
    if c == 220:
      c = 172
    if c == 221:
      c = 79
    if c == 222:
      c = 64
    if c == 223:
      c = 34
    if c == 224:
      c = 147
    if c == 225:
      c = 228
    if c == 226:
      c = 200
    if c == 227:
      c = 0
    if c == 228:
      c = 12
    if c == 229:
      c = 209
    if c == 230:
      c = 95
    if c == 231:
      c = 239
    if c == 232:
      c = 161
    if c == 233:
      c = 24
    if c == 234:
      c = 211
    if c == 235:
      c = 35
    if c == 236:
      c = 187
    if c == 237:
      c = 79
    if c == 238:
      c = 116
    if c == 239:
      c = 46
    if c == 240:
      c = 184
    if c == 241:
      c = 170
    if c == 242:
      c = 199
    if c == 243:
      c = 118
    if c == 244:
      c = 237
    if c == 245:
      c = 174
    if c == 246:
      c = 142
    if c == 247:
      c = 99
    if c == 248:
      c = 137
    if c == 249:
      c = 163
    if c == 250:
      c = 28
    if c == 251:
      c = 233
    if c == 252:
      c = 19
    if c == 253:
      c = 189
    if c == 254:
      c = 143
    if c == 255:
      c = 7


def json_fuzz(data):
  try:
    json.loads(data.decode("utf-8", "surrogatepass"))
  except Exception as e:
    pass


@instrument_func
def zip_fuzz(data):
  try:
    with io.BytesIO(data) as f:
      pz = zipfile.ZipFile(f)
      pinfos = pz.infolist()

      for i in range(len(pinfos)):
        pinfo = pinfos[i]

        x = pinfo.comment
        x = pinfo.compress_size
        x = pinfo.external_attr
        x = pinfo.extra
        x = pinfo.filename
        x = pinfo.flag_bits
        x = pinfo.header_offset
        x = pinfo.internal_attr
        x = pinfo.is_dir()
        x = pinfo.reserved
        x = pinfo.volume

        with pz.open(pinfo) as g:
          pdata = g.read()
  except Exception as e:
    pass


run_benchmark(low_cyclomatic, num_runs=40000, timeout=30)
run_benchmark(high_cyclomatic, num_runs=2000, timeout=30)
run_benchmark(json_fuzz, num_runs=4000, timeout=120, inst_all=True)
run_benchmark(zip_fuzz, num_runs=4000, timeout=30)
