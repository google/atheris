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

#include "fuzzed_data_provider.h"

#include <limits>

#include "util.h"

namespace atheris {

namespace {

uint16_t FastByteToHex(unsigned char byte) {
  const char hex[] = "0123456789ABCDEF";
  return (hex[byte & 0xf] << 8) + static_cast<uint16_t>(hex[(byte >> 4) & 0xf]);
}

}  // namespace

py::object FuzzedDataProvider::ConsumeUnicodeImpl(size_t count,
                                                  bool filter_surrogates) {
  if (count == 0) return UnicodeFromKindAndData(1, nullptr, 0);
  if (remaining_bytes_ == 0) return UnicodeFromKindAndData(1, nullptr, 0);

  if (remaining_bytes_ == 1) {
    Advance(1);
    return UnicodeFromKindAndData(1, nullptr, 0);
  }

  uint8_t string_spec = *data_ptr_;
  Advance(1);

  // 50% of the time, make a pure ASCII string. If we didn't do this, it would
  // be unlikely for libFuzzer to produce an ASCII string, so any API that
  // expected an ASCII string might be difficult to fuzz.
  if (string_spec & 1) {
    size_t bytes = std::min(count, remaining_bytes_);
    std::string buf(reinterpret_cast<const char*>(data_ptr_), bytes);
    for (char& c : buf) {
      c &= 0b01111111;  // Unset the first bit, clamp to ASCII
    }
    py::object ret = UnicodeFromKindAndData(1, buf.data(), buf.size());
    Advance(bytes);
    return ret;
  }

  if (string_spec & 2) {
    // Otherwise, 50% chance of utf-16-compatible string
    size_t bytes = std::min(count * 2, remaining_bytes_);
    size_t even_bytes = bytes & ~1ULL;
    std::vector<uint16_t> buf(even_bytes / 2);
    if (!buf.empty()) {
      memcpy(&buf[0], data_ptr_, even_bytes);
    }

    if (filter_surrogates) {
      for (uint16_t& codepoint : buf) {
        if (codepoint >= 0xd800 && codepoint < 0xe000) codepoint -= 0xd800;
      }
    }

    py::object ret = UnicodeFromKindAndData(2, buf.data(), buf.size());
    Advance(bytes);
    return ret;
  } else {
    // Otherwise, full 21-bitish Unicode characters, encoded into 32-bit chunks.
    size_t bytes = std::min(count * 4, remaining_bytes_);
    size_t group_bytes = bytes & ~3ULL;
    std::vector<uint32_t> buf(group_bytes / 4);
    if (!buf.empty()) {
      memcpy(buf.data(), data_ptr_, group_bytes);
    }
    for (uint32_t& codepoint : buf) {
      codepoint &= 0x1fffffU;  // 21 bits
      // The actual maximum is 0x10ffff, so if bit 0x100000 is set, zero out
      // nibble 0x0f0000.
      if (codepoint & 0x100000U) {
        codepoint &= ~0x0f0000U;
      }
    }

    if (filter_surrogates) {
      for (uint32_t& codepoint : buf) {
        if (codepoint >= 0xd800U && codepoint < 0xe000U) codepoint -= 0xd800U;
      }
    }

    auto ret = UnicodeFromKindAndData(4, buf.data(), buf.size());
    Advance(bytes);
    return ret;
  }
}

py::bytes FuzzedDataProvider::ConsumeBytes(size_t count) {
  size_t num_bytes = std::min(count, remaining_bytes_);

  if (!num_bytes) return py::bytes("", 0);

  py::bytes ret(reinterpret_cast<const char*>(data_ptr_), num_bytes);
  Advance(num_bytes);
  return ret;
}

py::object FuzzedDataProvider::ConsumeString(size_t count) {
#if PY_MAJOR_VERSION >= 3
  return ConsumeUnicode(count);
#else
  return ConsumeBytes(count);
#endif  // PY_MAJOR_VERSION >= 3
}

#define INT_TO_PYINT_FUNC PyLong_FromLong
#define UINT_TO_PYINT_FUNC PyLong_FromUnsignedLong

py::int_ FuzzedDataProvider::ConsumeInt(size_t bytes) {
  bytes = std::min(bytes, remaining_bytes_);
  PyObject* ret = nullptr;

  if (bytes == 0) {
    ret = INT_TO_PYINT_FUNC(0);
  } else if (bytes == 1) {
    ret = INT_TO_PYINT_FUNC(*reinterpret_cast<const int8_t*>(data_ptr_));
  } else if (bytes == 2) {
    ret = INT_TO_PYINT_FUNC(*reinterpret_cast<const int16_t*>(data_ptr_));
  } else if (bytes == 4) {
    ret = INT_TO_PYINT_FUNC(*reinterpret_cast<const int32_t*>(data_ptr_));
  } else if (bytes == 8) {
    ret = PyLong_FromLongLong(*reinterpret_cast<const int64_t*>(data_ptr_));
  } else if (bytes < 8) {
    int64_t tmp = 0;
    // We need to copy a number of bytes that fits into a 64-bit integer, so we
    // can just use that without having to go via a string. However,
    // we want to make sure sign extension works, so we get both positive and
    // negative values. To do that, we copy the integer into the high order
    // bytes of a 64-bit integer, then shift it down to the low bytes.
    memcpy(reinterpret_cast<char*>(&tmp) + 8 - bytes, data_ptr_, bytes);
    tmp >>= (64 - 8 * bytes);
    ret = PyLong_FromLongLong(tmp);
  } else {
    // The API for constructing a Big integer requires going through a string,
    // unfortunately. Emit a hex string, then convert it to a Big integer.
    // If the high-order bit is negative, do some Math (tm) to effect the
    // two's complement.
    char* buf = reinterpret_cast<char*>(alloca(2 * bytes + 2));
    buf[2 * bytes + 1] = '\0';
    uint16_t* number = reinterpret_cast<uint16_t*>(buf + 1);

    for (int i = 0; i < bytes; ++i) {
      number[bytes - i - 1] = FastByteToHex(data_ptr_[i]);
    }

    py::int_ obj(py::handle(PyLong_FromString(buf + 1, nullptr, 16)), false);

    if (data_ptr_[bytes - 1] & 0x80) {
      // number is negative
      py::int_ magnitude(1);
      magnitude = magnitude.attr("__lshift__")(bytes * 8);
      obj = obj - magnitude;
    }
    Advance(bytes);
    return obj;
  }

  Advance(bytes);
  return py::int_(py::handle(ret), false);
}

py::int_ FuzzedDataProvider::ConsumeUInt(size_t bytes) {
  bytes = std::min(bytes, remaining_bytes_);
  PyObject* ret = nullptr;

  if (bytes == 0) {
    ret = UINT_TO_PYINT_FUNC(0);
  } else if (bytes == 1) {
    uint8_t byte = *reinterpret_cast<const uint8_t*>(data_ptr_);
    ret = UINT_TO_PYINT_FUNC(byte);
  } else if (bytes == 2) {
    uint16_t bytes = *reinterpret_cast<const uint16_t*>(data_ptr_);
    ret = UINT_TO_PYINT_FUNC(bytes);
  } else if (bytes == 4) {
    uint32_t bytes = *reinterpret_cast<const uint32_t*>(data_ptr_);
    ret = UINT_TO_PYINT_FUNC(bytes);
  } else if (bytes == 8) {
    uint64_t bytes = *reinterpret_cast<const uint64_t*>(data_ptr_);
    ret = PyLong_FromUnsignedLongLong(bytes);
  } else if (bytes < 8) {
    uint64_t tmp = 0;
    // We need to copy a number of bytes that fits into a 64-bit integer, so we
    // can just use that without having to go via a string.
    memcpy(reinterpret_cast<char*>(&tmp), data_ptr_, bytes);
    ret = PyLong_FromUnsignedLongLong(tmp);
  } else {
    // The API for constructing a Big integer requires going through a string,
    // unfortunately. Emit a hex string, then convert it to a Big integer.
    char* buf = reinterpret_cast<char*>(alloca(2 * bytes + 2));
    buf[2 * bytes + 1] = '\0';
    uint16_t* number = reinterpret_cast<uint16_t*>(buf + 1);

    for (int i = 0; i < bytes; ++i) {
      number[bytes - i - 1] = FastByteToHex(data_ptr_[i]);
    }

    py::int_ obj(py::handle(PyLong_FromString(buf + 1, nullptr, 16)), false);

    Advance(bytes);
    return obj;
  }

  Advance(bytes);
  py::int_ tmp(py::handle(ret), false);
  return tmp;
}

py::int_ FuzzedDataProvider::ConsumeIntInRange(py::int_ min, py::int_ max) {
  py::int_ delta = max - min;

  if (delta < py::int_(0)) {
    std::cerr << Colorize(STDERR_FILENO,
                          "ConsumeIntInRange: min must be <= max")
              << " (got min=" << min << ", max=" << max << std::endl;
    exit(1);
  }

  int size = py::int_(delta.attr("bit_length")());
  if (size <= 64) {
    uint64_t native_delta = delta;
    uint64_t small_int = ConsumeSmallIntInRange(size, native_delta);
    py::int_ off = py::int_(small_int);
    py::int_ ret(min + off);
    return ret;
  }

  py::int_ ret =
      min + ConsumeInt(size / 8).attr("__mod__")(delta + py::int_(1));
  return ret;
}

int64_t FuzzedDataProvider::ConsumeSmallIntInRange(size_t n, uint64_t range) {
  uint64_t result = 0;
  size_t offset = 0;

  while (offset < n && (range >> offset) > 0 && remaining_bytes_ != 0) {
    --remaining_bytes_;
    result = (result << 8) | data_ptr_[remaining_bytes_];
    offset += 8;
  }

  if (range != std::numeric_limits<uint64_t>::max())
    result = result % (range + 1);

  return result;
}

py::list FuzzedDataProvider::ConsumeIntList(size_t count, size_t bytes) {
  py::list ret(count);
  for (size_t i = 0; i < count; ++i) {
    ret[i] = ConsumeInt(bytes);
  }
  return ret;
}

py::list FuzzedDataProvider::ConsumeIntListInRange(size_t len, py::int_ min,
                                                   py::int_ max) {
  py::list ret(len);
  for (size_t i = 0; i < len; ++i) {
    ret[i] = ConsumeIntInRange(min, max);
  }
  return ret;
}

const double kUInt64ToProbabilityDivisor = std::numeric_limits<uint64_t>::max();

double FuzzedDataProvider::ConsumeProbability() {
  uint64_t integral = 0;
  size_t bytes = std::min<size_t>(8, remaining_bytes_);
  memcpy(&integral, data_ptr_, bytes);
  Advance(bytes);

  return static_cast<double>(integral) / kUInt64ToProbabilityDivisor;
}

double FuzzedDataProvider::ConsumeFloat() {
  if (!remaining_bytes_) return 0.0;

  uint8_t type_val = *data_ptr_;
  Advance(1);

  if (type_val <= 10) {
    // Consume the same amount of bytes as for a regular float
    Advance(std::min<size_t>(9, remaining_bytes_));

    if (type_val == 0) return 0.0;
    if (type_val == 1) return -0.0;
    if (type_val == 2) return std::numeric_limits<double>::infinity();
    if (type_val == 3) return -std::numeric_limits<double>::infinity();
    if (type_val == 4) return std::numeric_limits<double>::quiet_NaN();
    // An sNaN is not valid in Python, so we don't create one here.
    if (type_val == 5) return std::numeric_limits<double>::denorm_min();
    if (type_val == 6) return -std::numeric_limits<double>::denorm_min();
    if (type_val == 7) return std::numeric_limits<double>::min();
    if (type_val == 8) return -std::numeric_limits<double>::min();
    if (type_val == 9) return std::numeric_limits<double>::max();
    if (type_val == 10) return -std::numeric_limits<double>::max();
  }

  double regular = ConsumeRegularFloat();
  return regular;
}

double FuzzedDataProvider::ConsumeRegularFloat() {
  return ConsumeFloatInRange(-std::numeric_limits<double>::max(),
                             std::numeric_limits<double>::max());
}

double FuzzedDataProvider::ConsumeFloatInRange(double min, double max) {
  if (min > max) {
    std::cerr << Colorize(STDERR_FILENO,
                          "ConsumeFloatInRange: min must be <= max")
              << " (got min=" << min << ", max=" << max << ")" << std::endl;
    exit(1);
  }

  double range = 0.0;
  double result = min;

  // Deal with overflow, in the event min and max are very far apart
  if (min < 0 && max > 0 && min + std::numeric_limits<double>::max() < max) {
    range = (max / 2) - (min / 2);
    if (ConsumeBool()) {
      result += range;
    }
  } else {
    range = max - min;
  }

  double probability = ConsumeProbability();
  return result + range * probability;
}

py::list FuzzedDataProvider::ConsumeFloatList(size_t count) {
  py::list ret(count);
  for (size_t i = 0; i < count; ++i) {
    ret[i] = py::float_(ConsumeFloat());
  }
  return ret;
}

py::list FuzzedDataProvider::ConsumeRegularFloatList(size_t count) {
  py::list ret(count);
  for (size_t i = 0; i < count; ++i) {
    ret[i] = py::float_(ConsumeRegularFloat());
  }
  return ret;
}
py::list FuzzedDataProvider::ConsumeProbabilityList(size_t count) {
  py::list ret(count);
  for (int i = 0; i < count; ++i) {
    ret[i] = py::float_(ConsumeProbability());
  }
  return ret;
}

py::list FuzzedDataProvider::ConsumeFloatListInRange(size_t count, double min,
                                                     double max) {
  py::list ret(count);
  for (size_t i = 0; i < count; ++i) {
    ret[i] = py::float_(ConsumeFloatInRange(min, max));
  }
  return ret;
}

bool FuzzedDataProvider::ConsumeBool() {
  if (!remaining_bytes_) return false;
  bool ret = *data_ptr_ & 1;
  Advance(1);
  return ret;
}

py::object FuzzedDataProvider::PickValueInList(py::list list) {
  if (list.size() <= std::numeric_limits<uint8_t>::max()) {
    return list[ConsumeSmallIntInRange(8, list.size() - 1)];
  } else if (list.size() <= std::numeric_limits<uint16_t>::max()) {
    return list[ConsumeSmallIntInRange(16, list.size() - 1)];
  } else if (list.size() <= std::numeric_limits<uint32_t>::max()) {
    return list[ConsumeSmallIntInRange(32, list.size() - 1)];
  } else {
    return list[ConsumeSmallIntInRange(64, list.size() - 1)];
  }
}

void FuzzedDataProvider::Advance(size_t bytes) {
  if (bytes > remaining_bytes_) {
    remaining_bytes_ = 0;
  } else {
    data_ptr_ += bytes;
    remaining_bytes_ -= bytes;
  }
}

}  // namespace atheris
