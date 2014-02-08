// Copyright (c) 2014 The LibTrace Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of the <organization> nor the
//     names of its contributors may be used to endorse or promote products
//     derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "event/utils.h"

#include <sstream>

#include "base/logging.h"
#include "event/value.h"

namespace event {

namespace {

bool ToString(const Value* value, size_t indent, std::stringstream* result) {
  DCHECK(value != NULL);
  DCHECK(result != NULL);

  if (value->IsScalar()) {
    int8 char_value = 0;
    uint8 uchar_value = 0;
    int16 short_value = 0;
    uint16 ushort_value = 0;
    int32 int_value = 0;
    uint32 uint_value = 0;
    int64 long_value = 0;
    uint64 ulong_value = 0;
    float float_value = 0;
    double double_value = 0;
    std::string string_value;

    if (CharValue::GetValue(value, &char_value)) {
      *result << static_cast<int>(char_value);
      return true;
    } else if (UCharValue::GetValue(value, &uchar_value)) {
      *result << static_cast<unsigned int>(uchar_value);
      return true;
    } else if (ShortValue::GetValue(value, &short_value)) {
      *result << short_value;
      return true;
    } else if (UShortValue::GetValue(value, &ushort_value)) {
      *result << ushort_value;
      return true;
    } else if (IntValue::GetValue(value, &int_value)) {
      *result << int_value;
      return true;
    } else if (UIntValue::GetValue(value, &uint_value)) {
      *result << uint_value;
      return true;
    } else if (LongValue::GetValue(value, &long_value)) {
      *result << long_value;
      return true;
    } else if (ULongValue::GetValue(value, &ulong_value)) {
      *result << ulong_value;
      return true;
    } else if (FloatValue::GetValue(value, &float_value)) {
      *result << float_value;
      return true;
    } else if (DoubleValue::GetValue(value, &double_value)) {
      *result << double_value;
      return true;
    } else if (value->GetAsString(&string_value)) {
      *result << "\"" << string_value << "\""; // TODO(etienneb): escaping.
      return true;
    }
  } else if (value->IsAggregate()) {
    if (ArrayValue::InstanceOf(value)) {
      std::string indent_string = std::string(indent , ' ');
      std::string indent_field = std::string(indent + 4, ' ');
      const ArrayValue* array_value = ArrayValue::Cast(value);
      DCHECK(array_value != NULL);

      *result << "[\n";
      ArrayValue::const_iterator it = array_value->values_begin();
      for (; it != array_value->values_end(); ++it) {
        *result << indent_field;
        if (!ToString(*it, indent + 4, result))
          return false;
        *result << "\n";
      }
      *result << indent_string << "]";
      return true;
    } else if (StructValue::InstanceOf(value)) {
      std::string indent_string = std::string(indent , ' ');
      std::string indent_field = std::string(indent + 4, ' ');
      const StructValue* struct_value = StructValue::Cast(value);
      DCHECK(struct_value != NULL);

      *result << "{\n";
      StructValue::const_iterator it = struct_value->fields_begin();
      for (; it != struct_value->fields_end(); ++it) {
        *result << indent_field << it->first << " = ";
        if (!ToString(it->second, indent + 4, result))
          return false;
        *result << "\n";
      }
      *result << indent_string << "}";
      return true;
    }
  }

  return false;
}

}  // namespace

bool ToString(const Event& event, std::string* result) {
  DCHECK(result != NULL);

  std::stringstream ss;
  ss << "[" << event.timestamp() << "] event ";
  if (!ToString(event.payload(), 0, &ss))
    return false;

  *result = ss.str();
  return true;
}

bool ToString(const Value* value, std::string* result) {
  DCHECK(value != NULL);
  DCHECK(result != NULL);

  std::stringstream ss;
  if (!ToString(value, 0, &ss))
    return false;

  *result = ss.str();
  return true;
}

}  // namespace event
