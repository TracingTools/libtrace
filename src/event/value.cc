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

#include "event/value.h"

#include <limits>

#include "base/logging.h"
#include "base/string_utils.h"

namespace event {

bool Value::GetAsInteger(int32* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_BOOL: {
      *value = BoolValue::GetValue(this);
      return true;
    }
    case VALUE_CHAR: {
      *value = CharValue::GetValue(this);
      return true;
    }
    case VALUE_UCHAR: {
      *value = UCharValue::GetValue(this);
      return true;
    }
    case VALUE_SHORT: {
      *value = ShortValue::GetValue(this);
      return true;
    }
    case VALUE_USHORT: {
      *value = UShortValue::GetValue(this);
      return true;
    }
    case VALUE_INT: {
      *value = IntValue::GetValue(this);
      return true;
    }
    case VALUE_UINT: {
      uint32 raw_value = UIntValue::GetValue(this);
      if (raw_value > static_cast<uint32>(IntValue::MaxValue()))
        return false;
      *value = static_cast<int32>(raw_value);
      return true;
    }
    case VALUE_LONG: {
      int64 raw_value = LongValue::GetValue(this);
      if (raw_value > static_cast<int64>(IntValue::MaxValue()) ||
          raw_value < static_cast<int64>(IntValue::MinValue())) {
         return false;
      }
      *value = static_cast<int32>(raw_value);
      return true;
    }
    case VALUE_ULONG: {
      uint64 raw_value = ULongValue::GetValue(this);
      if (raw_value > static_cast<uint64>(IntValue::MaxValue()))
        return false;
      *value = static_cast<int32>(raw_value);
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsUInteger(uint32* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_BOOL: {
      *value = BoolValue::GetValue(this);
      return true;
    }
    case VALUE_CHAR: {
      int32 raw_value = CharValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint32>(raw_value);
      return true;
    }
    case VALUE_UCHAR: {
      *value = UCharValue::GetValue(this);
      return true;
    }
    case VALUE_SHORT: {
      int32 raw_value = ShortValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint32>(raw_value);
      return true;
    }
    case VALUE_USHORT: {
      *value = UShortValue::GetValue(this);
      return true;
    }
    case VALUE_INT: {
       int32 raw_value = IntValue::GetValue(this);
       if (raw_value < 0)
         return false;
      *value = static_cast<uint32>(raw_value);
      return true;
    }
    case VALUE_UINT: {
      *value = UIntValue::GetValue(this);
      return true;
    }
    case VALUE_LONG: {
      int64 raw_value = LongValue::GetValue(this);
      if (raw_value < 0)
        return false;
      if (raw_value > static_cast<int64>(UIntValue::MaxValue()))
        return false;
      *value = static_cast<uint32>(raw_value);
      return true;
    }
    case VALUE_ULONG: {
      uint64 raw_value = ULongValue::GetValue(this);
      if (raw_value > static_cast<uint64>(UIntValue::MaxValue()))
        return false;
      *value = static_cast<uint32>(raw_value);
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsLong(int64* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_BOOL: {
      *value = BoolValue::GetValue(this);
      return true;
    }
    case VALUE_CHAR: {
      *value = CharValue::GetValue(this);
      return true;
    }
    case VALUE_UCHAR: {
      *value = UCharValue::GetValue(this);
      return true;
    }
    case VALUE_SHORT: {
      *value = ShortValue::GetValue(this);
      return true;
    }
    case VALUE_USHORT: {
      *value = UShortValue::GetValue(this);
      return true;
    }
    case VALUE_INT: {
      *value = IntValue::GetValue(this);
      return true;
    }
    case VALUE_UINT: {
      *value = UIntValue::GetValue(this);
      return true;
    }
    case VALUE_LONG: {
      *value = LongValue::GetValue(this);
      return true;
    }
    case VALUE_ULONG: {
      uint64 uvalue = ULongValue::GetValue(this);
      if (uvalue > static_cast<uint64>(LongValue::MaxValue()))
        return false;
      *value = static_cast<int64>(uvalue);
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsULong(uint64* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_BOOL: {
      *value = BoolValue::GetValue(this);
      return true;
    }
    case VALUE_CHAR: {
      int32 raw_value = CharValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint64>(raw_value);
      return true;
    }
    case VALUE_UCHAR: {
      *value = UCharValue::GetValue(this);
      return true;
    }
    case VALUE_SHORT: {
      int32 raw_value = ShortValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint64>(raw_value);
      return true;
    }
    case VALUE_USHORT: {
      *value = UShortValue::GetValue(this);
      return true;
    }
    case VALUE_INT: {
      int32 raw_value = IntValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint64>(raw_value);
      return true;
    }
    case VALUE_UINT: {
      *value = UIntValue::GetValue(this);
      return true;
    }
    case VALUE_LONG: {
      int64 raw_value = LongValue::GetValue(this);
      if (raw_value < 0)
        return false;
      *value = static_cast<uint64>(raw_value);
      return true;
    }
    case VALUE_ULONG: {
      *value = ULongValue::GetValue(this);
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsFloating(double* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_FLOAT: {
      *value = FloatValue::GetValue(this);
      return true;
    }
    case VALUE_DOUBLE: {
      *value = DoubleValue::GetValue(this);
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsString(std::string* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_STRING: {
      *value = StringValue::GetValue(this);
      return true;
    }
    case VALUE_WSTRING: {
      *value = base::WStringToString(WStringValue::GetValue(this));
      return true;
    }
    default:
      return false;
  }
}

bool Value::GetAsWString(std::wstring* value) const {
  DCHECK(value != NULL);

  switch (GetType()) {
    case VALUE_STRING: {
      *value = base::StringToWString(StringValue::GetValue(this));
      return true;
    }
    case VALUE_WSTRING: {
      *value = WStringValue::GetValue(this);
      return true;
    }
    default:
      return false;
  }
}

template<class T, int TYPE>
ValueType ScalarValue<T, TYPE>::GetType() const {
  return static_cast<ValueType>(TYPE);
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::IsScalar() const {
  return true;
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::IsAggregate() const {
  return false;
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::IsInteger() const {
  return std::numeric_limits<T>::is_specialized &&
         std::numeric_limits<T>::is_integer;
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::IsSigned() const {
  return std::numeric_limits<T>::is_specialized &&
         (!std::numeric_limits<T>::is_integer ||
          std::numeric_limits<T>::is_signed);
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::IsFloating() const {
  return std::numeric_limits<T>::is_specialized &&
         !std::numeric_limits<T>::is_integer;
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::Equals(const Value* value) const {
  if (value == NULL)
    return false;

  if (!ScalarValue<T, TYPE>::InstanceOf(value))
    return false;
  if (ScalarValue<T, TYPE>::Cast(value)->GetValue() != GetValue())
    return false;
  return true;
}

template<class T, int TYPE>
const T& ScalarValue<T, TYPE>::GetValue() const {
  return value_;
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::InstanceOf(const Value* value) {
  DCHECK(value != NULL);
  return value->GetType() == TYPE;
}

template<class T, int TYPE>
const ScalarValue<T, TYPE>* ScalarValue<T, TYPE>::Cast(const Value* value) {
  DCHECK(value != NULL);
  DCHECK(value->GetType() == TYPE);
  return reinterpret_cast<const SelfType*>(value);
}

template<class T, int TYPE>
const T& ScalarValue<T, TYPE>::GetValue(const Value* value) {
  DCHECK(value != NULL);
  return Cast(value)->GetValue();
}

template<class T, int TYPE>
bool ScalarValue<T, TYPE>::GetValue(const Value* value, T* dst) {
  DCHECK(value != NULL);
  DCHECK(dst != NULL);
  if (!InstanceOf(value))
    return false;
  *dst = Cast(value)->GetValue();
  return true;
}

template<class T, int TYPE>
T ScalarValue<T, TYPE>::MinValue() {
  return std::numeric_limits<T>::min();
}

template<class T, int TYPE>
T ScalarValue<T, TYPE>::MaxValue() {
  return std::numeric_limits<T>::max();
}

template<int TYPE>
ValueType AggregateValue<TYPE>::GetType() const {
  return static_cast<ValueType>(TYPE);
};

template<int TYPE>
bool AggregateValue<TYPE>::IsScalar() const {
  return false;
}

template<int TYPE>
bool AggregateValue<TYPE>::IsAggregate() const {
  return true;
}

template<int TYPE>
bool AggregateValue<TYPE>::IsInteger() const {
  return false;
}

template<int TYPE>
bool AggregateValue<TYPE>::IsSigned() const {
  return false;
}

template<int TYPE>
bool AggregateValue<TYPE>::IsFloating() const {
  return false;
}

ArrayValue::ArrayValue() {
}

ArrayValue::~ArrayValue() {
  for (Values::iterator it = values_.begin(); it != values_.end(); ++it)
    delete *it;
}

bool ArrayValue::IsEmpty() const {
  return Length() == 0;
}

size_t ArrayValue::Length() const {
  return values_.size();
}

void ArrayValue::Append(scoped_ptr<Value> value) {
  DCHECK(value.get() != NULL);
  values_.push_back(value.release());
}

const Value* ArrayValue::operator[](size_t index) const {
  return values_.at(index);
}

Value* ArrayValue::operator[](size_t index) {
  return values_.at(index);
}

const Value* ArrayValue::at(size_t index) const {
  return values_.at(index);
}

Value* ArrayValue::at(size_t index) {
  return values_.at(index);
}

bool ArrayValue::GetElementAsInteger(size_t index, int32* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsInteger(value);
}

bool ArrayValue::GetElementAsUInteger(size_t index, uint32* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsUInteger(value);
}

bool ArrayValue::GetElementAsLong(size_t index, int64* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsLong(value);
}

bool ArrayValue::GetElementAsULong(size_t index, uint64* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsULong(value);
}

bool ArrayValue::GetElementAsFloating(size_t index, double* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsFloating(value);
}

bool ArrayValue::GetElementAsString(size_t index, std::string* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsString(value);
}

bool ArrayValue::GetElementAsWString(size_t index, std::wstring* value) const {
  DCHECK(value != NULL);
  if (index >= values_.size())
    return false;
  return at(index)->GetAsWString(value);
}

bool ArrayValue::Equals(const Value* value) const {
  if (value == NULL)
    return false;

  if (!ArrayValue::InstanceOf(value))
    return false;

  const ArrayValue* array = ArrayValue::Cast(value);
  if (array->Length() != Length())
    return false;

  const_iterator left = values_begin();
  const_iterator right = array->values_begin();
  while (left != values_end() || right != array->values_end()) {
    if (!(*left)->Equals(*right))
      return false;

    ++left;
    ++right;
  }

  return true;
}

bool ArrayValue::InstanceOf(const Value* value) {
  DCHECK(value != NULL);
  return value->GetType() == VALUE_ARRAY;
}

const ArrayValue* ArrayValue::Cast(const Value* value) {
  DCHECK(value != NULL);
  DCHECK(value->GetType() == VALUE_ARRAY);
  return reinterpret_cast<const ArrayValue*>(value);
}

StructValue::StructValue() {
}

StructValue::~StructValue() {
  for (ValueList::iterator it = fields_.begin(); it != fields_.end(); ++it)
    delete it->second;
}

bool StructValue::HasField(const std::string& name) const {
  return fields_map_.find(name) != fields_map_.end();
}

const Value* StructValue::GetField(const std::string& name) const {
  ValueMap::const_iterator look = fields_map_.find(name);
  if (look == fields_map_.end())
    return NULL;
  return look->second;
}

bool StructValue::GetField(const std::string& name,
                           const Value** value) const {
  DCHECK(value != NULL);
  ValueMap::const_iterator look = fields_map_.find(name);
  if (look == fields_map_.end())
    return false;
  *value = look->second;
  return true;
}

bool StructValue::GetFieldAsInteger(
    const std::string& name, int32* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsInteger(value);
}

bool StructValue::GetFieldAsUInteger(
    const std::string& name, uint32* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsUInteger(value);
}

bool StructValue::GetFieldAsLong(const std::string& name, int64* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsLong(value);
}

bool StructValue::GetFieldAsULong(
    const std::string& name, uint64* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsULong(value);
}

bool StructValue::GetFieldAsFloating(
    const std::string& name, double* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsFloating(value);
}

bool StructValue::GetFieldAsString(
    const std::string& name, std::string* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsString(value);
}

bool StructValue::GetFieldAsWString(
    const std::string& name, std::wstring* value) const {
  DCHECK(value != NULL);
  const Value* field = NULL;
  if (!GetField(name, &field))
    return false;
  return field->GetAsWString(value);
}

bool StructValue::AddField(const std::string& name, scoped_ptr<Value> value) {
  DCHECK(value.get() != NULL);
  if (HasField(name))
    return false;
  Value* raw_value = value.release();
  fields_.push_back(std::make_pair(name, raw_value));
  fields_map_.insert(std::make_pair(name, raw_value));
  return true;
}

bool StructValue::Equals(const Value* value) const {
  if (value == NULL)
    return false;

  if (!StructValue::InstanceOf(value))
    return false;

  const StructValue* strct = StructValue::Cast(value);

  const_iterator left = fields_begin();
  const_iterator right = strct->fields_begin();
  while (left != fields_end() && right != strct->fields_end()) {
    if (left->first.compare(right->first) != 0)
      return false;
    if (!left->second->Equals(right->second))
      return false;

    ++left;
    ++right;
  }

  if (left != fields_end() || right != strct->fields_end())
    return false;

  return true;
}

bool StructValue::InstanceOf(const Value* value) {
  DCHECK(value != NULL);
  return value->GetType() == VALUE_STRUCT;
}

const StructValue* StructValue::Cast(const Value* value) {
  DCHECK(value != NULL);
  DCHECK(value->GetType() == VALUE_STRUCT);
  return reinterpret_cast<const StructValue*>(value);
}

// Force a template instantiation in this compilation unit. This must be at
// the end of the file because only defined methods are instantiated.
template class ScalarValue<bool, VALUE_BOOL>;
template class ScalarValue<int8, VALUE_CHAR>;
template class ScalarValue<uint8, VALUE_UCHAR>;
template class ScalarValue<int16, VALUE_SHORT>;
template class ScalarValue<uint16, VALUE_USHORT>;
template class ScalarValue<int32, VALUE_INT>;
template class ScalarValue<uint32, VALUE_UINT>;
template class ScalarValue<int64, VALUE_LONG>;
template class ScalarValue<uint64, VALUE_ULONG>;
template class ScalarValue<std::string, VALUE_STRING>;
template class ScalarValue<std::wstring, VALUE_WSTRING>;
template class ScalarValue<float, VALUE_FLOAT>;
template class ScalarValue<double, VALUE_DOUBLE>;

}  // namespace event
