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
//
// This file specifies a recursive data storage class called Value intended for
// storing event fields as a tree. Values are divided into two categories:
// scalar and aggregate. A scalar holds a value of a given basic type and an
// aggregate is a container for multiple disparate values.
//
// Usage examples:
// - Creation
//   scoped_ptr<ArrayValue> my_array(new ArrayValue());
//   my_array->Append<IntValue>(42);
//   my_array->Append<IntValue>(1024);
//   my_array->Append<StringValue>("end");
//
//   scoped_ptr<StructValue> top_struct(new StructValue());
//   top_struct->AddField("name1", my_array.Pass());
//   top_struct->AddField<LongValue>("name2", new LongValue(4U));
//
// - Introspection and casting
//   scoped_ptr<IntValue> value(new IntValue(42));
//   if (value->IsInteger())
//    // value is an integer.
//
//   if (IntValue::InstanceOf(value.get())
//    const IntValue* int_value = IntValue::Cast(value.get());
//    // Use int_value to access IntValue specific methods.
//
// - Value accessor
//   scoped_ptr<IntValue> value(new IntValue(42));
//
//   uint32 result = 0;
//   if (value->GetAsUInteger(&result))
//     // do something with result
//
//   int32 result = IntValue::GetValue(result.get());
//   // do something with result

#ifndef EVENT_VALUE_H_
#define EVENT_VALUE_H_

#include <cstdlib>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "base/base.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"

namespace event {

enum ValueType {
  VALUE_BOOL,
  VALUE_CHAR,
  VALUE_UCHAR,
  VALUE_SHORT,
  VALUE_USHORT,
  VALUE_INT,
  VALUE_UINT,
  VALUE_LONG,
  VALUE_ULONG,
  VALUE_FLOAT,
  VALUE_DOUBLE,
  VALUE_STRING,
  VALUE_WSTRING,
  VALUE_STRUCT,
  VALUE_ARRAY
};

// The Value class is the base class for Values. Types are implemented by
// subclasses of Value. A cast from Value* to Subclass* is needed to access
// specific methods and fields. Some convenience methods ease the access to
// common functionalities.
class Value {
 public:
  // Destructor.
  virtual ~Value() { }

  // Returns the type of the value stored by the current Value object.
  virtual ValueType GetType() const = 0;

  // These methods return some properties of the value type.
  // @{
  virtual bool IsScalar() const = 0;
  virtual bool IsAggregate() const = 0;
  virtual bool IsInteger() const = 0;
  virtual bool IsSigned() const = 0;
  virtual bool IsFloating() const = 0;
  // @}

  // These methods allow the convenient retrieval of a basic value.
  // If the current value can be converted into the given type,
  // the value is returned through the |value| parameter.
  // @param value receives the value holded in this wrapper.
  // @returns true when the conversion is valid, false otherwise and |value|
  // stays unchanged.
  // @{
  bool GetAsInteger(int32* value) const;
  bool GetAsUInteger(uint32* value) const;
  bool GetAsLong(int64* value) const;
  bool GetAsULong(uint64* value) const;
  bool GetAsFloating(double* value) const;
  bool GetAsString(std::string* value) const;
  bool GetAsWString(std::wstring* value) const;
  // @}

  // Compare this value with the given value |value|.
  // @param value the value to compare with.
  // @returns true when both values are equal, false otherwise.
  virtual bool Equals(const Value* value) const = 0;
};

template<class T, int TYPE>
class ScalarValue : public Value {
 public:
  typedef ScalarValue<T, TYPE> SelfType;
  typedef T ScalarType;

  explicit ScalarValue(const T& value)
      : value_(value) {
  }

  // Overridden from Value:
  // @{
  virtual ValueType GetType() const OVERRIDE;
  virtual bool IsScalar() const OVERRIDE;
  virtual bool IsAggregate() const OVERRIDE;
  virtual bool IsInteger() const OVERRIDE;
  virtual bool IsSigned() const OVERRIDE;
  virtual bool IsFloating() const OVERRIDE;

  virtual bool Equals(const Value* value) const OVERRIDE;
  // @}

  // Retrieve the value holded in this wrapper.
  const T& GetValue() const;

  // Cast and retrieve the value holded in |value|.
  // @param value the value to retrieve (must be of the appropriate type).
  // @returns the value holded in this wrapper.
  static const T& GetValue(const Value* value);

  // Try to retrieve the value holded in |value|.
  // @param value the value to retrieve.
  // @param dst receives the value holded in this wrapper.
  // @returns true is the conversion is valid, false otherwise.
  static bool GetValue(const Value* value, T* dst);

  // Determine if |value| is of type |TYPE|.
  // @returns true is |value| has the appropriate type, false otherwise.
  static bool InstanceOf(const Value* value);

  // Cast |value| to type |TYPE|.
  // @param value the value to cast.
  // @returns the casted value.
  static const SelfType* Cast(const Value* value);

  // Returns the minimun value representable by |T|.
  static T MinValue();

  // Returns the maximal value representable by |T|.
  static T MaxValue();

 private:
  T value_;
};

typedef ScalarValue<bool, VALUE_BOOL> BoolValue;
typedef ScalarValue<int8, VALUE_CHAR> CharValue;
typedef ScalarValue<uint8, VALUE_UCHAR> UCharValue;
typedef ScalarValue<int16, VALUE_SHORT> ShortValue;
typedef ScalarValue<uint16, VALUE_USHORT> UShortValue;
typedef ScalarValue<int32, VALUE_INT> IntValue;
typedef ScalarValue<uint32, VALUE_UINT> UIntValue;
typedef ScalarValue<int64, VALUE_LONG> LongValue;
typedef ScalarValue<uint64, VALUE_ULONG> ULongValue;
typedef ScalarValue<std::string, VALUE_STRING> StringValue;
typedef ScalarValue<std::wstring, VALUE_WSTRING> WStringValue;
typedef ScalarValue<float, VALUE_FLOAT> FloatValue;
typedef ScalarValue<double, VALUE_DOUBLE> DoubleValue;

template<int TYPE>
class AggregateValue : public Value {
 public:
  // Overridden from Value:
  // @{
  virtual ValueType GetType() const OVERRIDE;
  virtual bool IsScalar() const OVERRIDE;
  virtual bool IsAggregate() const OVERRIDE;
  virtual bool IsInteger() const OVERRIDE;
  virtual bool IsSigned() const OVERRIDE;
  virtual bool IsFloating() const OVERRIDE;
  // @}
};

// An ArrayValue holds a sequence of disparate values.
class ArrayValue : public AggregateValue<VALUE_ARRAY> {
 public:
  typedef std::vector<Value*> Values;
  typedef Values::const_iterator const_iterator;

  ArrayValue();
  virtual ~ArrayValue();
  
  // Returns whether the array is empty.
  bool IsEmpty() const;

  // Returns the number of elements in the array.
  size_t Length() const;

  // Appends a Value to the end of the sequence.
  // Take the ownership of |value|.
  // @param value the value to add.
  void Append(scoped_ptr<Value> value);

  // Allocates and appends a typed value to the array.
  // @tparam T a scalar value type (i.e. CharValue, IntValue, ...).
  // @param value the value to add.
  template<class T>
  void Append(const typename T::ScalarType& value) {
    scoped_ptr<Value> ptr(new T(value));
    Append(ptr.Pass());
  }

  // Appends to the end of the sequence a series of value.
  // @param value the values to add.
  // @param length the number of values to add.
  template<class T>
  void AppendAll(const typename T::ScalarType* value, size_t length) {
    for (size_t i = 0; i < length; ++i)
      Append<T>(value[i]);
  }

  // Returns the element at position |index|.
  // @param index the offset of the element to retrieve.
  // @{
  const Value* operator[](size_t index) const;
  Value* operator[](size_t index);

  const Value* at(size_t index) const;
  Value* at(size_t index);
  // @}

  // Retrieve the value of a given type for the element at position |index|.
  // @tparam T the type to cast the element value.
  // @param index the offset of the element in the array.
  // @param value receives the value of the element.
  // @returns true if the element is found and of the specified type, false
  //     otherwise.
  template<class T>
  bool GetElementAs(size_t index, const T** value) const {
    DCHECK(value != NULL);
    if (index >= values_.size())
      return false;
    const Value* field = at(index);
    if (!T::InstanceOf(field))
      return false;
    *value = T::Cast(field);
    return true;
  }

  // These methods allow the convenient retrieval of an element of the array
  // with a basic value. If the current value can be converted into the given
  // type, the value is returned through the |value| parameter.
  // @param index the offset of the element in the array.
  // @param value receives the value holded by the field.
  // @returns true when the conversion is valid, false otherwise and |value|
  // stay unchanged.
  // @{
  bool GetElementAsInteger(size_t index, int32* value) const;
  bool GetElementAsUInteger(size_t index, uint32* value) const;
  bool GetElementAsLong(size_t index, int64* value) const;
  bool GetElementAsULong(size_t index, uint64* value) const;
  bool GetElementAsFloating(size_t index, double* value) const;
  bool GetElementAsString(size_t index, std::string* value) const;
  bool GetElementAsWString(size_t index, std::wstring* value) const;
  // @}

  // Overridden from Value:
  // @{
  virtual bool Equals(const Value* value) const OVERRIDE;
  // @}

  // Iteration.
  // @{
  const_iterator values_begin() const { return values_.begin(); }
  const_iterator values_end() const { return values_.end(); }
  // @}

  // Determine if |value| is of type ArrayType.
  // @param value the value to check type.
  // @returns true is |value| has the appropriate type, false otherwise.
  static bool InstanceOf(const Value* value);

  // Cast |value| to type ArrayType.
  // @param value the value to cast.
  // @returns the casted value.
  static const ArrayValue* Cast(const Value* value);

 private:
  Values values_;

  DISALLOW_COPY_AND_ASSIGN(ArrayValue);
};

// StructValue provides a key-value dictionary and keeps fields in a sequence.
class StructValue : public AggregateValue<VALUE_STRUCT> {
 public:
  typedef std::map<std::string, Value*> ValueMap;
  typedef std::list<std::pair<std::string, Value*> > ValueList;
  typedef ValueList::const_iterator const_iterator;

  StructValue();
  virtual ~StructValue();

  // Check whether the dictionary has a value for the given field name.
  // @param name the name to check existence.
  // @returns true if the dictionary has a field named |name|.
  bool HasField(const std::string& name) const;

  // Retrieve the value for a given name.
  // @param name the name of the field to find.
  // @returns the value of the field if the field is found, NULL otherwise.
  const Value* GetField(const std::string& name) const;

  // Retrieve the value for a given name.
  // @param name the name of the field to find.
  // @param value receives the value of the field with name |name|.
  // @returns true if the field is found, false otherwise.
  bool GetField(const std::string& name, const Value** value) const;

  // Retrieve the value of a given type for a given name.
  // @tparam T the type to cast the field value.
  // @param name the name of the field to find.
  // @param value receives the value of the field with name |name|.
  // @returns true if the field is found and of the specified type, false
  //     otherwise.
  template<class T>
  bool GetFieldAs(const std::string& name, const T** value) const {
    DCHECK(value != NULL);
    const Value* field = NULL;
    if (!GetField(name, &field) || !T::InstanceOf(field))
      return false;
    *value = T::Cast(field);
    return true;
  }

  // These methods allow the convenient retrieval of a field with a basic
  // value. If the current value can be converted into the given type,
  // the value is returned through the |value| parameter.
  // @param name the name of the field to retrieve.
  // @param value receives the value holded by the field.
  // @returns true when the conversion is valid, false otherwise and |value|
  // stay unchanged.
  // @{
  bool GetFieldAsInteger(const std::string& name, int32* value) const;
  bool GetFieldAsUInteger(const std::string& name, uint32* value) const;
  bool GetFieldAsLong(const std::string& name, int64* value) const;
  bool GetFieldAsULong(const std::string& name, uint64* value) const;
  bool GetFieldAsFloating(const std::string& name, double* value) const;
  bool GetFieldAsString(const std::string& name, std::string* value) const;
  bool GetFieldAsWString(const std::string& name, std::wstring* value) const;
  // @}

  // Add a field with name |name| to this structure.
  // @param name the name of the field.
  // @param value the value of the field.
  // @returns true if the field can be added, false otherwise.
  bool AddField(const std::string& name, scoped_ptr<Value> value);

  // Add a field with name |name| to this structure.
  // @tparam T the type of the value of the field.
  // @param name the name of the field.
  // @param value the value of the field.
  // @returns true if the field can be added, false otherwise.
  template<class T>
  bool AddField(const std::string& name, const typename T::ScalarType& value) {
    scoped_ptr<Value> ptr(new T(value));
    return AddField(name, ptr.Pass());
  }

  // Overridden from Value:
  // @{
  virtual bool Equals(const Value* value) const OVERRIDE;
  // @}

  // Iteration.
  // @{
  const_iterator fields_begin() const { return fields_.begin(); }
  const_iterator fields_end() const { return fields_.end(); }
  // @}

  // Determine if |value| is of type StructType.
  // @returns true is |value| has the appropriate type, false otherwise.
  static bool InstanceOf(const Value* value);

  // Cast |value| to type StructType.
  // @param value the value to cast.
  // @returns the casted value.
  static const StructValue* Cast(const Value* value);

 private:
  ValueList fields_;
  ValueMap fields_map_;

  DISALLOW_COPY_AND_ASSIGN(StructValue);
};

}  // namespace event

#endif  // EVENT_VALUE_H_
