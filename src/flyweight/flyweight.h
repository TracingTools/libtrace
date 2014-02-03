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
// A flyweight reduces the memory usage of an application by facilitating the
// sharing of immutable values.
//
// Example:
//  // Choose an implementation.
//  Flyweight<std::string> flyweight(new internals::FlyweightTreeMapImpl);
//
//  // k1 and k2 will refer to the same instance of the string "Dummy".
//  FlyweightKey<std::string> k1 = flyweight.Insert("Dummy");
//  FlyweightKey<std::string> k2 = flyweight.Insert("Dummy");
//  assert(k1 == k2);
//
//  // The following reference is valid until the source flyweight is deleted.
//  const std::string& v1 = flyweight.ValueOf(k1);
//  assert(v1.compare("Dummy") == 0);
//
// Traits can be used to statically check that keys that come from a flyweight
// are not used to access values in a flyweight with different traits.
//
// Example:
//  struct TagOne {};
//  struct TagTwo {};
//  Flyweight<std::string, TagOne> flyweight_one;
//  Flyweight<std::string, TagTwo> flyweight_two;
//
//  FlyweightKey<std::string, TagOne> k = flyweight_one.Insert("Dummy");
//  const std::string& v = flyweight_two.ValueOf(k);  // Doesn't compile.

#ifndef FLYWEIGHT_FLYWEIGHT_H_
#define FLYWEIGHT_FLYWEIGHT_H_

#include <utility>

#include "base/base.h"
#include "base/logging.h"
#include "base/observer.h"
#include "base/scoped_ptr.h"
#include "flyweight/flyweight_key.h"

namespace flyweight {

// Forward declaration.
template <typename T, typename I>
class FlyweightImpl;

// Data structure to share immutable values.
template <typename T, typename I = DefaultFlyweightTag>
class Flyweight {
 public:
  typedef FlyweightImpl<T, I> Impl;
  typedef FlyweightKey<T, I> Key;
  typedef base::Observer<std::pair<Key, T> > Observer;
  typedef base::Observer<Key> ObserverKeys;
  typedef base::Observer<T> ObserverValues;

  // Constructs the flyweight using the provided implementation.
  // @param impl the implementation to which all queries will be redirected.
  Flyweight(scoped_ptr<Impl> impl);

  // Inserts a value in the flyweight if it's not already present and returns
  // a key to retrieve it.
  // @param value an immutable value to share.
  // @returns a key that can be used to retrieve |value|.
  const Key& Insert(const T& value);

  // Retrieves a value using a key created by Insert().
  // @param key the key of the value to retrieve.
  // @returns the value associated with the provided key.
  const T& ValueOf(const Key& key) const;
  
  // Enumerates the key-value pairs of the flyweight.
  // @param observer an observer that will receive the key-value pairs.
  void Enumerate(const Observer& observer) const;

  // Enumerates the keys of the flyweight.
  // @param observer an observer that will receive the keys.
  void EnumerateKeys(const ObserverKeys& observer) const;

  // Enumerates the values of the flyweight.
  // @param observer an observer that will receive the values.
  void EnumerateValues(const ObserverValues& observer) const;

 private:
  // Implentation to which all queries are redirected.
  scoped_ptr<Impl> impl_;

  DISALLOW_COPY_AND_ASSIGN(Flyweight);
};

template <typename T, typename I = DefaultFlyweightTag>
class FlyweightImpl {
 public:
  typedef typename Flyweight<T, I>::Key Key;
  typedef typename Flyweight<T, I>::Observer Observer;
  typedef typename Flyweight<T, I>::ObserverKeys ObserverKeys;
  typedef typename Flyweight<T, I>::ObserverValues ObserverValues;

  virtual ~FlyweightImpl() { }

  virtual const Key& Insert(const T& value) = 0;
  virtual const T& ValueOf(const Key& key) const = 0;
  virtual void Enumerate(const Observer& observer) const = 0;
  virtual void EnumerateKeys(const ObserverKeys& observer) const = 0;
  virtual void EnumerateValues(const ObserverValues& observer) const = 0;
};

template <typename T, typename I>
Flyweight<T, I>::Flyweight(scoped_ptr<Impl> impl) : impl_(impl.Pass()) {
  DCHECK(impl_.get() != NULL);
}

template <typename T, typename I>
const typename Flyweight<T, I>::Key& Flyweight<T, I>::Insert(const T& value) {
  return impl_->Insert(value);
}

template <typename T, typename I>
const T& Flyweight<T, I>::ValueOf(const Key& key) const {
  return impl_->ValueOf(key);
}

template <typename T, typename I>
void Flyweight<T, I>::Enumerate(const Observer& observer) const {
  impl_->Enumerate(observer);
}

template <typename T, typename I>
void Flyweight<T, I>::EnumerateKeys(const ObserverKeys& observer) const {
  impl_->EnumerateKeys(observer);
}

template <typename T, typename I>
void Flyweight<T, I>::EnumerateValues(const ObserverValues& observer) const {
  impl_->EnumerateValues(observer);
}

}  // namespace flyweight

#endif  // FLYWEIGHT_FLYWEIGHT_H_
