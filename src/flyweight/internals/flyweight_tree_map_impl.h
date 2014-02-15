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

#ifndef FLYWEIGHT_INTERNALS_FLYWEIGHT_TREE_MAP_IMPL_H_
#define FLYWEIGHT_INTERNALS_FLYWEIGHT_TREE_MAP_IMPL_H_

#include <map>
#include <utility>
#include <vector>

#include "base/base.h"
#include "base/logging.h"
#include "base/observer.h"
#include "flyweight/flyweight.h"
#include "flyweight/flyweight_key.h"

namespace flyweight {
namespace internals {

// Implementation of Flyweight that uses a tree map to retreive the key that
// corresponds to a value in logarithmic time and a vector to retrieve the value
// that corresponds to a key in constant time.
template <typename T, typename I = DefaultFlyweightTag>
class FlyweightTreeMapImpl : public flyweight::FlyweightImpl<T, I> {
 public:
  typedef typename Flyweight<T, I>::Key Key;
  typedef typename Flyweight<T, I>::KeyValuePair KeyValuePair;
  typedef typename Flyweight<T, I>::Observer Observer;
  typedef typename Flyweight<T, I>::ObserverKeys ObserverKeys;
  typedef typename Flyweight<T, I>::ObserverValues ObserverValues;

  FlyweightTreeMapImpl() : flyweight::FlyweightImpl<T, I>() {
  }

  // Overrides flyweight::FlyweightImpl<T, I>.
  // @{
  virtual const Key& Insert(const T& value) OVERRIDE;
  virtual const T& ValueOf(const Key& key) const OVERRIDE;
  virtual void Enumerate(const Observer& observer) const OVERRIDE;
  virtual void EnumerateKeys(const ObserverKeys& observer) const OVERRIDE;
  virtual void EnumerateValues(const ObserverValues& observer) const OVERRIDE;
  // @}

 private:
  typedef typename std::map<const T, Key> ValuesToKeysMap;
  typedef typename std::vector<const T*> KeysToValuesVector;

  ValuesToKeysMap values_map_;
  KeysToValuesVector keys_;

  DISALLOW_COPY_AND_ASSIGN(FlyweightTreeMapImpl);
};

template <typename T, typename I>
const typename FlyweightTreeMapImpl<T, I>::Key& 
    FlyweightTreeMapImpl<T, I>::Insert(const T& value) {

  // Check whether this value already exists.
  typename ValuesToKeysMap::iterator look = values_map_.find(value);
  if (look != values_map_.end())
    return look->second;

  // Insert an instance of this value.
  std::pair<typename ValuesToKeysMap::iterator, bool> inserted =
      values_map_.insert(std::make_pair(value, Key(keys_.size())));
  DCHECK(inserted.second);

  // Add the pointer to |keys_|.
  typename ValuesToKeysMap::iterator place = inserted.first;
  const Key& new_key = place->second;
  const T& new_value = place->first;
  keys_.push_back(&new_value);

  return new_key;
}

template <typename T, typename I>
const T& FlyweightTreeMapImpl<T, I>::ValueOf(const Key& key) const {
  return *keys_.at(key.key_value());
}

template <typename T, typename I>
void FlyweightTreeMapImpl<T, I>::Enumerate(const Observer& observer) const {
  typename ValuesToKeysMap::const_iterator it = values_map_.begin();
  for (; it != values_map_.end(); ++it) {
    observer.Receive(std::make_pair(it->second, it->first));
  }
}

template <typename T, typename I>
void FlyweightTreeMapImpl<T, I>::EnumerateKeys(
    const ObserverKeys& observer) const {
  typename ValuesToKeysMap::const_iterator it = values_map_.begin();
  for (; it != values_map_.end(); ++it)
    observer.Receive(it->second);
}

template <typename T, typename I>
void FlyweightTreeMapImpl<T, I>::EnumerateValues(
    const ObserverValues& observer) const {
  typename KeysToValuesVector::const_iterator it = keys_.begin();
  for (; it != keys_.end(); ++it)
    observer.Receive(**it);
}

}  // namespace internals
}  // namespace flyweight

#endif  // FLYWEIGHT_INTERNALS_FLYWEIGHT_TREE_MAP_IMPL_H_
