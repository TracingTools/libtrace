# libtrace

[![Build Status](https://travis-ci.org/TracingTools/libtrace.png?branch=master)](https://travis-ci.org/TracingTools/libtrace)

The libtrace librarie aims to help development of tools to analyze traces.


## Requirements (third party):

* [CMake](http://www.cmake.org/)
* [gmock](https://code.google.com/p/googlemock/) and [gtest](https://code.google.com/p/googletest/):
  ``svn checkout http://googlemock.googlecode.com/svn/trunk/ third_party/gmock``

## Building

```
cd libtrace
svn checkout http://googlemock.googlecode.com/svn/trunk/ third_party/gmock
cmake .
make
```

