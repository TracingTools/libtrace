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
// The parser manages the parsing and decoding of the trace files. To support
// multiple trace formats, the parser depends on helpers (ParserImpl). Each
// ParserImpl recognize one trace format and must be registred before parsing.
//
// The steps to use the parser:
//
//     1) Create a parser instance,
//     2) Register needed parser implementations,
//     3) Add trace files to parse,
//     4) Call the Parse() method,
//     5) Receive the decoded events through the observer.
//
// The parser is intented to be used like that:
//
//   parser::Parser parser;
//   parser.RegisterParser(new parser::dummy::DummyParser());
//   if (!parser.AddTraceFile("trace.dummy")
//     return false;
//   parser.Parse(base::MakeObserver(&observer, &Observer::Receive));

#ifndef PARSER_PARSER_H_
#define PARSER_PARSER_H_

#include <list>
#include <string>

#include "base/base.h"
#include "base/scoped_ptr.h"
#include "base/observer.h"
#include "event/event.h"

namespace parser {

// Forward declaration.
class ParserImpl;

// The trace files parser.
class Parser {
 public:
  typedef std::list<ParserImpl*> ParserList;

  // Constructor.
  Parser() { }

  // Destructor.
  ~Parser();

  // Adds a new kind of parser to the list of parsers.
  // @param parser the parser to add.
  void RegisterParser(scoped_ptr<ParserImpl> parser);

  // Adds a trace file to the list of traces to parse.
  // @param path absolute path to the trace file.
  // @returns true if the trace can be handled by this parser, false otherwise.
  bool AddTraceFile(const std::string& path);

  // Parses the trace files added with AddTraceFile() and sends the resulting
  // events to the provided observer.
  // @param observer an observer that will receive the decoded events.
  void Parse(const base::Observer<event::Event>& observer);

 private:
  ParserList parsers_;

  DISALLOW_COPY_AND_ASSIGN(Parser);
};

// A parser implementation for a specific file format.
class ParserImpl {
 public:
   virtual ~ParserImpl() { }

  // Adds a trace file to the list of traces to parse.
  // @param path absolute path to the trace file.
  // @returns true if the trace can be handled by this parser, false otherwise.
  virtual bool AddTraceFile(const std::string& path) = 0;

  // Parses the trace files added with AddTraceFile() and sends the resulting
  // events to the provided observer.
  // @param observer an observer that will receive the decoded events.
  virtual void Parse(const base::Observer<event::Event>& observer) = 0;
};

}  // namespace parser

#endif  // PARSER_PARSER_H_
