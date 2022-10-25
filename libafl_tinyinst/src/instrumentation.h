/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include <inttypes.h>
#include <string>
#include "coverage.h"
#include "runresult.h"

class Instrumentation {
public:
  virtual ~Instrumentation() { }

  virtual void Init(int argc, char **argv) = 0;
  virtual RunResult Run(int argc, char **argv, uint32_t init_timeout, uint32_t timeout) = 0;

  virtual RunResult RunWithCrashAnalysis(int argc, char** argv, uint32_t init_timeout, uint32_t timeout) {
    return Run(argc, argv, init_timeout, timeout);
  }

  virtual void CleanTarget() = 0;

  virtual bool HasNewCoverage() = 0;
  virtual void GetCoverage(Coverage &coverage, bool clear_coverage) = 0;
  virtual void ClearCoverage() = 0;
  virtual void IgnoreCoverage(Coverage &coverage) = 0;

  virtual std::string GetCrashName() { return "crash"; };

  virtual uint64_t GetReturnValue() { return 0; }

  std::string AnonymizeAddress(void* addr);
};
