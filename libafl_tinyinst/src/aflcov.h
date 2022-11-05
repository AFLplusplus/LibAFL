#pragma once
#include "litecov.h"

class AFLCov : public LiteCov {
 public:
  AFLCov() : LiteCov() {
  }

  void Init(int argc, char **argv) override {
    LiteCov::Init(argc, argv);
  }
}
