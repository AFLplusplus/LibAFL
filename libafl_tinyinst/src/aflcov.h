#pragma once
#include "litecov.h"

class AFLCov : public LiteCov {
 public:
  AFLCov(uint8_t *_coverage, size_t _capacity) : LiteCov() {
    coverage = _coverage;
    capacity = _capacity;
  }

  void Init(int argc, char **argv) override {
    LiteCov::Init(argc, argv);
  }
  void add_coverage(uint64_t addr) {
    if (addr < capacity) {
      coverage[addr] = 1;
    } else {
      printf("Address %llx is out of bounds\n", addr);
    }
  }
  void print_coverage() {
    for (size_t i = 0; i < capacity; i++) {
      if (coverage[i] == 1) { printf("Address %llx is covered\n", i); }
    }
  }

  uint8_t *coverage;
  size_t   capacity;
};
