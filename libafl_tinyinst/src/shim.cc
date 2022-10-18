#include "shim.h"

std::unique_ptr<LiteCov> litecov_new() {
  return std::make_unique<LiteCov>();
}

std::unique_ptr<Coverage> coverage_new() {
  return std::make_unique<Coverage>();
}

void get_coverage_map(rust::Vec<uint8_t> &v, Coverage &newcoverage) {
  for (auto iter = newcoverage.begin(); iter != newcoverage.end(); iter++) {
    for (auto offset : iter->offsets) {
      v.push_back(offset);
    }
  }
}