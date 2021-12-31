#include <memory>
#include "litecov.h"
#include "coverage.h"

std::unique_ptr<LiteCov> litecov_new() {
  return std::make_unique<LiteCov>();
}

std::unique_ptr<Coverage> coverage_new() {
    return std::make_unique<Coverage>();
}