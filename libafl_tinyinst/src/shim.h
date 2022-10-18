#pragma once
#include <memory>
#include <vector>
#include "litecov.h"
#include "coverage.h"
#include "bridge.h"
std::unique_ptr<LiteCov>  litecov_new();
std::unique_ptr<Coverage> coverage_new();
void get_coverage_map(rust::Vec<uint8_t> &v, Coverage &newcoverage);