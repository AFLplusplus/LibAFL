#pragma once
#include <memory>
#include <vector>
#include "litecov.h"
#include "coverage.h"
std::unique_ptr<LiteCov>  litecov_new();
std::unique_ptr<Coverage> coverage_new();
void get_coverage_map(uint8_t *bitmap, size_t map_size, Coverage &newcoverage);
