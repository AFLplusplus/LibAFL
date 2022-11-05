#pragma once
#include <memory>
#include <vector>
#include "litecov.h"
#include "coverage.h"
#include "tinyinstinstrumentation.h"

// litecov
std::unique_ptr<Coverage> coverage_new();
void get_coverage_map(uint8_t *bitmap, size_t map_size, Coverage &newcoverage);

// tinyinstinstrumentation
std::unique_ptr<TinyInstInstrumentation> tinyinstinstrumentation_new();