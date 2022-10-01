#pragma once
#include <memory>
#include "litecov.h"
#include "coverage.h"
std::unique_ptr<LiteCov>  litecov_new();
std::unique_ptr<Coverage> coverage_new();