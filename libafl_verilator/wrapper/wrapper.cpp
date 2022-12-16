#include <verilated.h>
#include <verilated_cov.h>
#include "wrapper.h"

static const char *__libafl_verilator_coverage_filename_base = "/proc/self/fd/%d";

static int __libafl_verilator_coverage_fd = -1;
static char *__libafl_verilator_coverage_filename = nullptr;

extern "C" {

void __libafl_set_coverage_file_fd(int fd) {
  __libafl_verilator_coverage_fd = fd;
}

void __libafl_process_verilator_coverage() {
  if (__libafl_verilator_coverage_filename == nullptr) {
    if (__libafl_verilator_coverage_fd == -1) {
      abort();
    }
    __libafl_verilator_coverage_filename = reinterpret_cast<char *>(malloc(strlen(__libafl_verilator_coverage_filename_base) + 16));
    sprintf(__libafl_verilator_coverage_filename, __libafl_verilator_coverage_filename_base, __libafl_verilator_coverage_fd);
  }
  VerilatedCov::write(__libafl_verilator_coverage_filename);
}

void __libafl_reset_verilator_coverage() {
  VerilatedCov::clear();
}

}