// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at

//   http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#include "Variane_testharness.h"
#include "verilator.h"
#include "verilated.h"
#include "verilated_vcd_c.h"
#include "Variane_testharness__Dpi.h"

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <getopt.h>
#include <chrono>
#include <ctime>
#include <signal.h>
#include <unistd.h>

#include <fesvr/dtm.h>

#include "interop.h"
#include "harness.h"
#define _GNU_SOURCE
#include <dlfcn.h>

static bool write_interception_enabled = false;
static bool ariane_initialised = false;
static int ariane_read_fd;
static size_t (*real_write)(int, const void *, size_t) = nullptr;

extern "C" {
  int __libafl_get_coverage_file_fd();

  // intercept writes to stdout to detect for initialisation
  ssize_t write(int fd, const void *buf, size_t count) {
    if (real_write == nullptr) {
      real_write =
          (size_t(*)(int, const void *, size_t))dlsym(RTLD_NEXT, "write");
    }
    if (write_interception_enabled) {
      if (memcmp(ARIANE_READY, buf, sizeof(ARIANE_READY)) == 0) {
        ariane_initialised = true;
        write_interception_enabled = false;
        ariane_read_fd = fd - 1;
        std::cout << "Ariane is ready! (notified by fd " << fd << ")" << std::endl;
        return count;
      }
    }
    return (*real_write)(fd, buf, count);
  }
}

// This software is heavily based on Rocket Chip
// Checkout this awesome project:
// https://github.com/freechipsproject/rocket-chip/

// This is a 64-bit integer to reduce wrap over issues and
// allow modulus.  You can also use a double, if you wish.
static vluint64_t main_time = 0;

extern dtm_t* dtm;

// Called by $time in Verilog converts to double, to match what SystemC does
double sc_time_stamp () {
  return main_time;
}

static Variane_testharness *top = nullptr;
static char executable_name[] = "ariane_harness";
static char jtag_option[] = "+jtag_rbb_enable=0";

extern "C" void __libafl_ariane_start(const char *input_file) {
  char *argv[3] = { executable_name, jtag_option, (char *) input_file };
  char *htif_argv[2] = { executable_name, (char *) input_file };

  Verilated::commandArgs(3, argv);

  dtm = new dtm_t(2, htif_argv);

  if (top != nullptr) abort();
  top = new Variane_testharness;

  for (int i = 0; i < 10; i++) {
    top->rst_ni = 0;
    top->clk_i = 0;
    top->rtc_i = 0;
    top->eval();
    top->clk_i = 1;
    top->eval();
    main_time++;
  }
  top->rst_ni = 1;

  write_interception_enabled = true;
  while (!ariane_initialised) {
    top->clk_i = 0;
    top->eval();

    top->clk_i = 1;
    top->eval();
    // toggle RTC
    if (main_time % 2 == 0) {
      top->rtc_i ^= 1;
    }
    main_time++;
  }
  write_interception_enabled = false;
}

extern "C" int __libafl_ariane_test_one_input(int input_fd) {
  dup2(input_fd, ariane_read_fd); // overwrite stdin for predictable fd in fesvr

  while (!dtm->done()) {
    top->clk_i = 0;
    top->eval();

    top->clk_i = 1;
    top->eval();
    // toggle RTC
    if (main_time % 2 == 0) {
      top->rtc_i ^= 1;
    }
    main_time++;
  }

  auto exit_code = dtm->exit_code();
  top->final();
  Verilated::quiesce();
  return exit_code;
}
