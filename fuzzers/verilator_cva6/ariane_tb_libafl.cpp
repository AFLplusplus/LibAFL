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

#include "harness.h"

// This software is heavily based on Rocket Chip
// Checkout this awesome project:
// https://github.com/freechipsproject/rocket-chip/

VerilatedContext *__libafl_verilator_context;
extern dtm_t* dtm;

static Variane_testharness *top = nullptr;
static char executable_name[] = "ariane_harness";
static char jtag_option[] = "+jtag_rbb_enable=0";

extern "C" void __libafl_ariane_start(const char *input_file) {
  __libafl_verilator_context = new VerilatedContext;
  char *argv[3] = { executable_name, jtag_option, (char *) input_file };
  char *htif_argv[2] = { executable_name, (char *) input_file };

  __libafl_verilator_context->threads(1);
  __libafl_verilator_context->traceEverOn(false);
  __libafl_verilator_context->commandArgs(3, argv);

  dtm = new dtm_t(2, htif_argv);

  if (top != nullptr) abort();
  top = new Variane_testharness{__libafl_verilator_context, "CVA6"};

  for (int i = 0; i < 10; i++) {
    top->rst_ni = 0;
    top->clk_i = 0;
    top->rtc_i = 0;
    top->eval();
    top->clk_i = 1;
    top->eval();
    __libafl_verilator_context->timeInc(1);
  }
  top->rst_ni = 1;
}

extern "C" void __libafl_ariane_tick() {
  top->clk_i = 0;
  top->eval();

  top->clk_i = 1;
  top->eval();
  // toggle RTC
  if (__libafl_verilator_context->time() % 2 == 0) {
    top->rtc_i ^= 1;
  }
  __libafl_verilator_context->timeInc(1);
}

extern "C" void __libafl_ariane_terminate() {
  dtm->stop();
}

extern "C" bool __libafl_ariane_terminated() {
  return dtm->done();
}

extern "C" void __libafl_ariane_finalize() {
  top->final();
}
