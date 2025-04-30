/*
   LibAFL - DumpCfg LLVM pass
   --------------------------------------------------

   Written by Dongjia Zhang <toka@aflplus.plus>

   Copyright 2022-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/time.h>
#else
  #include <io.h>
#endif
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>
#include <set>

#include "common-llvm.h"
#include <iostream>

#include <nlohmann/json.hpp>

#define FATAL(x...)               \
  do {                            \
    fprintf(stderr, "FATAL: " x); \
    exit(1);                      \
                                  \
  } while (0)

using namespace llvm;

namespace {

class DumpCfgPass : public PassInfoMixin<DumpCfgPass> {
 public:
  DumpCfgPass() {
  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 protected:
  DenseMap<BasicBlock *, uint32_t>               bb_to_cur_loc;
  DenseMap<StringRef, BasicBlock *>              entry_bb;
  DenseMap<BasicBlock *, std::vector<StringRef>> calls_in_bb;

 private:
  bool isLLVMIntrinsicFn(StringRef &n) {
    // Not interested in these LLVM's functions
#if LLVM_VERSION_MAJOR >= 18
    if (n.starts_with("llvm.")) {
#else
    if (n.startswith("llvm.")) {
#endif
      return true;
    } else {
      return false;
    }
  }
};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DumpCfgPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
#if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
#endif

                ) { MPM.addPass(DumpCfgPass()); });
          }};
}

PreservedAnalyses DumpCfgPass::run(Module &M, ModuleAnalysisManager &MAM) {
  LLVMContext &Ctx = M.getContext();
  auto         moduleName = M.getName();

  for (auto &F : M) {
    unsigned bb_cnt = 0;
    entry_bb[F.getName()] = &F.getEntryBlock();
    for (auto &BB : F) {
      bb_to_cur_loc[&BB] = bb_cnt;
      bb_cnt++;
      for (auto &IN : BB) {
        CallBase *callBase = nullptr;
        if ((callBase = dyn_cast<CallBase>(&IN))) {
          auto F = callBase->getCalledFunction();
          if (F) {
            StringRef fname = F->getName();
            if (isLLVMIntrinsicFn(fname)) { continue; }

            calls_in_bb[&BB].push_back(fname);
          }
        }
      }
    }
  }

  nlohmann::json cfg;

  // Dump CFG for this module
  for (auto record = bb_to_cur_loc.begin(); record != bb_to_cur_loc.end();
       record++) {
    auto        current_bb = record->getFirst();
    auto        loc = record->getSecond();
    Function   *calling_func = current_bb->getParent();
    std::string func_name = std::string("");

    if (calling_func) {
      func_name = std::string(calling_func->getName());
      // outs() << "Function name: " << calling_func->getName() << "\n";
    }

    std::vector<uint32_t> outgoing;
    for (auto bb_successor = succ_begin(current_bb);
         bb_successor != succ_end(current_bb); bb_successor++) {
      outgoing.push_back(bb_to_cur_loc[*bb_successor]);
    }
    cfg["edges"][func_name][loc] = outgoing;
  }

  for (auto record = calls_in_bb.begin(); record != calls_in_bb.end();
       record++) {
    auto        current_bb = record->getFirst();
    auto        loc = bb_to_cur_loc[current_bb];
    Function   *calling_func = current_bb->getParent();
    std::string func_name = std::string("");

    if (calling_func) {
      func_name = std::string(calling_func->getName());
      // outs() << "Function name: " << calling_func->getName() << "\n";
    }

    std::vector<std::string> outgoing_funcs;
    for (auto &item : record->getSecond()) {
      outgoing_funcs.push_back(std::string(item));
    }
    if (!outgoing_funcs.empty()) {
      cfg["calls"][func_name][std::to_string(loc)] = outgoing_funcs;
    }
  }

  for (auto record = entry_bb.begin(); record != entry_bb.end(); record++) {
    cfg["entries"][std::string(record->getFirst())] =
        bb_to_cur_loc[record->getSecond()];
  }

  if (getenv("CFG_OUTPUT_PATH")) {
    std::ofstream cfg_out(getenv("CFG_OUTPUT_PATH") + std::string("/") +
                          std::string(moduleName) + ".cfg");
    cfg_out << cfg << "\n";
  } else {
    FATAL("CFG_OUTPUT_PATH not set!");
  }

  auto PA = PreservedAnalyses::all();
  return PA;
}