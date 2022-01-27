/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Adrian Herrera <adrian.herrera@anu.edu.au>,
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   NGRAM previous location coverage comes from Adrian Herrera.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#include "common-llvm.h"

#include <time.h>

#include <list>
#include <string>
#include <fstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

typedef uint32_t prev_loc_t;

#define MAP_SIZE LIBAFL_EDGES_MAP_SIZE

using namespace llvm;

static cl::opt<bool> Debug("debug", cl::desc("Debug prints"), cl::init(false), cl::NotHidden);
static cl::opt<uint32_t> InstRatio("inst_ratio", cl::desc("Instrumentation ratio in percentage"), cl::init(100), cl::NotHidden);
static cl::opt<bool> ThreadSafe("thread_safe", cl::desc("Use the thread safe instrumentation"), cl::init(false), cl::NotHidden);

namespace {

#ifdef USE_NEW_PM
class AFLCoverage : public PassInfoMixin<AFLCoverage> {
 public:
  AFLCoverage() {
#else
class AFLCoverage : public ModulePass {
 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {
#endif

    // initInstrumentList();

  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t    map_size = MAP_SIZE;
  uint32_t    function_minimum_size = 1;

};

}  // namespace

#ifdef USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "AFLCoverageAccounting", "v0.1",
    /* lambda to insert our pass into the pass pipeline. */
    [](PassBuilder &PB) {
#if 1
       using OptimizationLevel = typename PassBuilder::OptimizationLevel;
       PB.registerOptimizerLastEPCallback(
         [](ModulePassManager &MPM, OptimizationLevel OL) {
           MPM.addPass(AFLCoverage());
         }
       );
/* TODO LTO registration */
#else
       using PipelineElement = typename PassBuilder::PipelineElement;
       PB.registerPipelineParsingCallback(
         [](StringRef Name, ModulePassManager &MPM, ArrayRef<PipelineElement>) {
            if ( Name == "AFLCoverageAccounting" ) {
              MPM.addPass(AFLCoverage());
              return true;
            } else {
              return false;
            }
         }
       );
#endif
    }
  };
}
#else

char AFLCoverage::ID = 0;
#endif

#ifdef USE_NEW_PM
PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool AFLCoverage::runOnModule(Module &M) {
#endif

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  uint32_t rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  /* Decide instrumentation ratio */

  if (!InstRatio || InstRatio > 100)
    FATAL("Bad value of the instrumentation ratio (must be between 1 and 100)");

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLMemWritePtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_memwrite_ptr");

  GlobalVariable *AFLMemReadPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_memread_ptr");

  GlobalVariable *AFLPrevLoc;

#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

  // other constants we need
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  /* Instrument all the things! */

  int inst_blocks = 0;
  // scanForDangerousFunctions(&M);

  for (auto &F : M) {

    int has_calls = 0;
    if (Debug)
      fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
              F.size());

    // if (!isInInstrumentList(&F)) { continue; }

    if (F.size() < function_minimum_size) { continue; }

    std::list<Value *> todo;
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (RandBelow(100) >= InstRatio) continue;

      uint32_t ReadsCnt = 0, WritesCnt = 0;

      for (auto &I : BB) {
          if (I.mayReadFromMemory())
              ++ReadsCnt;
          if (I.mayWriteToMemory())
              ++WritesCnt;
      }

      /* Make up cur_loc */

      cur_loc = RandBelow(map_size);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLoc, CurLoc));

      /* Update bitmap */

      if (ThreadSafe) {  /* Atomic */

        IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                            llvm::MaybeAlign(1),
#endif
                            llvm::AtomicOrdering::Monotonic);
      } else {

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }                                                  /* non atomic case */

      if (ReadsCnt > 0) {

        LoadInst *MemReadPtr = IRB.CreateLoad(AFLMemReadPtr);
        MemReadPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MemReadPtrIdx = IRB.CreateGEP(MemReadPtr, IRB.CreateXor(PrevLoc, CurLoc));

        LoadInst *MemReadCount = IRB.CreateLoad(MemReadPtrIdx);
        MemReadCount->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MemReadIncr = IRB.CreateAdd(MemReadCount, ConstantInt::get(Int32Ty, ReadsCnt));
        IRB.CreateStore(MemReadIncr, MemReadPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }

      if (WritesCnt > 0) {

        LoadInst *MemWritePtr = IRB.CreateLoad(AFLMemWritePtr);
        MemWritePtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MemWritePtrIdx = IRB.CreateGEP(MemWritePtr, IRB.CreateXor(PrevLoc, CurLoc));
      
        LoadInst *MemWriteCount = IRB.CreateLoad(MemWritePtrIdx);
        MemWriteCount->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MemWriteIncr = IRB.CreateAdd(MemWriteCount, ConstantInt::get(Int32Ty, WritesCnt));
        IRB.CreateStore(MemWriteIncr, MemWritePtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));      

      }

      /* Update prev_loc */

      StoreInst * Store = IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1),
                              AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }

  }
  
  if (Debug) {

    if (!inst_blocks)
      fprintf(stderr, "No instrumentation targets found.\n");
    else
      fprintf(stderr, "Instrumented %d locations (ratio %u%%).\n", inst_blocks, (unsigned)InstRatio);

  }

#ifdef USE_NEW_PM
  return PA;
#else
  return true;
#endif

}

#ifndef USE_NEW_PM
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
#endif
