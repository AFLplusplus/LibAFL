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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Support/FormatVariadic.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

typedef uint32_t prev_loc_t;

/* Maximum ngram size */
#define NGRAM_SIZE_MAX 16U

/* Maximum K for top-K context sensitivity */
#define CTX_MAX_K 32U

#define MAP_SIZE LIBAFL_EDGES_MAP_SIZE

using namespace llvm;

static cl::opt<bool> Debug("debug", cl::desc("Debug prints"), cl::init(false), cl::NotHidden);
static cl::opt<uint32_t> InstRatio("inst_ratio", cl::desc("Instrumentation ratio in percentage"), cl::init(100), cl::NotHidden);
static cl::opt<bool> NotZero("not_zero", cl::desc("Never hit 0 again in the hitcount"), cl::init(true), cl::NotHidden);
static cl::opt<uint32_t> Ngram("ngram", cl::desc("Size of the Ngram instrumentation (0 to disable)"), cl::init(0), cl::NotHidden);
static cl::opt<uint32_t> CtxK("ctx_k", cl::desc("Size of the context for K-Ctx context sensitivity (0 to disable)"), cl::init(0), cl::NotHidden);
static cl::opt<bool> Ctx("ctx", cl::desc("Enable full context sensitive coverage"), cl::init(false), cl::NotHidden);
static cl::opt<bool> ThreadSafe("thread_safe", cl::desc("Use the thread safe instrumentation"), cl::init(false), cl::NotHidden);
static cl::opt<bool> DumpCFG("dump_afl_cfg", cl::desc("Dump CFG containing AFL-style edge index"), cl::init(false), cl::NotHidden);
static cl::opt<std::string> DumpCFGPath("dump_afl_cfg_path", cl::desc("Path to dump CFG containing AFL-style edge index"), cl::init(".cfg"), cl::NotHidden);

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
  uint32_t                           map_size = MAP_SIZE;
  uint32_t                           function_minimum_size = 1;
  DenseMap<BasicBlock *, int32_t>    bb_to_cur_loc;
  DenseMap<StringRef, BasicBlock *>  entry_bb;

};

}  // namespace

#ifdef USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "AFLCoverage", "v0.1",
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
            if ( Name == "AFLCoverage" ) {
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
  if (Ctx && DumpCFG) FATAL("Does not support dumping CFG with full context sensitive coverage enabled.");
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
#ifdef HAVE_VECTOR_INTRINSICS
  IntegerType *IntLocTy =
      IntegerType::getIntNTy(C, sizeof(prev_loc_t) * CHAR_BIT);
#endif
  uint32_t rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  /*
    char *ptr;
    if ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE"))) {

      map_size = atoi(ptr);
      if (map_size < 8 || map_size > (1 << 29))
        FATAL("illegal AFL_MAP_SIZE %u, must be between 2^3 and 2^30",
    map_size); if (map_size % 8) map_size = (((map_size >> 3) + 1) << 3);

    }

  */

  /* Decide instrumentation ratio */

  if (!InstRatio || InstRatio > 100)
    FATAL("Bad value of the instrumentation ratio (must be between 1 and 100)");

  unsigned PrevLocSize = 0;
  unsigned PrevCallerSize = 0;

  bool instrument_ctx = Ctx || CtxK > 0;
  bool instrument_caller = false;

#ifdef HAVE_VECTOR_INTRINSICS
  /* Decide previous location vector size (must be a power of two) */
  VectorType *PrevLocTy = NULL;

  if (Ngram && (Ngram < 2 || Ngram > NGRAM_SIZE_MAX))
      FATAL(
          "Bad value of the Ngram size (must be between 2 and NGRAM_SIZE_MAX "
          "(%u))",
          NGRAM_SIZE_MAX);

  if (Ngram)
    PrevLocSize = Ngram - 1;
  else
    PrevLocSize = 1;

  /* Decide K-Ctx vector size (must be a power of two) */
  VectorType *PrevCallerTy = NULL;

  if (CtxK > CTX_MAX_K)
      FATAL("Bad value of K for K-context sensitivity (must be between 1 and CTX_MAX_K (%u))",
            CTX_MAX_K);

  if (CtxK == 1) {

    CtxK = 0;
    instrument_ctx = true;
    instrument_caller = true;  // Enable CALLER instead

  }

  if (CtxK) {

    PrevCallerSize = CtxK;
    instrument_ctx = true;

  }

#else
  if (Ngram)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  if (CtxK)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  PrevLocSize = 1;
#endif

#ifdef HAVE_VECTOR_INTRINSICS
  int PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
  if (Ngram)
    PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                ,
                                false
  #endif
    );
#endif

#ifdef HAVE_VECTOR_INTRINSICS
  int PrevCallerVecSize = PowerOf2Ceil(PrevCallerSize);
  if (CtxK)
    PrevCallerTy = VectorType::get(IntLocTy, PrevCallerVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                   ,
                                   false
  #endif
    );
#endif

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  GlobalVariable *AFLPrevLoc;
  GlobalVariable *AFLPrevCaller;
  GlobalVariable *AFLContext = NULL;

  if (Ctx || instrument_caller)
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
#else
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef HAVE_VECTOR_INTRINSICS
  if (Ngram)
  #if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc");
  #else
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
  #endif
  else
#endif
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef HAVE_VECTOR_INTRINSICS
  if (CtxK)
  #if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller");
  #else
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
  #endif
  else
#endif
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__afl_prev_caller");
#else
  AFLPrevCaller = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_caller",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef HAVE_VECTOR_INTRINSICS
  /* Create the vector shuffle mask for updating the previous block history.
     Note that the first element of the vector will store cur_loc, so just set
     it to undef to allow the optimizer to do its thing. */

  SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

  for (unsigned I = 0; I < PrevLocSize - 1; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));

  for (int I = PrevLocSize; I < PrevLocVecSize; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize));

  Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);

  Constant *                  PrevCallerShuffleMask = NULL;
  SmallVector<Constant *, 32> PrevCallerShuffle = {UndefValue::get(Int32Ty)};

  if (CtxK) {

    for (unsigned I = 0; I < PrevCallerSize - 1; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, I));

    for (int I = PrevCallerSize; I < PrevCallerVecSize; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, PrevCallerSize));

    PrevCallerShuffleMask = ConstantVector::get(PrevCallerShuffle);

  }

#endif

  // other constants we need
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  Value *   PrevCtx = NULL;     // CTX sensitive coverage
  LoadInst *PrevCaller = NULL;  // K-CTX coverage

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
    if (DumpCFG) entry_bb[F.getName()] = &F.getEntryBlock();

    std::list<Value *> todo;
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      // Context sensitive coverage
      if (instrument_ctx && &BB == &F.getEntryBlock()) {

#ifdef HAVE_VECTOR_INTRINSICS
        if (CtxK) {

          PrevCaller = IRB.CreateLoad(AFLPrevCaller);
          PrevCaller->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
          PrevCtx =
              IRB.CreateZExt(IRB.CreateXorReduce(PrevCaller), IRB.getInt32Ty());

        } else

#endif
        {

          // load the context ID of the previous function and write to to a
          // local variable on the stack
          LoadInst *PrevCtxLoad = IRB.CreateLoad(AFLContext);
          PrevCtxLoad->setMetadata(M.getMDKindID("nosanitize"),
                                   MDNode::get(C, None));
          PrevCtx = PrevCtxLoad;

        }

        // does the function have calls? and is any of the calls larger than one
        // basic block?
        for (auto &BB_2 : F) {

          if (has_calls) break;
          for (auto &IN : BB_2) {

            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {

              Function *Callee = callInst->getCalledFunction();
              if (!Callee || Callee->size() < function_minimum_size)
                continue;
              else {

                has_calls = 1;
                break;

              }

            }

          }

        }

        // if yes we store a context ID for this function in the global var
        if (has_calls) {

          Value *NewCtx = ConstantInt::get(Int32Ty, RandBelow(map_size));
#ifdef HAVE_VECTOR_INTRINSICS
          if (CtxK) {

            Value *ShuffledPrevCaller = IRB.CreateShuffleVector(
                PrevCaller, UndefValue::get(PrevCallerTy),
                PrevCallerShuffleMask);
            Value *UpdatedPrevCaller = IRB.CreateInsertElement(
                ShuffledPrevCaller, NewCtx, (uint64_t)0);

            StoreInst *Store =
                IRB.CreateStore(UpdatedPrevCaller, AFLPrevCaller);
            Store->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

          } else

#endif
          {

            if (Ctx) NewCtx = IRB.CreateXor(PrevCtx, NewCtx);
            StoreInst *StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
            StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

          }

        }

      }

      if (RandBelow(100) >= InstRatio) continue;

      /* Make up cur_loc */

      // cur_loc++;
      cur_loc = RandBelow(map_size);
      if (DumpCFG) bb_to_cur_loc[&BB] = cur_loc;
/* There is a problem with Ubuntu 18.04 and llvm 6.0 (see issue #63).
   The inline function successors() is not inlined and also not found at runtime
   :-( As I am unable to detect Ubuntu18.04 heree, the next best thing is to
   disable this optional optimization for LLVM 6.0.0 and Linux */
#if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
      // only instrument if this basic block is the destination of a previous
      // basic block that has multiple successors
      // this gets rid of ~5-10% of instrumentations that are unnecessary
      // result: a little more speed and less map pollution
      int more_than_one = -1;
      // fprintf(stderr, "BB %u: ", cur_loc);
      for (pred_iterator PI = pred_begin(&BB), E = pred_end(&BB); PI != E;
           ++PI) {

        BasicBlock *Pred = *PI;

        int count = 0;
        if (more_than_one == -1) more_than_one = 0;
        // fprintf(stderr, " %p=>", Pred);

        for (succ_iterator SI = succ_begin(Pred), E = succ_end(Pred); SI != E;
             ++SI) {

          BasicBlock *Succ = *SI;

          // if (count > 0)
          //  fprintf(stderr, "|");
          if (Succ != NULL) count++;
          // fprintf(stderr, "%p", Succ);

        }

        if (count > 1) more_than_one = 1;

      }

      // fprintf(stderr, " == %d\n", more_than_one);
      if (F.size() > 1 && more_than_one != 1) {

        // in CTX mode we have to restore the original context for the caller -
        // she might be calling other functions which need the correct CTX
        if (instrument_ctx && has_calls) {

          Instruction *Inst = BB.getTerminator();
          if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

            IRBuilder<> Post_IRB(Inst);

            StoreInst *RestoreCtx;
  #ifdef HAVE_VECTOR_INTRINSICS
            if (CtxK)
              RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
            else
  #endif
              RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
            RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

          }

        }

        continue;

      }

#endif

      ConstantInt *CurLoc;

#ifdef HAVE_VECTOR_INTRINSICS
      if (Ngram)
        CurLoc = ConstantInt::get(IntLocTy, cur_loc);
      else
#endif
        CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocTrans;

#ifdef HAVE_VECTOR_INTRINSICS
      /* "For efficiency, we propose to hash the tuple as a key into the
         hit_count map as (prev_block_trans << 1) ^ curr_block_trans, where
         prev_block_trans = (block_trans_1 ^ ... ^ block_trans_(n-1)" */

      if (Ngram)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXorReduce(PrevLoc), IRB.getInt32Ty());
      else
#endif
        PrevLocTrans = PrevLoc;

      if (instrument_ctx)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, PrevCtx), Int32Ty);
      else
        PrevLocTrans = IRB.CreateZExt(PrevLocTrans, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *MapPtrIdx;
#ifdef HAVE_VECTOR_INTRINSICS
      if (Ngram)
        MapPtrIdx = IRB.CreateGEP(
            MapPtr,
            IRB.CreateZExt(
                IRB.CreateXor(PrevLocTrans, IRB.CreateZExt(CurLoc, Int32Ty)),
                Int32Ty));
      else
#endif
        MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocTrans, CurLoc));

      /* Update bitmap */

      if (ThreadSafe) {  /* Atomic */
         /*
         #if LLVM_VERSION_MAJOR < 9
                 if (neverZero_counters_str !=
                     NULL) {  // with llvm 9 we make this the default as the bug
         in llvm
                              // is then fixed
         #else
                 if (NotZero) {

         #endif
                   // register MapPtrIdx in a todo list
                   todo.push_back(MapPtrIdx);

                 } else {

         */
        IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                            llvm::MaybeAlign(1),
#endif
                            llvm::AtomicOrdering::Monotonic);
        /*

                }

        */

      } else {

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
        if (neverZero_counters_str !=
            NULL) {  // with llvm 9 we make this the default as the bug in llvm
                     // is then fixed
#else
        if (NotZero) {

#endif
          /* hexcoder: Realize a counter that skips zero during overflow.
           * Once this counter reaches its maximum value, it next increments to
           * 1
           *
           * Instead of
           * Counter + 1 -> Counter
           * we inject now this
           * Counter + 1 -> {Counter, OverflowFlag}
           * Counter + OverflowFlag -> Counter
           */

          ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
          auto         cf = IRB.CreateICmpEQ(Incr, Zero);
          auto         carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }                                                  /* non atomic case */

      /* Update prev_loc history vector (by placing cur_loc at the head of the
         vector and shuffle the other elements back by one) */

      StoreInst *Store;

#ifdef HAVE_VECTOR_INTRINSICS
      if (Ngram) {

        Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
            PrevLoc, UndefValue::get(PrevLocTy), PrevLocShuffleMask);
        Value *UpdatedPrevLoc = IRB.CreateInsertElement(
            ShuffledPrevLoc, IRB.CreateLShr(CurLoc, (uint64_t)1), (uint64_t)0);

        Store = IRB.CreateStore(UpdatedPrevLoc, AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      } else

#endif
      {

        Store = IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1),
                                AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }

      // in CTX mode we have to restore the original context for the caller -
      // she might be calling other functions which need the correct CTX.
      // Currently this is only needed for the Ubuntu clang-6.0 bug
      if (instrument_ctx && has_calls) {

        Instruction *Inst = BB.getTerminator();
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

          IRBuilder<> Post_IRB(Inst);

          StoreInst *RestoreCtx;
#ifdef HAVE_VECTOR_INTRINSICS
          if (CtxK)
            RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
          else
#endif
            RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        }

      }

      inst_blocks++;

    }

  }
  if (DumpCFG) {
    int fd;
    if ((fd = open(DumpCFGPath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644)) < 0)
      FATAL("Could not open/create CFG dump file.");
    std::string cfg = "";
    for (auto record = entry_bb.begin(); record != entry_bb.end(); record++) {
      // Dump function BB entry points
      cfg += formatv("$${0}+{1}\n", record->getFirst(), bb_to_cur_loc[record->getSecond()]);
    }
    for (auto record = bb_to_cur_loc.begin(); record != bb_to_cur_loc.end(); record++) {
      // Dump CFG information
      auto current_bb = record->getFirst();
      Function* calling_func = current_bb->getParent();
      if (calling_func) {
        auto function_name = calling_func->getName().str();
        cfg += formatv("%%{0}", function_name);
      }
      else
        cfg += "%%__";
      auto current_cur_loc = record->getSecond();
      cfg += formatv("+{0}\n", current_cur_loc);
      for (auto bb_successor = succ_begin(current_bb);
            bb_successor != succ_end(current_bb); bb_successor++) {
        cfg += formatv("->{0}\n", bb_to_cur_loc[*bb_successor]).str();
      }
    }
    if (Debug) errs() << "CFG: \n" << cfg;
    if (cfg.size() > 0 && write(fd, cfg.c_str(), cfg.length()) <= 0)
      FATAL("Failed to dump CFG.\n");
  }

  /* Say something nice. */

  /*if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %d locations (%s mode, ratio %u%%).", inst_blocks,
          modeline, InstRatio);

    }

  }*/
  
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
