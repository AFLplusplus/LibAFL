/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

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
#endif

#include <list>
#include <string>
#include <fstream>

#include "common-llvm.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>

using namespace llvm;
static cl::opt<bool> CmplogExtended("cmplog_instructions_extended",
                                    cl::desc("Uses extended header"),
                                    cl::init(false), cl::NotHidden);
namespace {

#if USE_NEW_PM
class CmpLogInstructions : public PassInfoMixin<CmpLogInstructions> {
 public:
  CmpLogInstructions() {
  }
#else

class CmpLogInstructions : public ModulePass {
 public:
  static char ID;
  CmpLogInstructions() : ModulePass(ID) {
  }
#endif

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {
  #else
  StringRef getPassName() const override {
  #endif
    return "cmplog instructions";
  }
#endif

 private:
  bool hookInstrs(Module &M);
  bool be_quiet = true;
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CmpLogInstructions", "v0.1",
          [](PassBuilder &PB) {
  #if LLVM_VERSION_MAJOR >= 16
    #if LLVM_VERSION_MAJOR >= 20
            PB.registerPipelineStartEPCallback(
    #else
            PB.registerOptimizerEarlyEPCallback(
    #endif
  #else
            PB.registerOptimizerLastEPCallback(
  #endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(CmpLogInstructions());
                });
          }};
}
#else
char CmpLogInstructions::ID = 0;
#endif

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {
  while (first != last) {
    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;
  }

  return last;
}

bool CmpLogInstructions::hookInstrs(Module &M) {
  std::vector<Instruction *> icomps;
  std::vector<SwitchInst *>  switches;
  LLVMContext               &C = M.getContext();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int128Ty = IntegerType::getInt128Ty(C);

  FunctionCallee cmplogHookIns1;
  FunctionCallee cmplogHookIns2;
  FunctionCallee cmplogHookIns4;
  FunctionCallee cmplogHookIns8;
#ifndef _WIN32
  FunctionCallee cmplogHookIns16;
  FunctionCallee cmplogHookInsN;
#endif
  if (CmplogExtended) {
    cmplogHookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1_extended",
                                           VoidTy, Int8Ty, Int8Ty, Int8Ty);
  } else {
    cmplogHookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty,
                                           Int8Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2_extended",
                                           VoidTy, Int16Ty, Int16Ty, Int8Ty);
  } else {
    cmplogHookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy,
                                           Int16Ty, Int16Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4_extended",
                                           VoidTy, Int32Ty, Int32Ty, Int8Ty);
  } else {
    cmplogHookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy,
                                           Int32Ty, Int32Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8_extended",
                                           VoidTy, Int64Ty, Int64Ty, Int8Ty);
  } else {
    cmplogHookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy,
                                           Int64Ty, Int64Ty, Int8Ty);
  }

#ifndef _WIN32
  if (CmplogExtended) {
    cmplogHookIns16 = M.getOrInsertFunction("__cmplog_ins_hook16_extended",
                                            VoidTy, Int128Ty, Int128Ty, Int8Ty);
  } else {
    cmplogHookIns16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy,
                                            Int128Ty, Int128Ty, Int8Ty);
  }

  if (CmplogExtended) {
    cmplogHookInsN = M.getOrInsertFunction("__cmplog_ins_hookN_extended",
                                           VoidTy, Int128Ty, Int128Ty, Int8Ty);
  } else {
    cmplogHookInsN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy,
                                           Int128Ty, Int128Ty, Int8Ty);
  }
#endif

  Constant *Null = Constant::getNullValue(PointerType::get(Int8Ty, 0));

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {
    if (isIgnoreFunction(&F)) { continue; }

    for (auto &BB : F) {
      for (auto &IN : BB) {
        CmpInst *selectcmpInst = nullptr;
        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {
          icomps.push_back(selectcmpInst);
        }
      }
    }

    for (auto &BB : F) {
      SwitchInst *switchInst = nullptr;
      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {
        if (switchInst->getNumCases() > 1) { switches.push_back(switchInst); }
      }
    }
  }

  switches.erase(Unique(switches.begin(), switches.end()), switches.end());
  if (icomps.size()) {
    // if (!be_quiet) errs() << "Hooking " << icomps.size() <<
    //                          " cmp instructions\n";

    for (auto &selectcmpInst : icomps) {
      IRBuilder<> IRB(selectcmpInst->getParent());
      IRB.SetInsertPoint(selectcmpInst);

      Value *op0 = selectcmpInst->getOperand(0);
      Value *op1 = selectcmpInst->getOperand(1);
      Value *op0_saved = op0, *op1_saved = op1;
      auto   ty0 = op0->getType();
      auto   ty1 = op1->getType();

      IntegerType *intTyOp0 = NULL;
      IntegerType *intTyOp1 = NULL;
      unsigned     max_size = 0, cast_size = 0;
      unsigned     attr = 0, vector_cnt = 0, is_fp = 0;
      CmpInst     *cmpInst = dyn_cast<CmpInst>(selectcmpInst);

      if (!cmpInst) { continue; }

      switch (cmpInst->getPredicate()) {
        case CmpInst::ICMP_NE:
        case CmpInst::FCMP_UNE:
        case CmpInst::FCMP_ONE:
          break;
        case CmpInst::ICMP_EQ:
        case CmpInst::FCMP_UEQ:
        case CmpInst::FCMP_OEQ:
          attr += 1;
          break;
        case CmpInst::ICMP_UGT:
        case CmpInst::ICMP_SGT:
        case CmpInst::FCMP_OGT:
        case CmpInst::FCMP_UGT:
          attr += 2;
          break;
        case CmpInst::ICMP_UGE:
        case CmpInst::ICMP_SGE:
        case CmpInst::FCMP_OGE:
        case CmpInst::FCMP_UGE:
          attr += 3;
          break;
        case CmpInst::ICMP_ULT:
        case CmpInst::ICMP_SLT:
        case CmpInst::FCMP_OLT:
        case CmpInst::FCMP_ULT:
          attr += 4;
          break;
        case CmpInst::ICMP_ULE:
        case CmpInst::ICMP_SLE:
        case CmpInst::FCMP_OLE:
        case CmpInst::FCMP_ULE:
          attr += 5;
          break;
        default:
          break;
      }

      if (selectcmpInst->getOpcode() == Instruction::FCmp) {
        if (ty0->isVectorTy()) {
          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {
            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;
          }

#if (LLVM_VERSION_MAJOR >= 12)
          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty0 = tt->getElementType();
#endif
        }

        if (ty0->isHalfTy()
#if LLVM_VERSION_MAJOR >= 11
            || ty0->isBFloatTy()
#endif
        )
          max_size = 16;
        else if (ty0->isFloatTy())
          max_size = 32;
        else if (ty0->isDoubleTy())
          max_size = 64;
        else if (ty0->isX86_FP80Ty())
          max_size = 80;
        else if (ty0->isFP128Ty() || ty0->isPPC_FP128Ty())
          max_size = 128;
#if (LLVM_VERSION_MAJOR >= 12)
        else if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet)
          fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u!\n",
                  ty0->getTypeID());
#endif

        attr += 8;
        is_fp = 1;
        // fprintf(stderr, "HAVE FP %u!\n", vector_cnt);

      } else {
        if (ty0->isVectorTy()) {
#if (LLVM_VERSION_MAJOR >= 12)
          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {
            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;
          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty1 = ty0 = tt->getElementType();
#endif
        }

        intTyOp0 = dyn_cast<IntegerType>(ty0);
        intTyOp1 = dyn_cast<IntegerType>(ty1);

        if (intTyOp0 && intTyOp1) {
          max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                         ? intTyOp0->getBitWidth()
                         : intTyOp1->getBitWidth();

        } else {
#if (LLVM_VERSION_MAJOR >= 12)
          if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet) {
            fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u\n",
                    ty0->getTypeID());
          }

#endif
        }
      }

      if (!max_size || max_size < 16) {
        // fprintf(stderr, "too small\n");
        continue;
      }

      if (max_size % 8) { max_size = (((max_size / 8) + 1) * 8); }

      if (max_size > 128) {
        if (!be_quiet) {
          fprintf(stderr,
                  "Cannot handle this compare bit size: %u (truncating)\n",
                  max_size);
        }

        max_size = 128;
      }

      // do we need to cast?
      switch (max_size) {
        case 8:
        case 16:
        case 32:
        case 64:
        case 128:
          cast_size = max_size;
          break;
        default:
          cast_size = 128;
      }

      // XXX FIXME BUG TODO
      if (is_fp && vector_cnt) { continue; }

      uint64_t cur = 0, last_val0 = 0, last_val1 = 0, cur_val;

      while (1) {
        std::vector<Value *> args;
        bool                 skip = false;

        if (vector_cnt) {
          op0 = IRB.CreateExtractElement(op0_saved, cur);
          op1 = IRB.CreateExtractElement(op1_saved, cur);
          /*
          std::string errMsg;
          raw_string_ostream os(errMsg);
          op0_saved->print(os);
          fprintf(stderr, "X: %s\n", os.str().c_str());
          */
          if (is_fp) {
            /*
                        ConstantFP *i0 = dyn_cast<ConstantFP>(op0);
                        ConstantFP *i1 = dyn_cast<ConstantFP>(op1);
                        // BUG FIXME TODO: this is null ... but why?
                        // fprintf(stderr, "%p %p\n", i0, i1);
                        if (i0) {

                          cur_val = (uint64_t)i0->getValue().convertToDouble();
                          if (last_val0 && last_val0 == cur_val) { skip = true;

               } last_val0 = cur_val;

                        }

                        if (i1) {

                          cur_val = (uint64_t)i1->getValue().convertToDouble();
                          if (last_val1 && last_val1 == cur_val) { skip = true;

               } last_val1 = cur_val;

                        }

            */

          } else {
            ConstantInt *i0 = dyn_cast<ConstantInt>(op0);
            ConstantInt *i1 = dyn_cast<ConstantInt>(op1);
            if (i0 && i0->uge(0xffffffffffffffff) == false) {
              cur_val = i0->getZExtValue();
              if (last_val0 && last_val0 == cur_val) { skip = true; }
              last_val0 = cur_val;
            }

            if (i1 && i1->uge(0xffffffffffffffff) == false) {
              cur_val = i1->getZExtValue();
              if (last_val1 && last_val1 == cur_val) { skip = true; }
              last_val1 = cur_val;
            }
          }
        }

        if (!skip) {
          // errs() << "[CMPLOG] cmp  " << *cmpInst << "(in function " <<
          // cmpInst->getFunction()->getName() << ")\n";

          // first bitcast to integer type of the same bitsize as the original
          // type (this is a nop, if already integer)
          Value *op0_i = IRB.CreateBitCast(
              op0, IntegerType::get(C, ty0->getPrimitiveSizeInBits()));
          // then create a int cast, which does zext, trunc or bitcast. In our
          // case usually zext to the next larger supported type (this is a nop
          // if already the right type)
          Value *V0 =
              IRB.CreateIntCast(op0_i, IntegerType::get(C, cast_size), false);
          args.push_back(V0);
          Value *op1_i = IRB.CreateBitCast(
              op1, IntegerType::get(C, ty1->getPrimitiveSizeInBits()));
          Value *V1 =
              IRB.CreateIntCast(op1_i, IntegerType::get(C, cast_size), false);
          args.push_back(V1);

          // errs() << "[CMPLOG] casted parameters:\n0: " << *V0 << "\n1: " <<
          // *V1
          // << "\n";

          if (CmplogExtended) {
            // Only do this when using extended header
            ConstantInt *attribute = ConstantInt::get(Int8Ty, attr);
            args.push_back(attribute);
          }
#ifndef _WIN32
          if (cast_size != max_size) {
            ConstantInt *bitsize = ConstantInt::get(Int8Ty, (max_size / 8) - 1);
            args.push_back(bitsize);
          }
#endif

          // fprintf(stderr, "_ExtInt(%u) castTo %u with attr %u didcast %u\n",
          //         max_size, cast_size, attr);

          switch (cast_size) {
            case 8:
              IRB.CreateCall(cmplogHookIns1, args);
              break;
            case 16:
              IRB.CreateCall(cmplogHookIns2, args);
              break;
            case 32:
              IRB.CreateCall(cmplogHookIns4, args);
              break;
            case 64:
              IRB.CreateCall(cmplogHookIns8, args);
              break;
#ifndef _WIN32
            case 128:
              if (max_size == 128) {
                IRB.CreateCall(cmplogHookIns16, args);

              } else {
                IRB.CreateCall(cmplogHookInsN, args);
              }

              break;
#endif
          }
        }

        /* else fprintf(stderr, "skipped\n"); */

        ++cur;
        if (cur >= vector_cnt) { break; }
      }
    }
  }

  if (switches.size()) {
    for (auto &SI : switches) {
      Value        *Val = SI->getCondition();
      unsigned int  max_size = Val->getType()->getIntegerBitWidth();
      unsigned int  cast_size;
      unsigned char do_cast = 0;

      if (!SI->getNumCases() || max_size < 16) {
        // skipping trivial switch
        continue;
      }

      if (max_size % 8) {
        max_size = (((max_size / 8) + 1) * 8);
        do_cast = 1;
      }

      if (max_size > 128) {
        // can't handle this

        max_size = 128;
        do_cast = 1;
      }

      IRBuilder<> IRB(SI->getParent());
      IRB.SetInsertPoint(SI);

      switch (max_size) {
        case 8:
        case 16:
        case 32:
        case 64:
        case 128:
          cast_size = max_size;
          break;
        default:
          cast_size = 128;
          do_cast = 1;
      }

      // The predicate of the switch clause
      Value *CompareTo = Val;
      if (do_cast) {
        CompareTo =
            IRB.CreateIntCast(CompareTo, IntegerType::get(C, cast_size), false);
      }

      for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
           ++i) {
        // Who uses LLVM Major < 5?? :p
        ConstantInt *cint = i->getCaseValue();

        if (cint) {
          std::vector<Value *> args;
          args.push_back(CompareTo);

          Value *new_param = cint;
          if (do_cast) {
            new_param =
                IRB.CreateIntCast(cint, IntegerType::get(C, cast_size), false);
          }

          if (new_param) {
            args.push_back(new_param);
            if (CmplogExtended) {
              ConstantInt *attribute = ConstantInt::get(Int8Ty, 1);
              args.push_back(attribute);
            }
            if (cast_size != max_size) {
              // not 8, 16, 32, 64, 128.
              ConstantInt *bitsize =
                  ConstantInt::get(Int8Ty, (max_size / 8) - 1);
              args.push_back(bitsize);  // we have the arg for size in hookinsN
            }

            switch (cast_size) {
              case 8:
                IRB.CreateCall(cmplogHookIns1, args);
                break;
              case 16:
                IRB.CreateCall(cmplogHookIns2, args);
                break;
              case 32:
                IRB.CreateCall(cmplogHookIns4, args);
                break;
              case 64:
                IRB.CreateCall(cmplogHookIns8, args);
                break;
              case 128:
#ifdef WORD_SIZE_64
                if (max_size == 128) {
                  IRB.CreateCall(cmplogHookIns16, args);

                } else {
                  IRB.CreateCall(cmplogHookInsN, args);
                }

#endif
                break;
              default:
                break;
            }
          }
        }
      }
    }
  }
  return true;
}

#if USE_NEW_PM
PreservedAnalyses CmpLogInstructions::run(Module                &M,
                                          ModuleAnalysisManager &MAM) {
#else
bool CmpLogInstructions::runOnModule(Module &M) {
#endif
  hookInstrs(M);

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
#endif
  verifyModule(M);

#if USE_NEW_PM
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM
#else
static void registerCmpLogInstructionsPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {
  auto p = new CmpLogInstructions();
  PM.add(p);
}

static RegisterStandardPasses RegisterCmpLogInstructionsPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogInstructionsPass);

static RegisterStandardPasses RegisterCmpLogInstructionsPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogInstructionsPass);

static RegisterStandardPasses RegisterCmpLogInstructionsPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogInstructionsPass);

#endif
