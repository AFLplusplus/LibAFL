/*
   LibAFL - Autotokens LLVM pass
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

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#ifndef O_DSYNC
  #define O_DSYNC O_SYNC
#endif

// The max length of a token
#define MAX_AUTO_EXTRA 32

#define USE_AUTO_EXTRAS 4096
#define MAX_AUTO_EXTRAS (USE_AUTO_EXTRAS * 8)

#include <iostream>

using namespace llvm;

namespace {

#if USE_NEW_PM
class AutoTokensPass : public PassInfoMixin<AutoTokensPass> {
 public:
  AutoTokensPass() {
#else
class AutoTokensPass : public ModulePass {
 public:
  static char ID;

  AutoTokensPass() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
 private:
  std::vector<std::string> dictionary;
};

}  // namespace

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AutoTokensPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
  #if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
  #endif
                ) { MPM.addPass(AutoTokensPass()); });
          }};
}
#else
char AutoTokensPass::ID = 0;
#endif

void dict2file(int fd, uint8_t *mem, uint32_t len) {
  uint32_t i, j, binary = 0;
  char     line[MAX_AUTO_EXTRA * 8], tmp[8];

  strcpy(line, "\"");
  j = 1;
  for (i = 0; i < len; i++) {
    if (isprint(mem[i]) && mem[i] != '\\' && mem[i] != '"') {
      line[j++] = mem[i];

    } else {
      if (i + 1 != len || mem[i] != 0 || binary || len == 4 || len == 8) {
        line[j] = 0;
        sprintf(tmp, "\\x%02x", (uint8_t)mem[i]);
        strcat(line, tmp);
        j = strlen(line);
      }

      binary = 1;
    }
  }

  line[j] = 0;
  strcat(line, "\"\n");
  if (write(fd, line, strlen(line)) <= 0) {
    FATAL("Could not write to the dictionary file");
  }
#ifndef _WIN32
  fsync(fd);
#endif
}

#if USE_NEW_PM
PreservedAnalyses AutoTokensPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool AutoTokensPass::runOnModule(Module &M) {
#endif

  DenseMap<Value *, std::string *> valueMap;
  char                            *ptr;
  int                              fd, found = 0;
  bool                             use_file = true;

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);

  ptr = getenv("AFL_LLVM_DICT2FILE");

  if (!ptr || *ptr != '/') {
    // fprintf(stderr, "AFL_LLVM_DICT2FILE is not set to an absolute path:
    // %s\n", ptr); fprintf(stderr, "Writing tokens into libafl_tokens
    // section\n");

    use_file = false;
  }

  if (use_file) {
#ifndef _WIN32
    if ((fd = open(ptr, O_WRONLY | O_APPEND | O_CREAT | O_DSYNC, 0644)) < 0)
#else
    if ((fd = open(ptr, O_WRONLY | O_APPEND | O_CREAT, 0644)) < 0)
#endif
      FATAL("Could not open/create %s.", ptr);
  }

  /* Instrument all the things! */

  for (auto &F : M) {
    if (isIgnoreFunction(&F)) { continue; }

    /*  Some implementation notes.
     *
     *  We try to handle 3 cases:
     *  - memcmp("foo", arg, 3) <- literal string
     *  - static char globalvar[] = "foo";
     *    memcmp(globalvar, arg, 3) <- global variable
     *  - char localvar[] = "foo";
     *    memcmp(locallvar, arg, 3) <- local variable
     *
     *  The local variable case is the hardest. We can only detect that
     *  case if there is no reassignment or change in the variable.
     *  And it might not work across llvm version.
     *  What we do is hooking the initializer function for local variables
     *  (llvm.memcpy.p0i8.p0i8.i64) and note the string and the assigned
     *  variable. And if that variable is then used in a compare function
     *  we use that noted string.
     *  This seems not to work for tokens that have a size <= 4 :-(
     *
     *  - if the compared length is smaller than the string length we
     *    save the full string. This is likely better for fuzzing but
     *    might be wrong in a few cases depending on optimizers
     *
     *  - not using StringRef because there is a bug in the llvm 11
     *    checkout I am using which sometimes points to wrong strings
     *
     *  Over and out. Took me a full day. damn. mh/vh
     */

    for (auto &BB : F) {
      for (auto &IN : BB) {
        CallInst *callInst = nullptr;
        CmpInst  *cmpInst = nullptr;

        if ((cmpInst = dyn_cast<CmpInst>(&IN))) {
          Value       *op = cmpInst->getOperand(1);
          ConstantInt *ilen = dyn_cast<ConstantInt>(op);

          /* We skip > 64 bit integers. why? first because their value is
             difficult to obtain, and second because clang does not support
             literals > 64 bit (as of llvm 12) */

          if (ilen && ilen->uge(0xffffffffffffffff) == false) {
            uint64_t val2 = 0, val = ilen->getZExtValue();
            uint32_t len = 0;
            if (val > 0x10000 && val < 0xffffffff) { len = 4; }
            if (val > 0x100000001 && val < 0xffffffffffffffff) { len = 8; }

            if (len) {
              auto c = cmpInst->getPredicate();

              switch (c) {
                case CmpInst::FCMP_OGT:  // fall through
                case CmpInst::FCMP_OLE:  // fall through
                case CmpInst::ICMP_SLE:  // fall through
                case CmpInst::ICMP_SGT:

                  // signed comparison and it is a negative constant
                  if ((len == 4 && (val & 80000000)) ||
                      (len == 8 && (val & 8000000000000000))) {
                    if ((val & 0xffff) != 1) { val2 = val - 1; }
                    break;
                  }

                  // fall through

                case CmpInst::FCMP_UGT:  // fall through
                case CmpInst::FCMP_ULE:  // fall through
                case CmpInst::ICMP_UGT:  // fall through
                case CmpInst::ICMP_ULE:
                  if ((val & 0xffff) != 0xfffe) val2 = val + 1;
                  break;

                case CmpInst::FCMP_OLT:  // fall through
                case CmpInst::FCMP_OGE:  // fall through
                case CmpInst::ICMP_SLT:  // fall through
                case CmpInst::ICMP_SGE:

                  // signed comparison and it is a negative constant
                  if ((len == 4 && (val & 80000000)) ||
                      (len == 8 && (val & 8000000000000000))) {
                    if ((val & 0xffff) != 1) val2 = val - 1;
                    break;
                  }

                  // fall through

                case CmpInst::FCMP_ULT:  // fall through
                case CmpInst::FCMP_UGE:  // fall through
                case CmpInst::ICMP_ULT:  // fall through
                case CmpInst::ICMP_UGE:
                  if ((val & 0xffff) != 1) val2 = val - 1;
                  break;

                default:
                  val2 = 0;
              }

              if (use_file) {
                dict2file(fd, (uint8_t *)&val, len);
              } else {
                dictionary.push_back(std::string((char *)&val, len));
              }

              found++;
              if (val2) {
                if (use_file) {
                  dict2file(fd, (uint8_t *)&val2, len);
                } else {
                  dictionary.push_back(std::string((char *)&val2, len));
                }
                found++;
              }
            }
          }
        }

        if ((callInst = dyn_cast<CallInst>(&IN))) {
          bool   isStrcmp = true;
          bool   isMemcmp = true;
          bool   isStrncmp = true;
          bool   isStrcasecmp = true;
          bool   isStrncasecmp = true;
          bool   isIntMemcpy = true;
          bool   isStdString = true;
          bool   addedNull = false;
          size_t optLen = 0;

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          std::string FuncName = Callee->getName().str();
          isStrcmp &= !FuncName.compare("strcmp");
          isMemcmp &=
              (!FuncName.compare("memcmp") || !FuncName.compare("bcmp"));
          isStrncmp &= !FuncName.compare("strncmp");
          isStrcasecmp &= !FuncName.compare("strcasecmp");
          isStrncasecmp &= !FuncName.compare("strncasecmp");
          isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");
          isStdString &= ((FuncName.find("basic_string") != std::string::npos &&
                           FuncName.find("compare") != std::string::npos) ||
                          (FuncName.find("basic_string") != std::string::npos &&
                           FuncName.find("find") != std::string::npos));

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isStdString)
            continue;

          /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
           * prototype */
          FunctionType *FT = Callee->getFunctionType();

          isStrcmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) ==
                  IntegerType::getInt8Ty(M.getContext())->getPointerTo(0);
          isStrcasecmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) ==
                  IntegerType::getInt8Ty(M.getContext())->getPointerTo(0);
          isMemcmp &= FT->getNumParams() == 3 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getParamType(2)->isIntegerTy();
          isStrncmp &=
              FT->getNumParams() == 3 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) ==
                  IntegerType::getInt8Ty(M.getContext())->getPointerTo(0) &&
              FT->getParamType(2)->isIntegerTy();
          isStrncasecmp &=
              FT->getNumParams() == 3 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) ==
                  IntegerType::getInt8Ty(M.getContext())->getPointerTo(0) &&
              FT->getParamType(2)->isIntegerTy();
          isStdString &= FT->getNumParams() >= 2 &&
                         FT->getParamType(0)->isPointerTy() &&
                         FT->getParamType(1)->isPointerTy();

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isStdString)
            continue;

          /* is a str{n,}{case,}cmp/memcmp, check if we have
           * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
           * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
           * memcmp(x, "const", ..) or memcmp("const", x, ..) */
          Value *Str1P = callInst->getArgOperand(0),
                *Str2P = callInst->getArgOperand(1);
          std::string Str1, Str2;
          StringRef   TmpStr;
          bool        HasStr1;
          getConstantStringInfo(Str1P, TmpStr);

          if (TmpStr.empty()) {
            HasStr1 = false;

          } else {
            HasStr1 = true;
            Str1 = TmpStr.str();
          }

          bool HasStr2;
          getConstantStringInfo(Str2P, TmpStr);
          if (TmpStr.empty()) {
            HasStr2 = false;

          } else {
            HasStr2 = true;
            Str2 = TmpStr.str();
          }

          // we handle the 2nd parameter first because of llvm memcpy
          if (!HasStr2) {
            auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
            if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {
              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {
                if (Var->hasInitializer()) {
                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {
                    HasStr2 = true;
                    Str2 = Array->getRawDataValues().str();
                  }
                }
              }
            }
          }

          // for the internal memcpy routine we only care for the second
          // parameter and are not reporting anything.
          if (isIntMemcpy == true) {
            if (HasStr2 == true) {
              Value       *op2 = callInst->getArgOperand(2);
              ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
              if (ilen) {
                uint64_t literalLength = Str2.length();
                uint64_t optLength = ilen->getZExtValue();
                if (literalLength + 1 == optLength) {
                  Str2.append("\0", 1);  // add null byte
                }

                if (optLength > Str2.length()) { optLength = Str2.length(); }
              }

              valueMap[Str1P] = new std::string(Str2);
              continue;
            }

            continue;
          }

          // Neither a literal nor a global variable?
          // maybe it is a local variable that we saved
          if (!HasStr2) {
            std::string *strng = valueMap[Str2P];
            if (strng && !strng->empty()) {
              Str2 = *strng;
              HasStr2 = true;
            }
          }

          if (!HasStr1) {
            auto Ptr = dyn_cast<ConstantExpr>(Str1P);

            if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {
              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {
                if (Var->hasInitializer()) {
                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {
                    HasStr1 = true;
                    Str1 = Array->getRawDataValues().str();
                  }
                }
              }
            }
          }

          // Neither a literal nor a global variable?
          // maybe it is a local variable that we saved
          if (!HasStr1) {
            std::string *strng = valueMap[Str1P];
            if (strng && !strng->empty()) {
              Str1 = *strng;
              HasStr1 = true;
            }
          }

          /* handle cases of one string is const, one string is variable */
          if (!(HasStr1 ^ HasStr2)) continue;

          std::string thestring;

          if (HasStr1)
            thestring = Str1;
          else
            thestring = Str2;

          optLen = thestring.length();

          if (optLen < 2 || (optLen == 2 && !thestring[1])) { continue; }

          if (isMemcmp || isStrncmp || isStrncasecmp) {
            Value       *op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);

            if (!ilen) {
              op2 = callInst->getArgOperand(1);
              ilen = dyn_cast<ConstantInt>(op2);
            }

            if (ilen) {
              uint64_t literalLength = optLen;
              optLen = ilen->getZExtValue();
              if (optLen > thestring.length()) { optLen = thestring.length(); }
              if (optLen < 2) { continue; }
              if (literalLength + 1 == optLen) {  // add null byte
                thestring.append("\0", 1);
                addedNull = true;
              }
            }
          }

          // add null byte if this is a string compare function and a null
          // was not already added
          if (!isMemcmp) {
            if (addedNull == false && thestring[optLen - 1] != '\0') {
              thestring.append("\0", 1);  // add null byte
              optLen++;
            }

            if (!isStdString) {
              // ensure we do not have garbage
              size_t offset = thestring.find('\0', 0);
              if (offset + 1 < optLen) optLen = offset + 1;
              thestring = thestring.substr(0, optLen);
            }
          }

          // we take the longer string, even if the compare was to a
          // shorter part. Note that depending on the optimizer of the
          // compiler this can be wrong, but it is more likely that this
          // is helping the fuzzer
          if (optLen != thestring.length()) optLen = thestring.length();
          if (optLen > MAX_AUTO_EXTRA) optLen = MAX_AUTO_EXTRA;
          if (optLen < 3)  // too short? skip
            continue;

          ptr = (char *)thestring.c_str();

          if (use_file) {
            dict2file(fd, (uint8_t *)ptr, optLen);
          } else {
            dictionary.push_back(thestring.substr(0, optLen));
          }
          found++;
        }
      }
    }
  }

  if (use_file) {
    close(fd);
#if USE_NEW_PM
    auto PA = PreservedAnalyses::all();
    return PA;
#else
    return true;
#endif
  }

  LLVMContext &Ctx = M.getContext();

  if (dictionary.size()) {
    size_t memlen = 0, count = 0, offset = 0;

    // sort and unique the dictionary
    std::sort(dictionary.begin(), dictionary.end());
    auto last = std::unique(dictionary.begin(), dictionary.end());
    dictionary.erase(last, dictionary.end());

    for (auto token : dictionary) {
      memlen += token.length();
      count++;
    }

    if (count) {
      auto ptrhld = std::unique_ptr<char[]>(new char[memlen + count]);

      count = 0;

      for (auto token : dictionary) {
        if (offset + token.length() < 0xfffff0 && count < MAX_AUTO_EXTRAS) {
          // This lenght is guranteed to be < MAX_AUTO_EXTRA
          ptrhld.get()[offset++] = (uint8_t)token.length();
          memcpy(ptrhld.get() + offset, token.c_str(), token.length());
          offset += token.length();
          count++;
        }
      }

      // Type
      ArrayType *arrayTy = ArrayType::get(IntegerType::get(Ctx, 8), offset);
      // The actual dict
      GlobalVariable *dict = new GlobalVariable(
          M, arrayTy, true, GlobalVariable::WeakAnyLinkage,
          ConstantDataArray::get(Ctx,
                                 *(new ArrayRef<char>(ptrhld.get(), offset))),
          "libafl_dictionary_" + M.getName());
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
      dict->setSection("libafl_token");
#elif defined(__APPLE__)
      dict->setSection("__DATA,__libafl_token");
#endif
    }
  }

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}

#if USE_NEW_PM

#else
static void registerAutoTokensPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new AutoTokensPass());
}

static RegisterPass<AutoTokensPass> X("autotokens",
                                      "autotokens instrumentation pass", false,
                                      false);

static RegisterStandardPasses RegisterAutoTokensPass(
    PassManagerBuilder::EP_OptimizerLast, registerAutoTokensPass);

static RegisterStandardPasses RegisterAutoTokensPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAutoTokensPass);
#endif
