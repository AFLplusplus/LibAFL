/*
   LibAFL - Profiling LLVM pass
   --------------------------------------------------

   Written by Dongjia Zhang <toka@aflplus.plus>

   Copyright 2022-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

// This llvm pass is for conducting static analysis.

#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <sys/time.h>
  #include <unistd.h>
#else
  #include <io.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <list>
#include <set>
#include <string>

// LLVM Includes

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IRBuilder.h"
#if USE_NEW_PM
  #include "llvm/IR/PassManager.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/Passes/PassPlugin.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
#endif
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"

// Other includes
#include <cmath>
#include <algorithm>
#include <iostream>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <filesystem>

using namespace llvm;

namespace {

#if USE_NEW_PM
class AnalysisPass : public PassInfoMixin<AnalysisPass> {
 public:
  AnalysisPass() {
#else
class AnalysisPass : public ModulePass {
 public:
  static char ID;

  AnalysisPass() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  DenseMap<BasicBlock *, uint32_t>               bb_to_cur_loc;
  DenseMap<StringRef, BasicBlock *>              entry_bb;
  DenseMap<BasicBlock *, std::vector<StringRef>> calls_in_bb;
  // DenseMap<StringRef, std::unordered_map<int, int>> structDesc;
  // The type name is not in the memory, so create std::strign impromptu

 private:
  uint32_t travereScope(DIScope *bottom) {
    uint32_t level = 0;
    for (auto scope = bottom; !isa<DISubprogram>(scope);
         scope = scope->getScope()) {
      level += 1;
    }

    return level;
  }

  std::string typeWriter(Type *typ) {
    // Because there's no string object for the type in the memory
    // I have to build the string myself
    std::string              type_str;
    llvm::raw_string_ostream rso(type_str);
    typ->print(rso);
    return rso.str();
  }

  bool isMemCmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isMemcmp = (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
                     !FuncName.compare("CRYPTO_memcmp") ||
                     !FuncName.compare("OPENSSL_memcmp") ||
                     !FuncName.compare("memcmp_const_time") ||
                     !FuncName.compare("memcmpct"));
    isMemcmp &= FT->getNumParams() == 3 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0)->isPointerTy() &&
                FT->getParamType(1)->isPointerTy() &&
                FT->getParamType(2)->isIntegerTy();
    return isMemcmp;
  }

  bool isStrcmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isStrcmp =
        (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
         !FuncName.compare("xmlStrEqual") || !FuncName.compare("g_strcmp0") ||
         !FuncName.compare("curl_strequal") ||
         !FuncName.compare("strcsequal") || !FuncName.compare("strcasecmp") ||
         !FuncName.compare("stricmp") || !FuncName.compare("ap_cstr_casecmp") ||
         !FuncName.compare("OPENSSL_strcasecmp") ||
         !FuncName.compare("xmlStrcasecmp") ||
         !FuncName.compare("g_strcasecmp") ||
         !FuncName.compare("g_ascii_strcasecmp") ||
         !FuncName.compare("Curl_strcasecompare") ||
         !FuncName.compare("Curl_safe_strcasecompare") ||
         !FuncName.compare("cmsstrcasecmp") || !FuncName.compare("strstr") ||
         !FuncName.compare("g_strstr_len") ||
         !FuncName.compare("ap_strcasestr") || !FuncName.compare("xmlStrstr") ||
         !FuncName.compare("xmlStrcasestr") ||
         !FuncName.compare("g_str_has_prefix") ||
         !FuncName.compare("g_str_has_suffix"));
    isStrcmp &= FT->getNumParams() == 2 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0) == FT->getParamType(1) &&
                FT->getParamType(0) ==
                    IntegerType::getInt8Ty(M.getContext())->getPointerTo(0);
    return isStrcmp;
  }

  bool isStrncmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isStrncmp =
        (!FuncName.compare("strncmp") || !FuncName.compare("xmlStrncmp") ||
         !FuncName.compare("curl_strnequal") ||
         !FuncName.compare("strncasecmp") || !FuncName.compare("strnicmp") ||
         !FuncName.compare("ap_cstr_casecmpn") ||
         !FuncName.compare("OPENSSL_strncasecmp") ||
         !FuncName.compare("xmlStrncasecmp") ||
         !FuncName.compare("g_ascii_strncasecmp") ||
         !FuncName.compare("Curl_strncasecompare") ||
         !FuncName.compare("g_strncasecmp"));
    isStrncmp &= FT->getNumParams() == 3 &&
                 FT->getReturnType()->isIntegerTy(32) &&
                 FT->getParamType(0) == FT->getParamType(1) &&
                 FT->getParamType(0) ==
                     IntegerType::getInt8Ty(M.getContext())->getPointerTo(0) &&
                 FT->getParamType(2)->isIntegerTy();
    return isStrncmp;
  }

  bool isGccStdStringStdString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();
    bool isGccStdStringStdString =
        Callee->getName().find("__is_charIT_EE7__value") != std::string::npos &&
        Callee->getName().find("St7__cxx1112basic_stringIS2_St11char_traits") !=
            std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0) == FT->getParamType(1) &&
        FT->getParamType(0)->isPointerTy();
    return isGccStdStringStdString;
  }

  bool isGccStdStringCString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isGccStdStringCString =
        Callee->getName().find(
            "St7__cxx1112basic_stringIcSt11char_"
            "traitsIcESaIcEE7compareEPK") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();
    return isGccStdStringCString;
  }

  bool isLlvmStdStringStdString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isLlvmStdStringStdString =
        Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
        Callee->getName().find("_12basic_stringI") != std::string::npos &&
        Callee->getName().find("_11char_traits") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();
    return isLlvmStdStringStdString;
  }

  bool isLlvmStdStringCString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isLlvmStdStringCString =
        Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
        Callee->getName().find("_12basic_stringI") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();

    return isLlvmStdStringCString;
  }

  bool isLLVMIntrinsicFn(StringRef &n) {
    // Not interested in these LLVM's functions
    if (n.starts_with("llvm.")) {
      return true;
    } else {
      return false;
    }
  }

  bool isMemorySensitiveFn(StringRef &n) {
    if (n.equals("write") || n.equals("read") || n.equals("fgets") ||
        n.equals("memcmp") || n.equals("memcpy") || n.equals("mempcpy") ||
        n.equals("memmove") || n.equals("memset") || n.equals("memchr") ||
        n.equals("memrchr") || n.equals("memmem") || n.equals("bzero") ||
        n.equals("explicit_bzero") || n.equals("bcmp") || n.equals("strchr") ||
        n.equals("strrchr") || n.equals("strcasecmp") || n.equals("strncat") ||
        n.equals("strerror") || n.equals("strncasecmp") || n.equals("strcat") ||
        n.equals("strcmp") || n.equals("strspn") || n.equals("strncmp") ||
        n.equals("strcpy") || n.equals("strncpy") || n.equals("strcoll") ||
        n.equals("stpcpy") || n.equals("strdup") || n.equals("strlen") ||
        n.equals("strxfrm") || n.equals("strtok") || n.equals("strnlen") ||
        n.equals("strstr") || n.equals("strcasestr") || n.equals("strscpn") ||
        n.equals("strpbrk") || n.equals("atoi") || n.equals("atol") ||
        n.equals("atoll") || n.equals("wcslen") || n.equals("wcscpy") ||
        n.equals("wcscmp")) {
      return true;
    } else {
      return false;
    }
  }

  bool isMallocFn(StringRef &n) {
    if (n.equals("malloc") || n.equals("calloc") || n.equals("realloc") ||
        n.equals("reallocarray") || n.equals("memalign") ||
        n.equals("__libc_memalign") || n.equals("aligned_alloc") ||
        n.equals("posix_memalign") || n.equals("valloc") ||
        n.equals("pvalloc") || n.equals("mmap")) {
      return true;
    } else {
      return false;
    }
  }

  bool isFreeFn(StringRef &n) {
    if (n.equals("free") || n.equals("cfree") || n.equals("munmap")) {
      return true;
    } else {
      return false;
    }
  }

  bool isCppNewFn(StringRef &n) {
    // operator new[](unsigned long)
    // operator new[](unsigned long, std::nothrow_t const&)
    // operator new[](unsigned long, std::align_val_t)
    // operator new[](unsigned long, std::align_val_t, std::nothrow_t const&)
    // operator new(unsigned long)
    // operator new(unsigned long, std::nothrow_t const&)
    // operator new(unsigned long, std::align_val_t)
    // operator new(unsigned long, std::align_val_t, std::nothrow_t const&)

    if (n.equals("_Znam") || n.equals("_ZnamRKSt9nothrow_t") ||
        n.equals("_ZnamSt11align_val_t") ||
        n.equals("_ZnamSt11align_val_tRKSt9nothrow_t") || n.equals("_Znwm") ||
        n.equals("_ZnwmRKSt9nothrow_t") || n.equals("_ZnwmSt11align_val_t") ||
        n.equals("_ZnwmSt11align_val_tRKSt9nothrow_t")) {
      return true;
    } else {
      return false;
    }
  }

  bool isCppDelete(StringRef &n) {
    // operator delete[](void*)
    // operator delete[](void*, unsigned long)
    // operator delete[](void*, unsigned long, std::align_val_t)
    // operator delete[](void*, std::nothrow_t const&)
    // operator delete[](void*, std::align_val_t)
    // operator delete[](void*, std::align_val_t, std::nothrow_t const&)
    // operator delete(void*)
    // operator delete(void*, unsigned long)
    // operator delete(void*, unsigned long, std::align_val_t)
    // operator delete(void*, std::nothrow_t const&)
    // operator delete(void*, std::align_val_t)
    // operator delete(void*, std::align_val_t, std::nothrow_t const&)

    if (n.equals("_ZdaPv") || n.equals("_ZdaPvm") ||
        n.equals("_ZdaPvmSt11align_val_t") ||
        n.equals("_ZdaPvRKSt9nothrow_t") || n.equals("_ZdaPvSt11align_val_t") ||
        n.equals("_ZdaPvSt11align_val_tRKSt9nothrow_t") || n.equals("_ZdlPv") ||
        n.equals("_ZdlPvm") || n.equals("_ZdlPvmSt11align_val_t") ||
        n.equals("_ZdlPvRKSt9nothrow_t") || n.equals("_ZdlPvSt11align_val_t") ||
        n.equals("_ZdlPvSt11align_val_tRKSt9nothrow_t")

    ) {
      return true;
    } else {
      return false;
    }
  }
};

}  // namespace

inline bool file_exist(const std::string &name) {
  std::ifstream f(name.c_str());
  return f.good();
}

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AnalysisPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(AnalysisPass());
                });
          }};
}
#else
char AnalysisPass::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses AnalysisPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool AnalysisPass::runOnModule(Module &M) {

#endif

  std::string            relFilename = M.getSourceFileName();
  llvm::SmallString<128> FilenameVec = StringRef(relFilename);
  llvm::SmallString<128> RealPath;
  llvm::sys::fs::real_path(FilenameVec, RealPath);
  std::filesystem::path fp{std::string(RealPath)};
  std::string           genericFilePath = fp.generic_string();

  std::replace(genericFilePath.begin(), genericFilePath.end(), '/', '#');

  /*
    std::ifstream ifs;
    ifs.open("/out/whitelist.txt");

    if (ifs.fail()) { abort(); }
    std::string              srcfile;
    std::vector<std::string> srcList;
    while (ifs >> srcfile) {
      srcList.push_back(srcfile);
    }

    bool run = false;

    for (std::string S : srcList) {
      if (S == Filename) {
        outs() << "Accept " << Filename << "\n";
        run = true;
      }
    }
  */
  bool run = true;

  std::string output_dir;
  const char *path = std::getenv("ANALYSIS_OUTPUT");
  if (path != nullptr) {
    output_dir = path;
    if (std::filesystem::exists(output_dir) &&
        std::filesystem::is_directory(output_dir)) {
      // good
    } else {
      std::cerr << "Output path is empty!" << std::endl;
    }
    // Use the output_dir string here
  } else {
    std::cerr << "Output path not set!" << std::endl;
  }
  bool done_already =
      file_exist(output_dir + std::string("/") + genericFilePath + ".json");
  if (done_already) {
    run = false;
  } else {
    std::ofstream out_lock(output_dir + std::string("/") + genericFilePath +
                           ".json");
  }

  if (run) {
    outs() << "Analysis on " + genericFilePath << "\n";
    LLVMContext   &Ctx = M.getContext();
    auto           moduleName = M.getName().str();
    nlohmann::json res;

    for (auto &F : M) {
      if (F.isDeclaration()) { continue; }

      DenseMap<StringRef, u_int32_t>            APIcalls;
      DenseMap<StringRef, uint32_t>             heapAPIs;
      DenseMap<StringRef, uint32_t>             memoryAPIs;
      std::unordered_map<uint32_t, uint32_t>    nestedLevel;
      std::unordered_map<uint32_t, uint32_t>    cmpGlobals;
      std::unordered_map<uint32_t, uint32_t>    cmpNonZeros;
      DenseMap<StringRef, uint32_t>             structWrites;
      std::unordered_map<std::string, uint32_t> structArgs;
      std::unordered_map<std::string, uint32_t> cmpTypes;
      std::unordered_map<std::string, uint32_t> callArgTypes;
      std::unordered_map<std::string, uint32_t> storeTypes;
      std::unordered_map<std::string, uint32_t> loadTypes;
      std::unordered_map<std::string, uint32_t> allocaTypes;
      std::unordered_map<std::string, uint32_t> cmpComplexity;

      unsigned bb_cnt = 0;
      unsigned inst_cnt = 0;
      unsigned edges_cnt = 0;

      unsigned call_cnt = 0;
      unsigned cmp_cnt = 0;
      unsigned load_cnt = 0;
      unsigned store_cnt = 0;
      unsigned alloca_cnt = 0;
      unsigned branch_cnt = 0;
      unsigned binary_op_cnt = 0;

      entry_bb[F.getName()] = &F.getEntryBlock();
      // now we get the sha256sum for this function. (mangled function name
      // should be unique else it will result in linker error) by this we make a
      // map (<fn name> |-> <analysis data>)
      std::size_t hashed = std::hash<std::string>{}(F.getName().str());
      // cast again as string, it's json, key has to be a string
      std::string function_id = std::to_string(hashed);

      for (auto &BB : F) {
        bb_to_cur_loc[&BB] = bb_cnt;
        bb_cnt++;
        for (auto &IN : BB) {
          /// Check data types

          auto meta = IN.getMetadata(0);
          if (meta) {
            DILocation *diloc = nullptr;
            if ((diloc = dyn_cast<DILocation>(meta))) {
              auto     scope = diloc->getScope();
              uint32_t nested_level = travereScope(scope);
              nestedLevel[nested_level] += 1;
            }
          }

          CallBase       *callBase = nullptr;
          CmpInst        *cmpInst = nullptr;
          LoadInst       *loadInst = nullptr;
          StoreInst      *storeInst = nullptr;
          AllocaInst     *allocaInst = nullptr;
          BranchInst     *branchInst = nullptr;
          BinaryOperator *binaryOp = nullptr;

          if ((binaryOp = dyn_cast<BinaryOperator>(&IN))) {
            binary_op_cnt++;
          } else if ((branchInst = dyn_cast<BranchInst>(&IN))) {
            branch_cnt++;
          } else if ((callBase = dyn_cast<CallBase>(&IN))) {
            // What type of call is this?
            auto F = callBase->getCalledFunction();
            if (F) {
              StringRef name = F->getName();
              if (isLLVMIntrinsicFn(name)) {
                // just ignore
                continue;
              }
              APIcalls[name]++;
              call_cnt++;

              calls_in_bb[&BB].push_back(name);
              // Check memory related calls
              if (isMallocFn(name)) {
                heapAPIs["malloc"]++;
              } else if (isFreeFn(name)) {
                heapAPIs["free"]++;
              } else if (isCppNewFn(name)) {
                heapAPIs["new"]++;
              } else if (isCppDelete(name)) {
                heapAPIs["delete"]++;
              }

              if (isMemorySensitiveFn(name)) { memoryAPIs[name]++; }

              if (isMemCmp(M, callBase)) {
                cmpComplexity["mem cmp"]++;
              } else if (isStrcmp(M, callBase) || isStrncmp(M, callBase) ||
                         isGccStdStringCString(M, callBase) ||
                         isGccStdStringStdString(M, callBase) ||
                         isLlvmStdStringCString(M, callBase) ||
                         isLlvmStdStringStdString(M, callBase)) {
                cmpComplexity["str cmp"]++;
              }

              for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++) {
                auto        arg_ty = arg->getType();
                std::string type_str = typeWriter(arg_ty);
                callArgTypes[type_str]++;
              }
            }
          } else if ((cmpInst = dyn_cast<CmpInst>(&IN))) {
            FCmpInst *fcmp = nullptr;
            ICmpInst *icmp = nullptr;

            if ((icmp = dyn_cast<ICmpInst>(cmpInst))) {
              cmpComplexity["int cmp"]++;
            } else if ((fcmp = dyn_cast<FCmpInst>(cmpInst))) {
              cmpComplexity["float cmp"]++;
            }
            auto typ = cmpInst->getOperand(0)->getType();

            auto     op0 = cmpInst->getOperand(0);
            auto     op1 = cmpInst->getOperand(1);
            uint32_t num_constants = 0;
            uint32_t non_zero_constants = 0;

            Constant *c1 = nullptr;
            Constant *c2 = nullptr;

            if ((c1 = dyn_cast<Constant>(op0))) {
              if (!c1->isZeroValue()) { non_zero_constants++; }
              num_constants++;
            }

            if ((c2 = dyn_cast<Constant>(op1))) {
              if (c2->isZeroValue()) { non_zero_constants++; }
              num_constants++;
            }

            cmpGlobals[num_constants]++;
            cmpNonZeros[num_constants]++;
            cmpTypes[typeWriter(typ)]++;
            cmp_cnt++;
          } else if ((loadInst = dyn_cast<LoadInst>(&IN))) {
            auto typ = loadInst->getType();
            loadTypes[typeWriter(typ)]++;
            load_cnt++;
          } else if ((storeInst = dyn_cast<StoreInst>(&IN))) {
            auto typ = storeInst->getValueOperand()->getType();
            storeTypes[typeWriter(typ)]++;
            // Here check writes into structs
            // check where storeInst stores into
            auto               op = storeInst->getPointerOperand();
            GetElementPtrInst *gep = nullptr;
            if ((gep = dyn_cast<GetElementPtrInst>(op))) {
              // If this is a gep?
              auto typ = gep->getSourceElementType();

              if (typ->isStructTy()) { structWrites[typ->getStructName()]++; }
            }

            store_cnt++;
          } else if ((allocaInst = dyn_cast<AllocaInst>(&IN))) {
            auto typ = allocaInst->getAllocatedType();
            allocaTypes[typeWriter(typ)]++;
            alloca_cnt++;
          }

          inst_cnt++;
        }

        auto term = BB.getTerminator();
        edges_cnt += term->getNumSuccessors();

        // Dump everything in this Fn
      }

      std::string fnname = std::string(F.getName());

      res[function_id]["name"] = fnname;

      if (bb_cnt) { res[function_id]["# BBs"] = bb_cnt; }

      if (inst_cnt) { res[function_id]["# insts"] = inst_cnt; }

      if (edges_cnt) { res[function_id]["# edges"] = edges_cnt; }

      if (binary_op_cnt) { res[function_id]["# binaryOp"] = binary_op_cnt; }

      if (call_cnt) { res[function_id]["# call"] = call_cnt; }

      if (cmp_cnt) { res[function_id]["# cmp"] = cmp_cnt; }

      if (load_cnt) { res[function_id]["# load"] = load_cnt; }

      if (store_cnt) { res[function_id]["# store"] = store_cnt; }

      if (alloca_cnt) { res[function_id]["# alloca"] = alloca_cnt; }

      if (branch_cnt) { res[function_id]["# branch"] = branch_cnt; }

      res[function_id]["ABC metric"] =
          sqrt(alloca_cnt * alloca_cnt + branch_cnt * branch_cnt +
               call_cnt * call_cnt);
      res[function_id]["cyclomatic"] = edges_cnt - bb_cnt + 2;

      // outs() << "APIs:\n";
      for (auto record = APIcalls.begin(); record != APIcalls.end(); record++) {
        auto key = record->getFirst();
        if (!isLLVMIntrinsicFn(key)) {
          res[function_id]["AP"][std::string(key)] = APIcalls[key];
          // outs() << key << " " << APIcalls[key] << "\n";
        }
      }
      // outs() << "\n";

      // outs() << "memoryAPIs:\n";
      for (auto record = heapAPIs.begin(); record != heapAPIs.end(); record++) {
        auto key = record->getFirst();
        res[function_id]["h AP"][std::string(key)] = heapAPIs[key];
        // outs() << key << " " << heapAPIs[key] << "\n";
      }
      // outs() << "\n";

      for (auto record = memoryAPIs.begin(); record != memoryAPIs.end();
           record++) {
        auto key = record->getFirst();
        res[function_id]["m AP"][std::string(key)] = memoryAPIs[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = nestedLevel.begin(); record != nestedLevel.end();
           record++) {
        auto key = record->first;
        res[function_id]["ne lv"][std::to_string(key)] = nestedLevel[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = cmpGlobals.begin(); record != cmpGlobals.end();
           record++) {
        auto key = record->first;
        res[function_id]["cm gl"][std::to_string(key)] = cmpGlobals[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = cmpNonZeros.begin(); record != cmpNonZeros.end();
           record++) {
        auto key = record->first;
        res[function_id]["cm nz"][std::to_string(key)] = cmpNonZeros[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      // outs() << "writesIntoStructs:\n";
      for (auto record = structWrites.begin(); record != structWrites.end();
           record++) {
        auto key = record->getFirst();
        // Some are nameless struct
        res[function_id]["wr st"][std::string(key)] = structWrites[key];
        // outs() << key << " " << structWrites[key] << "\n";
      }
      // outs() << "\n";

      // outs() << "StructsInArgs:\n";
      for (auto record = structArgs.begin(); record != structArgs.end();
           record++) {
        auto key = record->first;
        res[function_id]["str arg"][std::string(key)] = record->second;
        // outs() << key << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "CmpTypes:\n";
      for (auto record = cmpTypes.begin(); record != cmpTypes.end(); record++) {
        res[function_id]["cm ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      for (auto record = cmpComplexity.begin(); record != cmpComplexity.end();
           record++) {
        res[function_id]["cm cm"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }

      // outs() << "CallArgTypes:\n";
      for (auto record = callArgTypes.begin(); record != callArgTypes.end();
           record++) {
        res[function_id]["ar ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "storeTypes:\n";
      for (auto record = storeTypes.begin(); record != storeTypes.end();
           record++) {
        res[function_id]["st ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "loadTypes:\n";
      for (auto record = loadTypes.begin(); record != loadTypes.end();
           record++) {
        res[function_id]["l ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "allocaTypes:\n";
      for (auto record = allocaTypes.begin(); record != allocaTypes.end();
           record++) {
        res[function_id]["al ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      if (getenv("ANALYSIS_OUTPUT")) {
        if (std::ofstream(getenv("ANALYSIS_OUTPUT") + std::string("/") +
                          genericFilePath + ".json")
            << res << "\n") {
        } else {
          errs() << "Failed to write the data"
                 << "\n";
        }
      } else {
        errs() << "Failed to write the data, output path not set!"
               << "\n";
      }
    }
  }

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}
