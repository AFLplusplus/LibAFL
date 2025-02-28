#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Support/Debug.h>
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"

// #include "WPA/WPAPass.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ddg-utils.h"
#include "common-llvm.h"

#define MAX_DEPTH 3
#define MIN_FCN_SIZE 1
#define VAR_NAME_LEN 264

#define MAP_SIZE DDG_MAP_SIZE
// #define MAP_SIZE 65536
#define ALL_BIT_SET (MAP_SIZE - 1)
// #define MAP_SIZE 255

// #define INTERPROCEDURAL 1   	// unset if you want only intraprocedural ret
// values management BUT #define  LOAD_INSTR           // considers loads as
// stores

// #define DEBUG 1               // set if you want debug prints enabled

#define AFL_SR(s) (srandom(s))
#define AFL_R(x) (random() % (x))

#ifdef DEBUG
  #define DEBUG(X) \
    do {           \
      X;           \
    } while (false)
#else
  #define DEBUG(X) ((void)0)
#endif

using namespace llvm;
// using namespace svf;

class DDGInstrModulePass : public PassInfoMixin<DDGInstrModulePass> {
 private:
  void InsertDataFlow(Value *Operand, Value *Res) {
    std::map<Value *, std::vector<Value *>>::iterator it =
        this->DataFlowTracker.begin();
    while (it != this->DataFlowTracker.end()) {
      std::vector<Value *>           Slice = it->second;
      std::vector<Value *>::iterator jt;
      for (jt = Slice.begin(); jt != Slice.end(); ++jt) {
        if (Operand == *jt) {
          this->DataFlowTracker[it->first].push_back(Res);
          break;
        }
      }
      it++;
    }
  }

  void RetrieveDataFlow(Value *V, std::vector<Value *> *Dependencies) {
    std::map<Value *, std::vector<Value *>>::iterator it =
        this->DataFlowTracker.begin();
    while (it != this->DataFlowTracker.end()) {
      std::vector<Value *>           Slice = it->second;
      std::vector<Value *>::iterator jt;
      for (jt = Slice.begin(); jt != Slice.end(); ++jt) {
        if (V == *jt) {
          Dependencies->push_back(it->first);
          break;
        }
      }
      it++;
    }
  }

  bool isSourceCodeVariable(Value *Variable) {
    std::map<Value *, std::vector<Value *>>::iterator it =
        this->DataFlowTracker.find(Variable);
    return it != this->DataFlowTracker.end();
  }

  bool isLLVMVariable(Value                            *Variable,
                      std::map<Value *, Instruction *> *LLVMVariables) {
    std::map<Value *, Instruction *>::iterator it =
        LLVMVariables->find(Variable);
    return it != LLVMVariables->end();
  }

  void CreateDataFlow(Value *Variable) {
    std::map<Value *, std::vector<Value *>>::iterator it =
        this->DataFlowTracker.find(Variable);
    if (it == this->DataFlowTracker.end()) {
      this->DataFlowTracker[Variable].push_back(Variable);
    }
  }

  // When we have `Store A, B`, we want to know that exactly B reperensents. In
  // the default case, it is a source code variable and so we're done. BUT, in
  // many cases B could represent the field of a struct, or a location whithin a
  // buffer. So, we need to recover what B represents to be more precise when we
  // define the dependency relationship.
  void RetrieveAccessedVariable(Value *Variable, std::vector<Value *> *Flows,
                                std::map<Value *, Instruction *> *LLVMVariables,
                                Value **ActualSrcVariable) {
    if (isLLVMVariable(Variable, LLVMVariables)) {
      // If it is an LLVM variable (mostly for struct fields), we have it
      // tracked down in the LLVMVariables list, so we just need to parse the
      // GEP inst
      Instruction *DefiningInstruction = (*LLVMVariables)[Variable];
      // For now we only handle the GEP instructions, maybe in future
      // it could be useful to implement other instructions
      if (auto GEP = dyn_cast<GetElementPtrInst>(DefiningInstruction)) {
        Value *PtrOperand = GEP->getPointerOperand();
        Variable = PtrOperand;
        *ActualSrcVariable = PtrOperand;
        if (isSourceCodeVariable(PtrOperand)) {
          // We finally could connect an LLVM variable to an actual Source code
          // Variable!
          for (unsigned int i = 1; i < DefiningInstruction->getNumOperands();
               i++) {  // Starts from 1, since 0 is thr PtrOperand
            Value *Op = DefiningInstruction->getOperand(i);
            if (!isa<Constant>(Op)) { RetrieveDataFlow(Op, Flows); }
          }
          return;
        } else {
          // Re-itereate the Variable analysis
          RetrieveAccessedVariable(Variable, Flows, LLVMVariables,
                                   ActualSrcVariable);
        }
        for (unsigned int i = 1; i < DefiningInstruction->getNumOperands();
             i++) {  // Starts from 1, since 0 is thr PtrOperand
          Value *Op = DefiningInstruction->getOperand(i);
          if (!isa<Constant>(Op)) { RetrieveDataFlow(Op, Flows); }
        }
      }
    } else {
      // If it is not a GEP-defined llvm variable, we basically use the DataFlow
      // Tracker, to retrieve the dependency of this variable. The idea is that,
      // if this llvm variable is not GEP-depending, it should be easier to
      // retrieve what it does represent
      std::vector<Value *> TmpFlow;
      RetrieveDataFlow(Variable, &TmpFlow);
      if (TmpFlow.size() == 1) {
        *ActualSrcVariable = TmpFlow[0];
        // We found a Source Code variable (Variable->getName())
        return;
      } else if (TmpFlow.size() > 1) {
        *ActualSrcVariable = TmpFlow[0];
        DEBUG(errs() << "[Warning] multiple flows for the same GEP access, "
                        "choosing the first one\n");
      } else {
        return;
      }
    }
  }

 public:
  static char                             ID;
  FunctionCallee                          logger;
  Type                                   *VoidTy;
  std::map<Value *, std::vector<Value *>> DataFlowTracker;

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    LLVMContext &C = M.getContext();

    auto &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    auto DTCallback = [&FAM](Function &F) -> DominatorTree * {
      return &FAM.getResult<DominatorTreeAnalysis>(F);
    };

    auto PDTCallback = [&FAM](Function &F) -> PostDominatorTree * {
      return &FAM.getResult<PostDominatorTreeAnalysis>(F);
    };

    auto LICallback = [&FAM](Function &F) -> LoopInfo * {
      return &FAM.getResult<LoopAnalysis>(F);
    };

    IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    // IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
    ConstantInt *One = ConstantInt::get(Int8Ty, 1);
    unsigned int instrumentedLocations = 0;

    std::map<BasicBlock *, ConstantInt *> BlocksLocs;
    std::map<BasicBlock *, Value *>       VisitedBlocks;
    ConstantInt *Visited = ConstantInt::get(Int16Ty, 0xff);
    ConstantInt *NonVisited = ConstantInt::get(Int16Ty, 0);
    ConstantInt *CurLoc;
    char        *name = nullptr;
    unsigned     BBCounter = 0;

    unsigned     bb_count = 0;
    unsigned int cur_loc = 0;
    uint32_t     map_size = MAP_SIZE;

    struct timeval  tv;
    struct timezone tz;
    unsigned int    rand_seed;

    /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
    gettimeofday(&tv, &tz);
    rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
    AFL_SR(rand_seed);

    GlobalVariable *DDGMapPtr = M.getGlobalVariable("__ddg_area_ptr");
    if (DDGMapPtr == nullptr)
      DDGMapPtr =
          new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                             GlobalValue::ExternalLinkage, 0, "__ddg_area_ptr");

#ifdef INTERPROCEDURAL
    // For each function we store the return Values
    std::map<Function *, std::vector<Instruction *>> ReturnValues;

    for (auto &F : M) {
      if (F.size() < MIN_FCN_SIZE) continue;

      for (auto &BB : F) {
        for (auto &I : BB) {
          if (auto RI = dyn_cast<ReturnInst>(&I)) {
            Value *RetVal = RI->getReturnValue();
            if (RetVal) { ReturnValues[&F].push_back(RI); }
          }
        }
      }
    }
#endif

    for (auto &F : M) {
      if (F.size() < MIN_FCN_SIZE) continue;

      std::map<Value *, std::vector<FlowWriteInstruction *>>
          Stores;  // Represents the nodes of our DataDep Graph
      std::vector<std::tuple<BasicBlock *, BasicBlock *>>
          StoreEdges;  // Contains the edges of the DDG
      std::map<BasicBlock *, std::set<BasicBlock *>>
          IncomingEdges;  // Map s.t. key is a BB and value is a set of BBs
                          // whose data flow reaches the key
      std::map<Value *, Instruction *>
          LLVMVariables;  // LLVM IR Variables which are used as Operands for
                          // the store (for instance, the ones resulting from a
                          // GEP)

      BasicBlock  &EntryBB = F.getEntryBlock();
      Instruction *FirstInst = &*EntryBB.getFirstNonPHIOrDbg();

      // First we add the function params to track the dataflow
      for (Function::arg_iterator arg_it = F.arg_begin(); arg_it != F.arg_end();
           arg_it++) {
        Argument *Arg = arg_it;
        if (Value *ArgVariable = dyn_cast<Value>(Arg)) {
          CreateDataFlow(ArgVariable);
          FlowWriteInstruction *MyStore =
              new FlowWriteInstruction(&EntryBB, FirstInst, declaration);
          Stores[ArgVariable].push_back(MyStore);
        }
      }

      LoopInfo          *LI = LICallback(F);
      DominatorTree     *DT = DTCallback(F);
      PostDominatorTree *PT = PDTCallback(F);

      // We basically want to track data flow between memory instructions
      // and call instructions (i.e., the arguments)

      // Here we extract the data dependence info for function F
      for (auto &BB : F) {
        BBCounter += 1;
        for (auto &I : BB) {
          // We track all variables "Alloca" derived and we add them to the
          // RootNode
          if (auto AI = dyn_cast<AllocaInst>(&I)) {
            Value *Variable = static_cast<Value *>(AI);
            CreateDataFlow(Variable);
          }

          if (auto LOI = dyn_cast<LoadInst>(&I)) {
            Value *Variable = LOI->getPointerOperand();
            CreateDataFlow(Variable);
#ifdef LOAD_INSTR
            std::vector<Value *> Flows;
            RetrieveDataFlow(Variable, &Flows);

            // If `Variable` does not directly represent a Src code variable, we
            // fetch what it represents (e.g., the field of a struct)
            if (!isSourceCodeVariable(Variable)) {
              Value *ActualSrcVariable = nullptr;
              RetrieveAccessedVariable(Variable, &Flows, &LLVMVariables,
                                       &ActualSrcVariable);
              if (ActualSrcVariable) Variable = ActualSrcVariable;
            }

            for (std::vector<Value *>::iterator it = Flows.begin();
                 it != Flows.end(); ++it) {
              Value *Dependency = *it;

              // First we find the edges between the current store and the
              // previous ones (i.e., when we wrote into `c` and `b` if the
              // current store is `a = c + b`)
              std::vector<FlowWriteInstruction *> AllStoresPerVariable =
                  Stores[Dependency];
              unsigned ConsideredStores = 0;
              bool    *ReachingStores = isReachableByStore(
                  &AllStoresPerVariable, LOI, &DT, &LI, &ConsideredStores);

              // ReachingStores[0] refers to the last Store instruction that we
              // met (i.e., the last in `AllStoresPerVariable` This is why we
              // iterate the vector in a reverse way BUT the array in the
              // forward
              unsigned i = 0;
              for (std::vector<FlowWriteInstruction *>::reverse_iterator it =
                       AllStoresPerVariable.rbegin();
                   it != AllStoresPerVariable.rend(); it++) {
                if (ReachingStores[i] && (i < ConsideredStores)) {
                  Instruction *Src = (*it)->I;
                  if (Src ==
                      LOI)  // Already managed in the `reachableByStores` method
                    continue;
                  if (Src->getParent() != LOI->getParent()) {
                    StoreEdges.push_back(edge);
                    IncomingEdges[LOI->getParent()].insert(LOI->getParent());
                    DEBUG(errs() << "+++++++++++\nAdding edge\n");
                    DEBUG(debug_instruction(Src));
                    DEBUG(debug_instruction(LOI));
                    DEBUG(errs() << "-----------\n");
                  }
                }
                i++;
              }

              delete[] ReachingStores;
            }
            // Then we insert the new Store in our map that contains all the
            // stores, so we build forward deps
            FlowWriteInstruction *MyStore =
                new FlowWriteInstruction(LOI->getParent(), LOI, declaration);
            Stores[Variable].push_back(MyStore);
#endif
          }

          if (auto GEP = dyn_cast<GetElementPtrInst>(
                  &I)) {  // We dedicate an list for GEPs defined llvm vars.
            Value *Var = static_cast<Value *>(
                &I);  // For other LLVM variables, we use the DataflowTracker
            LLVMVariables[Var] = GEP;
          }

          // We propagate the dependency info
          Value *Result = static_cast<Value *>(&I);
          if (Result and
              !isa<CallInst>(
                  I)) {  // We exclude CallInst, as they're managed separately
                         // (Not excluding them now, would introduce a double
                         // dependency leading to the same value)
            for (unsigned int i = 0; i < I.getNumOperands(); i++) {
              Value *Op = I.getOperand(i);
              if (!isa<Constant>(Op)) InsertDataFlow(Op, Result);
            }
          }
#ifdef INTERPROCEDURAL
          else if (Result and isa<CallInst>(I)) {
            CallInst *CI = dyn_cast<CallInst>(&I);
            Function *CalledFunction = CI->getCalledFunction();
            std::map<Function *, std::vector<Instruction *>>::iterator it =
                ReturnValues.find(CalledFunction);
            if (it != ReturnValues.end()) {
              std::vector<Instruction *> RetValsInstrs = it->second;
              for (std::vector<Instruction *>::iterator jt =
                       RetValsInstrs.begin();
                   jt != RetValsInstrs.end(); jt++) {
                Instruction *In = *jt;
                ReturnInst  *Ret = static_cast<ReturnInst *>(In);
                Value       *RV = Ret->getReturnValue();
                CreateDataFlow(RV);
                InsertDataFlow(RV, Result);  // We indicate dependency between
                                             // retval and call site
                Stores[RV].push_back(new FlowWriteInstruction(
                    Ret->getParent(), Ret, declaration));
              }
            }
          }
#endif
          // We create the actual DDG depending on mem accesses and Call
          // instructions
          if (auto ST = dyn_cast<StoreInst>(&I)) {
            Value *Variable = ST->getPointerOperand();  // Where we're writing
            Value *Access = ST->getValueOperand();  // What we're writing, this
                                                    // gives us the dependencies
            // The current Store is writing `Access` into `Variable`

            std::vector<Value *> Flows;
            RetrieveDataFlow(Access, &Flows);

            // If `Variable` does not directly represent a Src code variable, we
            // fetch what it represents (e.g., the field of a struct)
            if (!isSourceCodeVariable(Variable)) {
              Value *ActualSrcVariable = nullptr;
              RetrieveAccessedVariable(Variable, &Flows, &LLVMVariables,
                                       &ActualSrcVariable);
              if (ActualSrcVariable) Variable = ActualSrcVariable;
            }

            StoreType Type = declaration;  // Usually we have `a = c + b`
            for (std::vector<Value *>::iterator it = Flows.begin();
                 it != Flows.end(); ++it) {
              Value *Dependency = *it;
              if (Dependency == Variable)  // If we fall into `a += c + b`, we
                                           // manage differently
                Type = modification;  // Probably we dont need this distinction
                                      // anymore, but keep it for future
                                      // experiments

              // First we find the edges between the current store and the
              // previous ones (i.e., when we wrote into `c` and `b` if the
              // current store is `a = c + b`)
              std::vector<FlowWriteInstruction *> AllStoresPerVariable =
                  Stores[Dependency];
              unsigned ConsideredStores = 0;
              bool    *ReachingStores = isReachableByStore(
                  &AllStoresPerVariable, ST, DT, LI, &ConsideredStores);

              // ReachingStores[0] refers to the last Store instruction that we
              // met (i.e., the last in `AllStoresPerVariable` This is why we
              // iterate the vector in a reverse way BUT the array in the
              // forward
              unsigned i = 0;
              for (std::vector<FlowWriteInstruction *>::reverse_iterator it =
                       AllStoresPerVariable.rbegin();
                   it != AllStoresPerVariable.rend(); it++) {
                if (ReachingStores[i] && (i < ConsideredStores)) {
                  Instruction *Src = (*it)->I;
                  if (Src ==
                      ST)  // Already managed in the `reachableByStores` method
                    continue;
                  if (isPredecessorBB(Src,
                                      ST))  // Already managed by edge coverage
                    continue;
#if LLVM_VERSION_MAJOR == 9
                  BasicBlock *SrcParent = Src->getParent();
                  BasicBlock *STParent = ST->getParent();
                  if (PT->dominates(SrcParent, STParent))
#else
                  if (PT->dominates(Src, ST))
#endif
                    continue;
                  if (Src->getParent() != ST->getParent()) {
                    std::tuple<BasicBlock *, BasicBlock *> edge =
                        decltype(edge){Src->getParent(), ST->getParent()};
                    StoreEdges.push_back(edge);
                    IncomingEdges[ST->getParent()].insert(Src->getParent());
                    DEBUG(errs() << "+++++++++++\nAdding edge\n");
                    DEBUG(debug_instruction(Src));
                    DEBUG(debug_instruction(ST));
                    DEBUG(errs() << "-----------\n");
                  }
                }
                i++;
              }

              delete[] ReachingStores;
            }
            // Then we insert the new Store in our map that contains all the
            // stores, so we build forward deps
            FlowWriteInstruction *MyStore =
                new FlowWriteInstruction(ST->getParent(), ST, Type);
            Stores[Variable].push_back(MyStore);

          }
          // Three major cases:
          // 1) a = foo(x)           => a depends on the result of foo() applied
          // on x and x depends on its previous values and return value 2)
          // memcpy(src, dst, N)  => dst depends on src and N && the triple src,
          // dst, N depends on their previous value (memcpy or any other API) 3)
          // foo(x, out_y, out_z) => out_x, out_y are writen within foo
          // depending on x. Thus here the dependency is managed internally to
          // the function when passing on it
          else if (CallInst *Call = dyn_cast<CallInst>(&I)) {
            FlowWriteInstruction *MyStore = nullptr;
            Value                *Variable = nullptr;
            Function             *FC = Call->getCalledFunction();
            // DEBUG(errs() << "Looking for dependencies when calling " <<
            // FC->getName() << "\n");
            int argStart =
                0;  // In some cases, we dont want to track dependencies for
                    // each argument. For instance, for memcpy(src, dst, n), we
                    // can ignore previous `src` dependencies, since it is being
                    // written. Rather, for this specific case, we generate a
                    // FlowWriteInstruction object to save the fact that `src`
                    // internal value has been modified according to `dst` and
                    // `n`

            if (FC == nullptr) continue;
            if (FC->isIntrinsic()) {
              switch (FC->getIntrinsicID()) {
                case Intrinsic::memcpy: {
                  Variable = Call->getArgOperand(0);
                  std::vector<Value *> Flows;
                  RetrieveDataFlow(Variable, &Flows);
                  if (Flows.size() != 0) Variable = Flows[0];
                  MyStore = new FlowWriteInstruction(Call->getParent(), Call,
                                                     declaration);
                  argStart = 1;
                  break;
                }
                case Intrinsic::memset: {
                  // memset does not produce a real dataflow
                  // errs() << "memset to implement\n";
                  break;
                }
                case Intrinsic::memmove: {
                  Variable = Call->getArgOperand(0);
                  std::vector<Value *> Flows;
                  RetrieveDataFlow(Variable, &Flows);
                  if (Flows.size() != 0) Variable = Flows[0];
                  MyStore = new FlowWriteInstruction(Call->getParent(), Call,
                                                     declaration);
                  argStart = 1;
                  break;
                }
                default: {
                  // errs() << "Not implemented/interesting intrinsic for data
                  // flow\n";
                  break;
                }
              }
            }
            for (unsigned int i = argStart; i < Call->arg_size(); i++) {
              Value *ArgOp = Call->getArgOperand(i);
              if (!isa<Constant>(ArgOp)) {
                std::vector<Value *> Flows;
                RetrieveDataFlow(ArgOp, &Flows);

                for (std::vector<Value *>::iterator it = Flows.begin();
                     it != Flows.end(); ++it) {
                  Value *Dependency = *it;
                  // DEBUG(errs() << "Call depending on: {" <<
                  // Dependency->getName() << "}\n");
                  std::vector<FlowWriteInstruction *> AllStoresPerVariable =
                      Stores[Dependency];
                  unsigned ConsideredStores = 0;
                  bool    *ReachingStores = isReachableByStore(
                      &AllStoresPerVariable, Call, DT, LI, &ConsideredStores);
                  unsigned i = 0;
                  for (std::vector<FlowWriteInstruction *>::reverse_iterator
                           it = AllStoresPerVariable.rbegin();
                       it != AllStoresPerVariable.rend(); it++) {
                    if (ReachingStores[i] && (i < ConsideredStores)) {
                      Instruction *Src = (*it)->I;
                      if (Src == Call)  // Already managed in the
                                        // `reachableByStores` method
                        continue;
                      if (isPredecessorBB(Src, Call)) continue;
#if LLVM_VERSION_MAJOR == 9
                      BasicBlock *SrcParent = Src->getParent();
                      BasicBlock *CallParent = Call->getParent();
                      if (PT->dominates(SrcParent, CallParent))
#else
                      if (PT->dominates(Src, Call))
#endif
                        continue;
                      if (Src->getParent() != Call->getParent()) {
                        std::tuple<BasicBlock *, BasicBlock *> edge =
                            decltype(edge){Src->getParent(), Call->getParent()};
                        StoreEdges.push_back(edge);
                        IncomingEdges[Call->getParent()].insert(
                            Src->getParent());
                        DEBUG(errs() << "+++++++++++\nAdding edge\n");
                        DEBUG(debug_instruction(Src));
                        DEBUG(debug_instruction(Call));
                        DEBUG(errs() << "-----------\n");
                      }
                    }
                    i++;
                  }
                }
              }
            }
            if (Variable != nullptr && MyStore != nullptr) {
              Stores[Variable].push_back(MyStore);
            }
          } else
            continue;
        }
      }

      // Instrument the locations in the function
      BasicBlock::iterator IP = EntryBB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      Value               *IsCurrentBlockVisited;

      for (auto &BB : F) {
        bb_count++;
        name = new char[VAR_NAME_LEN];
        memset(name, 0, VAR_NAME_LEN);
        snprintf(name, VAR_NAME_LEN, "my_var_%d", BBCounter++);
        AllocaInst *AllocaIsCurrentlyBlockVisited =
            IRB.CreateAlloca(Int16Ty, nullptr, StringRef(name));
        AllocaIsCurrentlyBlockVisited->setMetadata(M.getMDKindID("nosanitize"),
                                                   MDNode::get(C, None));
        IsCurrentBlockVisited =
            static_cast<Value *>(AllocaIsCurrentlyBlockVisited);
        StoreInst *InitializeVisited;
        if (&EntryBB == &BB)
          InitializeVisited = IRB.CreateStore(Visited, IsCurrentBlockVisited);
        else
          InitializeVisited =
              IRB.CreateStore(NonVisited, IsCurrentBlockVisited);

        if (InitializeVisited)
          InitializeVisited->setMetadata(M.getMDKindID("nosanitize"),
                                         MDNode::get(C, None));

        VisitedBlocks[&BB] = IsCurrentBlockVisited;

        // errs() << "MAP SIZE " << std::to_string(map_size) << "\n";
        cur_loc = AFL_R(map_size);
        CurLoc = ConstantInt::get(Int16Ty, cur_loc);
        BlocksLocs[&BB] = CurLoc;
      }

      for (auto &BB : F) {
        if (&BB == &EntryBB) continue;

        IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));
        IsCurrentBlockVisited = VisitedBlocks[&BB];

        StoreInst *StoreIsVisited =
            IRB.CreateStore(Visited, IsCurrentBlockVisited);
        StoreIsVisited->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

        Value *HashedLoc = nullptr;
        if (IncomingEdges[&BB].size() <= 1) continue;
        for (std::set<BasicBlock *>::iterator it = IncomingEdges[&BB].begin();
             it != IncomingEdges[&BB].end(); ++it) {
          Value       *isVisited = VisitedBlocks[*it];
          ConstantInt *PotentiallyPreviousLoc = BlocksLocs[*it];
          if (!isVisited or !PotentiallyPreviousLoc) continue;
          LoadInst *LoadIsVisited =
              IRB.CreateLoad(isVisited->getType(), isVisited);
          LoadIsVisited->setMetadata(M.getMDKindID("nosanitize"),
                                     MDNode::get(C, None));

          Value *PrevLocIfVisited =
              IRB.CreateAnd(LoadIsVisited, PotentiallyPreviousLoc);
          CurLoc = BlocksLocs[&BB];
          if (HashedLoc == nullptr)
            HashedLoc = IRB.CreateXor(CurLoc, PrevLocIfVisited);
          else
            HashedLoc = IRB.CreateXor(HashedLoc, PrevLocIfVisited);
        }
        if (HashedLoc == nullptr) continue;

        HashedLoc = IRB.CreateZExt(HashedLoc, IRB.getInt16Ty());

        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(Int8Ty, 0), DDGMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value    *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, HashedLoc);
        LoadInst *Counter = IRB.CreateLoad(Int8Ty, MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);
        auto   cf = IRB.CreateICmpEQ(Incr, Zero);
        auto   carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

        StoreInst *StoreMapPtr = IRB.CreateStore(Incr, MapPtrIdx);
        StoreMapPtr->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));

        instrumentedLocations++;
      }
    }

    errs() << "DDG - Instrumented " << instrumentedLocations
           << " locations over a total of " << bb_count << " \t\n";

    auto PA = PreservedAnalyses::all();
    return PA;
  }
};

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "DDGInstrPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
#if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
#endif
                ) { MPM.addPass(DDGInstrModulePass()); });
          }};
}
