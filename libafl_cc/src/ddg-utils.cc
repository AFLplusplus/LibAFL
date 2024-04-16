#include "llvm/Analysis/CFG.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Support/Debug.h>
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
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

#include "ddg-utils.h"

#define BB_THRESHOLD 16

void debug_instruction(Instruction *I) {
  DILocation *D = I->getDebugLoc();

  if (D != NULL) {
    errs() << "Line: " << D->getLine() << "\n";
    return;
  }
  errs() << "[DEBUG] No dbg info recovered\n";
}

// void debug_DDG(std::map<CustomDDGNode*, std::vector<CustomDDGNode*>> graph) {
//   std::map<CustomDDGNode*, std::vector<CustomDDGNode*>>::iterator it =
//   graph.begin(); while(it != graph.end()) {
//     CustomDDGNode* src = it->first;
//     std::vector<CustomDDGNode*> sinks = it->second;
//
//     it++;
//   }
// }

// Checks if Src is in the predecessor BB of To
bool isPredecessorBB(Instruction *Src, Instruction *To) {
  BasicBlock *ToParent = To->getParent();
  BasicBlock *SrcParent = Src->getParent();
  for (auto it = pred_begin(ToParent); it != pred_end(ToParent); ++it) {
    BasicBlock *predecessor = *it;
    if (predecessor == SrcParent) return true;
  }
  return false;
}

bool *isReachableByStore(std::vector<FlowWriteInstruction *> *From,
                         Instruction *To, DominatorTree *DT, LoopInfo *LI,
                         unsigned *ConsideredStores) {
  size_t   NumberOfStores = From->size();
  unsigned bb_threshold =
      NumberOfStores < BB_THRESHOLD ? NumberOfStores : BB_THRESHOLD;
  *ConsideredStores = bb_threshold;
  FlowWriteInstruction *TopNstores[bb_threshold];
  bool                 *ReachingStores = new bool[bb_threshold];
  SmallPtrSet<BasicBlock *, BB_THRESHOLD> ExclusionSet;
  unsigned                                idx = 0;
  for (std::vector<FlowWriteInstruction *>::reverse_iterator it =
           From->rbegin();
       it != From->rend(); it++) {
    FlowWriteInstruction *MyStore = *it;
    // TopNStores contains the last N stores, which are the ones that we check
    // if are reachable. These are put in reverse order, i.e., the position `0`
    // (TopNstores[0]) is the last store that we met (which is the last in the
    // vector From)
    TopNstores[idx] = MyStore;
    ExclusionSet.insert(MyStore->BB);
    idx++;
    if (idx >= bb_threshold) break;
  }

  // We need the ExclusionSet to be complete, before startintg with the actual
  // check loop
  for (int i = 0; i < bb_threshold; i++) {
    Instruction *FromInstruction = TopNstores[i]->I;
    if (TopNstores[i]->BB == To->getParent()) {
      // If the two BBs are the same, we discard this flow. It is not
      // interesting since if we reach the BB we cover it
      ReachingStores[i] = false;
      // continue; // RE-ENABLE THIS WHEN NO DEBUGGING IS NEEDED;
    }
    ExclusionSet.erase(TopNstores[i]->BB);
    if (FromInstruction != To) {
      bool r =
          isPotentiallyReachable(FromInstruction, To, &ExclusionSet, DT, LI);
      // errs() << "isPotentiallyReachable " << r << "\n";
      ReachingStores[i] = r;
    } else
      ReachingStores[i] = false;  // Same instruction not reachable by itself
    ExclusionSet.insert(TopNstores[i]->BB);
  }
  // ReachingStores[0] refers to the last Store instruction that we met

  return ReachingStores;
}