#include "Analysis/CallGraph/CBCallGraph.h"
#include "Analysis/Graph/ControlDependenceGraph.h"
#include "Analysis/Graph/DomTreePass.h"
#include "Checker/CBPluginPass.h"
#include <map>
#include <string>
#include <vector>

#include "IR/SEG/SEGCallSiteOutputNode.h"
#include "IR/SEG/SEGCallSitePseudoInputNode.h"
#include "IR/SEG/SEGSimpleOperandNode.h"
#include "IR/SEG/SymbolicExprGraph.h"
#include "IR/SEG/SymbolicExprGraphBuilder.h"

#include "Analysis/CFG/CFGReachabilityAnalysis.h"
#include "Analysis/CallGraph/CBCallGraph.h"
#include "Analysis/Graph/ControlDependenceGraph.h"
#include "Analysis/Graph/DomTreePass.h"
#include "Checker/PSA/Vulnerability.h"

#include "GraphDiffer.h"
#include "PatchParser.h"
#include "SpecParser.h"

using namespace llvm;
using namespace std;

class SEGPathDiff : public CBPluginPass {

private:
  vector<shared_ptr<Vulnerability>> customizedCheckers;

  PatchParser *patchParser = nullptr;
  GraphDiffer *graphParser = nullptr;
  EnhancedSEGWrapper *SEGWrapper = nullptr;
  SpecParser *specParser = nullptr;

  SymbolicExprGraphBuilder *SEGBuilder = nullptr;
  CBCallGraph *pCBCG = nullptr;
  DebugInfoAnalysis *pDIA = nullptr;
  ControlDependenceAnalysis *pCDGs = nullptr;
  CFGReachabilityAnalysis *pCRA = nullptr;
  SymbolicExprGraphSolver *pSolver = nullptr;
  DomTreePass *pDT = nullptr;
  TSDataLayout *DL = nullptr;
  ExternalMemorySpec *MemSpec = nullptr;
  ExternalIOSpec *IOSpec = nullptr;

public:
  void getAnalysisUsage(AnalysisUsage &AU) override;

  void runOnModule(Module &M) override;
};
