#ifndef CLEARBLUE_ENHANCEDSEG_H
#define CLEARBLUE_ENHANCEDSEG_H

#include "ConditionNode.h"
#include "DriverSpecs.h"
#include "NodeHelper.h"
#include "SensitiveOps.h"
#include "UtilsHelper.h"
#include <llvm/Support/Casting.h>
#include <queue>
#include <utility>

#include "IR/SEG/SEGCallSiteOutputNode.h"
#include "IR/SEG/SEGCallSitePseudoInputNode.h"
#include "IR/SEG/SEGSimpleOperandNode.h"
#include "IR/SEG/SymbolicExprGraph.h"
#include "IR/SEG/SymbolicExprGraphBuilder.h"
#include <llvm/Support/Debug.h>

#include "Analysis/CFG/CFGReachabilityAnalysis.h"
#include "Analysis/CallGraph/CBCallGraph.h"
#include "Analysis/Graph/ControlDependenceGraph.h"
#include "Analysis/Graph/DomTreePass.h"
#include "Checker/PSA/Vulnerability.h"

using namespace llvm;
using namespace std;

typedef ControlDependenceGraph::CDType CDType;

struct SEGTraceWithBB {
  vector<SEGObject *> trace;
  vector<BasicBlock *> bbs;

  SEGTraceWithBB(){};

  SEGTraceWithBB(vector<SEGObject *> trace, vector<BasicBlock *> bbs)
      : trace(trace), bbs(bbs){};

  SEGTraceWithBB(SEGTraceWithBB const &trace1) {
    trace = trace1.trace;
    bbs = trace1.bbs;
  };

  bool operator==(const SEGTraceWithBB &trace1) const {
    return trace == trace1.trace && bbs == trace1.bbs;
  }

  bool operator<(const SEGTraceWithBB &trace1) const {
    return trace < trace1.trace;
  }

  bool isSubSEGTrace(const SEGTraceWithBB &trace1) {
    auto it = search(trace1.trace.begin(), trace1.trace.end(), trace.begin(),
                     trace.end());

    // If iterator 'it' is not the end of 'b', 'a' is a subvector of 'b'
    return (it != trace1.trace.end());
  }

  void dump() {
    DEBUG_WITH_TYPE("statistics", dbgs() << "[BBs]:");
    for (int i = 0; i < bbs.size(); i++) {
      DEBUG_WITH_TYPE("statistics", dbgs() << " " << bbs[i]->getName());
    }
    DEBUG_WITH_TYPE("statistics", dbgs() << "\n");
    for (int i = 0; i < trace.size(); i++) {
      if (isa<SEGStoreMemNode>(trace[i])) {
        auto *storeNode = dyn_cast<SEGStoreMemNode>(trace[i]);
        if (storeNode->getStoreSiteAsStoreInst()) {
          printSourceCodeInfoWithValue(storeNode->getStoreSiteAsStoreInst());
        }
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else if (isa<SEGCallSitePseudoInputNode>(trace[i])) {
        auto *inputNode = dyn_cast<SEGCallSitePseudoInputNode>(trace[i]);
        if (inputNode->getCallSite().getInstruction()) {
          printSourceCodeInfoWithValue(
              inputNode->getCallSite().getInstruction());
        }
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else if (isa<SEGCallSiteOutputNode>(trace[i])) {
        auto *outputNode = dyn_cast<SEGCallSiteOutputNode>(trace[i]);
        if (outputNode->getCallSite()->getInstruction()) {
          printSourceCodeInfoWithValue(
              outputNode->getCallSite()->getInstruction());
        }
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else if (isa<SEGArgumentNode>(trace[i])) {
        auto *argNode = dyn_cast<SEGArgumentNode>(trace[i]);
        printSourceCodeInfoWithValue(&argNode->getParentGraph()
                                          ->getBaseFunc()
                                          ->getEntryBlock()
                                          .getInstList()
                                          .front());
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else if (isa<SEGPhiNode>(trace[i])) {
        auto *phiNode = dyn_cast<SEGPhiNode>(trace[i]);
        printSourceCodeInfoWithValue(phiNode->getLLVMDbgValue());
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else if (trace[i]->getLLVMDbgValue()) {
        printSourceCodeInfoWithValue(trace[i]->getLLVMDbgValue());
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      } else {
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Node] " << *trace[i] << "\n");
      }
    }
    DEBUG_WITH_TYPE("statistics", dbgs() << "\n");
  }

  SEGNodeBase *getFirstNode() {
    for (auto elem : trace) {
      if (auto *node = dyn_cast<SEGNodeBase>(elem)) {
        return node;
      }
    }
    return nullptr;
  }

  SEGNodeBase *getLastNode() {
    for (auto elem = trace.rbegin(); elem != trace.rend(); elem++) {
      if (auto *node = dyn_cast<SEGNodeBase>(*elem)) {
        return node;
      }
    }
    return nullptr;
  }
};

struct EnhancedSEGTrace {
  SEGTraceWithBB trace;
  ConditionNode *conditions;
  int output_order;

  InputNode *input_node;
  OutputNode *output_node;

  // just to use set
  bool operator<(const EnhancedSEGTrace &trace1) const {
    return trace < trace1.trace;
  }

  bool operator==(const EnhancedSEGTrace &trace1) const {
    return trace == trace1.trace && conditions == trace1.conditions &&
           input_node == trace1.input_node &&
           output_order == trace1.output_order &&
           output_node == trace1.output_node;
  }

  EnhancedSEGTrace(){};

  EnhancedSEGTrace(vector<SEGObject *> inter, vector<BasicBlock *> bbs) {
    trace = SEGTraceWithBB(inter, bbs);
  };

  EnhancedSEGTrace(EnhancedSEGTrace const &trace1) {
    trace = trace1.trace;
    conditions = trace1.conditions;
    input_node = trace1.input_node;
    output_node = trace1.output_node;
    output_order = trace1.output_order;
  };

  EnhancedSEGTrace(SEGTraceWithBB &segTrace) : trace(segTrace){};
};

// Data Flow + Control Flow + Flow Order
class EnhancedSEGWrapper {
  SymbolicExprGraphBuilder *SEGBuilder;

  CBCallGraph *CBCG;
  CFGReachabilityAnalysis *CRA;
  ControlDependenceAnalysis *CDGs;
  DebugInfoAnalysis *DIA;
  DomTreePass *DT;

  map<SEGOperandNode *, pair<int, int>> nodeFlowOrder;

  map<Function *, set<Function *>> caller2CalleeMap;
  map<Function *, set<Function *>> callee2CallerMap;

  map<Function *, set<vector<Function *>>> caller2AllCallers;
  map<Function *, set<vector<Function *>>> caller2AllCallees;

  set<Function *> indirectCalls;

  map<pair<BasicBlock *, BasicBlock *>, set<vector<pair<BasicBlock *, CDType>>>>
      startEndBBsToPaths;

  map<vector<pair<BasicBlock *, CDType>>, SMTSolver::SMTResultType>
      feasibilityBBPaths;

  map<pair<Instruction *, Instruction *>, bool> reachabilityMap;

  DenseMap<CBCallGraphNode *, DenseMap<CBCallGraphNode *, set<SEGCallSite *>>>
      func2AllCallsites;
  DenseMap<pair<Function *, Function *>,
           set<pair<Function *, pair<SEGCallSite *, SEGCallSite *>>>>
      commonCaller2CS;
  DenseMap<CBCallGraphNode *, int> dfn;
  DenseMap<CBCallGraphNode *, int> low;
  int token;
  stack<CBCallGraphNode *> tarjanStack;
  set<CBCallGraphNode *> isInStack;
  DenseMap<CBCallGraphNode *, set<CBCallGraphNode *>> SCCs;
  DenseMap<CBCallGraphNode *, DenseMap<CBCallGraphNode *, set<SEGCallSite *>>>
      SCC2CallerCS;
  DenseMap<CBCallGraphNode *, CBCallGraphNode *> node2SCCRoot;

  set<pair<ConditionNode *, ConditionNode *>> cacheReducedAB;
  set<pair<ConditionNode *, ConditionNode *>> cacheConflictAB;
  set<pair<ConditionNode *, ConditionNode *>> cacheMergeAB;

  map<Value *, bool> whetherICMPIO;

  set<vector<SEGObject *>> visitedTraces;

  void computeCallGraph();

  void computeIndirectCall();

  int collect_traces_time = 0;
  int collect_condition_time = 0;
  int collect_concat_time = 0;
  int collect_forward_time = 0;
  int collect_backward_time = 0;

  int collect_inter_forward_time = 0;
  int collect_inter_backward_time = 0;

  int count_obtain_backward_cache = 0;
  int count_obtain_forward_cache = 0;

  int collect_bb_path = 0;
  int collect_whole_smt = 0;
  int check_feasibile_time = 0;
  int check_whether_io = 0;
  int collect_trace_smt = 0;

public:
  Module *M;
  SymbolicExprGraphSolver *SEGSolver;
  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardIntraVisited;
  map<SEGNodeBase *, set<vector<SEGObject *>>> forwardIntraVisited;
  map<SEGNodeBase *, set<vector<SEGObject *>>> cond2ValueFlowsIntra;
  map<SEGNodeBase *, set<vector<SEGObject *>>> cond2ValueFlowsInter;

  EnhancedSEGWrapper(Module *pM, SymbolicExprGraphBuilder *pSEGBuilder,
                     SymbolicExprGraphSolver *pSEGSolver,
                     DebugInfoAnalysis *pDIA, CBCallGraph *pCBCG,
                     ControlDependenceAnalysis *pCDGs,
                     CFGReachabilityAnalysis *pCRA, DomTreePass *pDT);

  Function *getFuncByName(string fileFuncName);

  bool isTwoSEGNodeValueEqual(SEGNodeBase *node1, SEGNodeBase *node2);

  bool isIndirectCall(Function *func);

  bool isKernelOrCommonAPI(StringRef funcName);

  bool isTransitiveCallee(Function *func1, Function *func2);

  bool match_def_use_context(const vector<SEGObject *> &history_trace);

  string getCallSourceFile(Function *F);

  SMTExpr condNode2SMTExprInter(ConditionNode *condNode);

  SMTExpr condNode2SMTExprIntra(ConditionNode *condNode);

  SMTExpr condDataDepToExpr(
      ConditionNode *curNode,
      map<SEGNodeBase *, set<vector<SEGObject *>>> &cond2ValueFlows);

  void value2EnhancedSEGNode(set<Value *> &values, set<SEGNodeBase *> &nodes);

  void condNode2FlowInter(
      set<SEGNodeBase *> condNodes,
      map<SEGNodeBase *, set<vector<SEGObject *>>> &localCond2ValueFlows);
  void condNode2FlowIntra(
      set<SEGNodeBase *> condNodes,
      map<SEGNodeBase *, set<vector<SEGObject *>>> &localCond2ValueFlows);

  void obtainIntraEnhancedSlicing(set<SEGTraceWithBB> intraSEGTraces,
                                  set<EnhancedSEGTrace *> &intraTraces);

  void obtainInterSlicing(EnhancedSEGTrace *intraTrace,
                          set<EnhancedSEGTrace *> &interTraces);

  void collectRelatedBBs(vector<SEGObject *> &trace, int index,
                         vector<BasicBlock *> &curbbOnTraces,
                         vector<vector<BasicBlock *>> &bbOnTracesPaths);

  void
  collectPathToEntryOnCDG(BasicBlock *startBB, BasicBlock *endBB,
                          set<pair<BasicBlock *, CDType>> &visitedBBs,
                          vector<pair<BasicBlock *, CDType>> &curPath,
                          set<vector<pair<BasicBlock *, CDType>>> &totalPaths);

  void
  collectPathToEntryOnCFG(BasicBlock *startBB, BasicBlock *endBB,
                          set<pair<BasicBlock *, CDType>> &visitedBBs,
                          vector<pair<BasicBlock *, CDType>> &curPath,
                          set<vector<pair<BasicBlock *, CDType>>> &totalPath);

  void collectConditions(EnhancedSEGTrace *trace);

  void
  collectBBsToEntry(EnhancedSEGTrace *trace,
                    set<vector<pair<BasicBlock *, CDType>>> &totalCFGPaths);

  bool isConditionMerge(ConditionNode *curCond, ConditionNode *otherCond);

  bool isConditionConflict(ConditionNode *curCond, ConditionNode *otherCond);

  bool isConditionAReduceB(ConditionNode *curCond, ConditionNode *otherCond);

  void intraValueFlow(SEGNodeBase *criterion, set<SEGTraceWithBB> &intraTraces);

  bool checkifICMPIO(ICmpInst *iCmpInst, vector<SEGObject *> &guardedTrace);

  void intraValueFlowBackward(SEGNodeBase *node, vector<SEGObject *> &curTrace,
                              set<vector<SEGObject *>> &backwards);

  void intraValueFlowForward(SEGNodeBase *node, vector<SEGObject *> &curTrace,
                             set<vector<SEGObject *>> &forwards);

  void interValueFlowBackward(SEGNodeBase *node, vector<Function *> &callTrace,
                              vector<SEGObject *> &curTrace,
                              set<vector<SEGObject *>> &backwardInters);

  void interValueFlowForward(SEGNodeBase *node, vector<Function *> &callTrace,
                             vector<SEGObject *> &curTrace,
                             set<vector<SEGObject *>> &forwardInters);

  void findCallSite(Function *Caller, Function *Callee,
                    vector<SEGCallSite *> &callSites);

  static void removeCallGraphCycle(map<Function *, set<Function *>> &graph,
                                   map<Function *, set<Function *>> &tree);

  void funcCallLowerTracer(Function *func, vector<Function *> &curTrace,
                           set<vector<Function *>> &traces);

  void funcCallUpperTracer(Function *func, vector<Function *> &curTrace,
                           set<vector<Function *>> &traces);

  bool needForward(SEGNodeBase *node);

  bool needBackward(SEGNodeBase *node);

  bool isInputNode(SEGNodeBase *startNode, bool intra = false);

  bool checkCurPathFeasibility(vector<pair<BasicBlock *, CDType>> path);

  ConditionNode *path2IOCondition(vector<pair<BasicBlock *, CDType>> path,
                                  vector<SEGObject *> &guardedTrace);

  void canFindInput(vector<SEGObject *> trace, set<InputNode *> &inputNodes,
                    bool intra = false);

  void canFindOutput(vector<SEGObject *> trace, set<OutputNode *> &outputNodes,
                     bool isBenign, bool intra = false);

  bool ifInOutputMatch(InputNode *start, OutputNode *end);

  void Tarjan(CBCallGraphNode *node);

  bool check_reachability_inter(Instruction *src_inst, Instruction *dst_inst);

  void find_common_caller(
      Function *func1, Function *func2,
      set<pair<Function *, pair<SEGCallSite *, SEGCallSite *>>> &func2cs);

  void find_all_callers_bfs(
      CBCallGraphNode *node,
      DenseMap<CBCallGraphNode *, set<SEGCallSite *>> &caller2cs);

  void
  updateTraceOrder(map<SEGNodeBase *, set<EnhancedSEGTrace *>> &groupedTraces);

  void findLastIcmp(BasicBlock *bb, set<ICmpInst *> &icmpInsts);

  void findErrorCodeInput(ICmpInst *icmpInst, set<InputNode *> &icmpInputs);

  SEGNodeBase *findFirstNode(vector<SEGObject *> trace);

  bool isTwoEnhancedTraceEq(EnhancedSEGTrace *trace1, EnhancedSEGTrace *trace2);

  bool isTwoIONodeEqual(EnhancedSEGTrace *trace1, EnhancedSEGTrace *trace2);

  bool isTwoConditionEqual(ConditionNode *cond1, ConditionNode *cond2);

  void dumpEnhancedTraceCond(const EnhancedSEGTrace *trace);
};

#endif // CLEARBLUE_ENHANCEDSEG_H
