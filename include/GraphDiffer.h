#ifndef CLEARBLUE_GRAPHDIFFER_H
#define CLEARBLUE_GRAPHDIFFER_H

#include "EnhancedSEG.h"
#include "UtilsHelper.h"

using namespace llvm;
using namespace std;

struct seg_patch_cmp {
  LLVMValueIndexer *instance;
  seg_patch_cmp() : instance(LLVMValueIndexer::get()) {}

  bool operator()(const SEGObject *A, const SEGObject *B) const {
    if (!A || !B) {
      // Handle null pointers explicitly
      return A < B;
    }
    StringRef funcSEGA = "";
    StringRef funcSEGB = "";
    if (A && A->getParentGraph() && A->getParentGraph()->getBaseFunc() &&
        A->getParentGraph()->getBaseFunc()->hasName()) {
      funcSEGA = A->getParentGraph()->getBaseFunc()->getName();
    }
    if (B && B->getParentGraph() && B->getParentGraph()->getBaseFunc() &&
        B->getParentGraph()->getBaseFunc()->hasName()) {
      funcSEGB = B->getParentGraph()->getBaseFunc()->getName();
    }

    if (funcSEGA != funcSEGB) {
      return funcSEGA < funcSEGB;
    } else {
      int indexSEGA = A ? A->getSEGIndex() : -1;
      int indexSEGB = B ? B->getSEGIndex() : -1;
      if (indexSEGA != indexSEGB || (indexSEGA == -1 && indexSEGB == -1)) {
        return indexSEGA < indexSEGB;
      } else {
        int indexA = A ? A->getObjIndex() : -1;
        int indexB = B ? B->getObjIndex() : -1;
        return indexA < indexB;
      }
    }
  }
};

class GraphDiffer {

  set<SEGNodeBase *> addedSEGNodes;
  set<SEGNodeBase *> removedSEGNodes;

  map<SEGObject *, SEGObject *, seg_patch_cmp> matchedNodesBefore;
  map<SEGObject *, SEGObject *, seg_patch_cmp> matchedNodesAfter;

  set<EnhancedSEGTrace *> beforeIntraTraces;
  set<EnhancedSEGTrace *> afterIntraTraces;

  set<EnhancedSEGTrace *> addedIntraTraces;
  set<EnhancedSEGTrace *> removedIntraTraces;
  map<EnhancedSEGTrace *, EnhancedSEGTrace *> unchangedIntraTraces;

  map<ConditionNode *, set<ConditionNode *>> matchedConditions;
  map<ConditionNode *, set<ConditionNode *>> matchedConditionSMTs;

  map<pair<ConditionNode *, ConditionNode *>, SMTSolver::SMTResultType>
      condPairFeasibility;

  int matchedConditionsNum = 0;

  void computePeerFuncs(string fileName);

  bool isTwoEnhancedTraceMatch(EnhancedSEGTrace *trace1,
                               EnhancedSEGTrace *trace2);

  bool isTwoSEGTraceMatched(SEGTraceWithBB &trace1, SEGTraceWithBB &trace2);

  bool isTwoIONodeMatched(EnhancedSEGTrace *trace1, EnhancedSEGTrace *trace2);

  bool isTwoSEGTraceMatchedWithoutPhi(const vector<SEGObject *> &trace1,
                                      const vector<SEGObject *> &trace2);

  bool isTwoSEGTraceMatchedWithPhi(const vector<SEGObject *> &trace1,
                                   const vector<SEGObject *> &trace2);
  bool isTwoConditionMatched(ConditionNode *cond1, ConditionNode *cond2);

  bool isTwoConditionMatchedFast(ConditionNode *cond1, ConditionNode *cond2);

  bool isTwoConditionSubMatched(ConditionNode *cond1, ConditionNode *cond2);

  bool isTwoConditionMatchedSMT(ConditionNode *cond1, ConditionNode *cond2);

  void findHasSubTree(ConditionNode *cond1, ConditionNode *cond2,
                      map<ConditionNode *, ConditionNode *> &matchedSubTree,
                      map<ConditionNode *, ConditionNode *> &subMatchedSubTree);

  void findIfCond2SubTreeCond1(
      ConditionNode *cond1, ConditionNode *cond2, vector<NodeType> pathCond2,
      map<ConditionNode *, ConditionNode *> &matchedSubTree,
      map<ConditionNode *, ConditionNode *> &subMatchedSubTree);

  bool isTwoFlowOrderMatched(EnhancedSEGTrace *trace1,
                             EnhancedSEGTrace *trace2);

  void matchABSEGNodes(set<Value *> &addedValues, set<Value *> &removedValues);

  void obtainIntraSlicing();

  set<SEGNodeBase *> processedBeforeNodes, processedAfterNodes;
  set<const SymbolicExprGraph *> beforeGraphs, afterGraphs;

  void obtainIntraSlicingStage1(set<SEGTraceWithBB> &intraSEGTracesBefore,
                                set<SEGTraceWithBB> &intraSEGTracesAfter);

  void obtainIntraSlicingStage2(set<SEGTraceWithBB> &intraSEGTracesBefore,
                                set<SEGTraceWithBB> &intraSEGTracesAfter);

  void obtainIntraSlicingStage3(set<SEGTraceWithBB> &intraSEGTracesBefore,
                                set<SEGTraceWithBB> &intraSEGTracesAfter);

  void classifyInterEnhancedTraces(set<EnhancedSEGTrace *> &beforeInterTraces,
                                   set<EnhancedSEGTrace *> &afterInterTraces);

  void diffABIntraTraces();

  void intra2InterTraces();

public:
  EnhancedSEGWrapper *SEGWrapper;

  SymbolicExprGraphSolver *SEGSolver;

  // (S-, _)
  set<EnhancedSEGTrace *> addedInterTraces;
  // (_, S+)
  set<EnhancedSEGTrace *> removedInterTraces;
  // (S-, S+)_cond
  map<EnhancedSEGTrace *, EnhancedSEGTrace *> changedCondInterTraces;
  // (S-, S+)_ord
  map<EnhancedSEGTrace *, EnhancedSEGTrace *> changedOrderInterTraces;

  GraphDiffer(EnhancedSEGWrapper *SEGWrapper,
              SymbolicExprGraphSolver *pSEGSolver);

  void loadPeerFuncLines(string peerLine);

  void parseValueFlowChanges(set<Value *> &addedValues,
                             set<Value *> &removedValues);

  void diffTwoPathCondNum(map<Instruction *, CDType> &cond1,
                          map<Instruction *, CDType> &cond2,
                          map<Instruction *, CDType> &diff);

  ConditionNode *diffTwoConditions(ConditionNode *cond1, ConditionNode *cond2);

  void diffTwoConditionSEGNodes(ConditionNode *condMap1,
                                ConditionNode *condMap2,
                                set<SEGNodeBase *> &diffCondNodes);

  map<OutputNode *, pair<int, int>>
  diffTwoOrder(map<OutputNode *, int> &order1, map<OutputNode *, int> &order2);

  bool isPeerFunc(string name1, string name2);

  void getPeerFuncs(Function *indirect, vector<Function *> &results);

  bool isOrderMatched(vector<int> &originalOrders,
                      vector<shared_ptr<VulnerabilityTrace>> &traces);
  // peerFunctions
  map<string, set<string>> func2PeerFuncs;
};

#endif // CLEARBLUE_GRAPHDIFFER_H
