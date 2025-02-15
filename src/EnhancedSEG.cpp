#include "EnhancedSEG.h"
#include "ConditionNode.h"
#include "ValueHelper.h"
#include <IR/ConstantsContext.h>
#include <algorithm>
#include <regex>

EnhancedSEGWrapper::EnhancedSEGWrapper(
    Module *pM, SymbolicExprGraphBuilder *pSEGBuilder,
    SymbolicExprGraphSolver *pSEGSolver, DebugInfoAnalysis *pDIA,
    CBCallGraph *pCBCG, ControlDependenceAnalysis *pCDGs,
    CFGReachabilityAnalysis *pCRA, DomTreePass *pDT) {

  M = pM;
  SEGBuilder = pSEGBuilder;
  SEGSolver = pSEGSolver;
  CBCG = pCBCG;
  DIA = pDIA;
  CRA = pCRA;
  CDGs = pCDGs;
  DT = pDT;

  computeCallGraph();

  // compute indirect call in call graph
  computeIndirectCall();
}

// one inst to more than one nodes?
void EnhancedSEGWrapper::value2EnhancedSEGNode(set<Value *> &values,
                                               set<SEGNodeBase *> &nodes) {

  for (auto value : values) {
    if (auto *inst = dyn_cast<Instruction>(value)) {
      Function *curFunc = inst->getParent()->getParent();
      SymbolicExprGraph *SEG = SEGBuilder->getSymbolicExprGraph(curFunc);
      if (!SEG) {
        continue;
      }

      if (auto *ret = dyn_cast<ReturnInst>(inst)) {
        auto *ret_value = ret->getReturnValue();
        if (!ret_value) {
          continue;
        }
        if (isa<ConstantInt>(ret_value)) {
          continue;
        }
        if (SEG->findNode(ret_value)) {
          nodes.insert(SEG->findNode(ret_value));
        }
      } else if (auto *store = dyn_cast<StoreInst>(inst)) {
        // TODO: process store instruction
      } else if (auto *load = dyn_cast<LoadInst>(inst)) {
        SEGOperandNode *node = SEG->findNode(load);
        nodes.insert(node); // push loadMemNode instead of operandNode
      } else {
        // TODO: pseudo input or psuedo output?
        if (SEG->findNode(value)) {
          nodes.insert(SEG->findNode(value));
        }
      }
    } else if (auto *argument = dyn_cast<Argument>(value)) {
      Function *curFunc = argument->getParent();
      SymbolicExprGraph *SEG = SEGBuilder->getSymbolicExprGraph(curFunc);
      if (!SEG) {
        continue;
      }
      if (SEG->findNode(argument)) {
        nodes.insert(SEG->findNode(argument));
      }
    } else if (auto *func = dyn_cast<Function>(value)) {
      continue;
    } else if (auto *metadata = dyn_cast<MetadataAsValue>(value)) {
      if (auto *metaValue =
              dyn_cast<ValueAsMetadata>(metadata->getMetadata())->getValue()) {
        set<Value *> strippedValue;
        strippedValue.insert(metaValue);
        value2EnhancedSEGNode(strippedValue, nodes);
      }
    } else {
      set<Function *> usedFuncs;
      findValueEnClosedFunc(value, usedFuncs);
      for (auto cur_func : usedFuncs) {
        SymbolicExprGraph *SEG = SEGBuilder->getSymbolicExprGraph(cur_func);
        if (!SEG) {
          continue;
        }
        if (SEG->findNode(value)) {
          nodes.insert(SEG->findNode(value));
        }
      }
    }
  }
}

void EnhancedSEGWrapper::obtainIntraEnhancedSlicing(
    set<SEGTraceWithBB> intraSEGTraces, set<EnhancedSEGTrace *> &intraTraces) {
  for (auto segTrace : intraSEGTraces) {

    set<InputNode *> inputNodes;
    canFindInput(segTrace.trace, inputNodes, true);

    set<OutputNode *> outputNodes;
    canFindOutput(segTrace.trace, outputNodes, false, true);
    if (inputNodes.empty() || outputNodes.empty()) {
      continue;
    }
    for (auto inputNode : inputNodes) {
      for (auto outputNode : outputNodes) {
        if (!inputNode || !outputNode ||
            !ifInOutputMatch(inputNode, outputNode)) {
          continue;
        }

        long start_idx = find(segTrace.trace.begin(), segTrace.trace.end(),
                              inputNode->usedNode) -
                         segTrace.trace.begin();
        long end_idx = find(segTrace.trace.begin(), segTrace.trace.end(),
                            outputNode->usedNode) -
                       segTrace.trace.begin();
        vector<SEGObject *> sub_trace(segTrace.trace.begin() + start_idx,
                                      segTrace.trace.begin() + end_idx + 1);

        vector<BasicBlock *> curbbOnTraces;
        vector<vector<BasicBlock *>> bbOnTracesPaths;
        collectRelatedBBs(sub_trace, 0, curbbOnTraces, bbOnTracesPaths);

        for (auto relatedBBs : bbOnTracesPaths) {
          auto *enhancedTrace = new EnhancedSEGTrace(sub_trace, relatedBBs);
          enhancedTrace->input_node = inputNode;
          enhancedTrace->output_node = outputNode;

          auto start = chrono::high_resolution_clock::now();
          collectConditions(enhancedTrace);
          auto stop = chrono::high_resolution_clock::now();
          auto duration =
              chrono::duration_cast<std::chrono::microseconds>(stop - start);
          collect_condition_time += duration.count();

          bool found_exist = false;
          for (auto cur_item : intraTraces) {
            if (isTwoEnhancedTraceEq(enhancedTrace, cur_item)) {
              found_exist = true;
              break;
            }
          }
          if (!found_exist) {
            intraTraces.insert(enhancedTrace);
          }
        }
      }
    }
  }
  DEBUG_WITH_TYPE("time", dbgs() << "Time for intra slicing: "
                                 << collect_traces_time / 1000 << "ms\n");
  DEBUG_WITH_TYPE("time", dbgs() << "Time for condition collection: "
                                 << collect_condition_time / 1000 << "ms\n");
}

bool EnhancedSEGWrapper::isTwoEnhancedTraceEq(EnhancedSEGTrace *trace1,
                                              EnhancedSEGTrace *trace2) {
  if (trace1->trace.trace != trace2->trace.trace) {
    return false;
  }
  if (trace1->trace.bbs != trace2->trace.bbs) {
    return false;
  }
  if (!isTwoIONodeEqual(trace1, trace2)) {
    return false;
  }
  if (!isTwoConditionEqual(trace1->conditions, trace2->conditions)) {
    return false;
  }
  return true;
}

bool EnhancedSEGWrapper::isTwoIONodeEqual(EnhancedSEGTrace *trace1,
                                          EnhancedSEGTrace *trace2) {
  if (trace1->input_node->usedNode != trace2->input_node->usedNode) {
    return false;
  }
  if (trace1->input_node->usedSite != trace2->input_node->usedSite) {
    return false;
  }
  if (trace1->output_node->usedNode != trace2->output_node->usedNode) {
    return false;
  }
  if (trace1->output_node->usedSite != trace2->output_node->usedSite) {
    return false;
  }
  return true;
}

bool EnhancedSEGWrapper::isTwoConditionEqual(ConditionNode *cond1,
                                             ConditionNode *cond2) {
  if (cond1->type != cond2->type)
    return false;
  if ((cond1->value == nullptr) ^ (cond2->value == nullptr))
    return false;

  if (cond1->value != nullptr && cond2->value != nullptr) {
    if (cond1->value == cond2->value) {
      return true;
    } else {
      return false;
    }
  }
  if (cond1->children.size() != cond2->children.size())
    return false;

  set<ConditionNode *> matchedCondNodes;
  for (auto i : cond1->children) {
    bool find_match = false;
    for (auto j : cond2->children) {
      if (matchedCondNodes.find(j) != matchedCondNodes.end()) {
        continue;
      }
      if (isTwoConditionEqual(i, j)) {
        matchedCondNodes.insert(j);
        find_match = true;
        break;
      }
    }
    if (!find_match) {
      return false;
    }
  }
  return true;
}

// collect related BBs on seg trace
void EnhancedSEGWrapper::collectRelatedBBs(
    vector<SEGObject *> &trace, int index, vector<BasicBlock *> &curbbOnTraces,
    vector<vector<BasicBlock *>> &bbOnTracesPaths) {
  if (index >= trace.size()) {
    bbOnTracesPaths.push_back(curbbOnTraces);
    return;
  }
  if (auto *storeNode = dyn_cast<SEGStoreMemNode>(trace[index])) {
    if (storeNode->getStoreSiteAsStoreInst()) {
      auto ins = storeNode->getStoreSiteAsStoreInst();
      if (curbbOnTraces.empty() || curbbOnTraces.back() != ins->getParent()) {
        curbbOnTraces.push_back(ins->getParent());
        collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
        curbbOnTraces.pop_back();
        return;
      }
    }
  } else if (auto *loadNode = dyn_cast<SEGLoadMemNode>(trace[index])) {
    //    dumpVector(trace);
    //    for (auto node: loadNode->children()) {
    //      if (loadNode->getMatchingCondition(node)) {
    //        DEBUG_WITH_TYPE("condition",  dbgs() <<
    //        *loadNode->getMatchingCondition(node) << "\n");
    //      }
    //    }
    //    for (auto it = loadNode->use_site_begin(); it !=
    //    loadNode->use_site_end(); it++) {
    //      DEBUG_WITH_TYPE("condition",  dbgs() << **it << "\n");
    //    }
  } else if (auto *pseudoInputNode =
                 dyn_cast<SEGCallSitePseudoInputNode>(trace[index])) {
    auto ins = pseudoInputNode->getCallSite().getInstruction();
    if (curbbOnTraces.empty() || curbbOnTraces.back() != ins->getParent()) {
      curbbOnTraces.push_back(ins->getParent());
      collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
      curbbOnTraces.pop_back();
      return;
    }
  } else if (auto *outputNode = dyn_cast<SEGCallSiteOutputNode>(trace[index])) {
    auto ins = outputNode->getCallSite()->getInstruction();
    if (curbbOnTraces.empty() || curbbOnTraces.back() != ins->getParent()) {
      curbbOnTraces.push_back(ins->getParent());
      collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
      curbbOnTraces.pop_back();
      return;
    }
  } else if (auto *argNode = dyn_cast<SEGArgumentNode>(trace[index])) {
    if (curbbOnTraces.empty() ||
        curbbOnTraces.back() !=
            &argNode->getParentGraph()->getBaseFunc()->getEntryBlock()) {
      curbbOnTraces.push_back(
          &argNode->getParentGraph()->getBaseFunc()->getEntryBlock());
      collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
      curbbOnTraces.pop_back();
      return;
    }
  } else if (trace[index]->getLLVMDbgValue()) {
    if (auto *ins = dyn_cast<Instruction>(trace[index]->getLLVMDbgValue())) {
      if (!isa<GetElementPtrInst>(ins) &&
          !isa<LoadInst>(ins)) { // load and gep inst would incur noise
        if (curbbOnTraces.empty() || curbbOnTraces.back() != ins->getParent()) {
          curbbOnTraces.push_back(ins->getParent());
          collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
          curbbOnTraces.pop_back();
          return;
        }
      }
    } else if (isa<ConstantInt>(trace[index]->getLLVMDbgValue()) &&
               (index + 1) < trace.size() &&
               isa<SEGPhiNode>(trace[index + 1])) {
      // correct phi node
      auto *phiNode = dyn_cast<SEGPhiNode>(trace[index + 1]);
      for (const auto &it : *phiNode) {
        if (it.ValNode == trace[index] && it.ValNode->getLLVMDbgValue() &&
            isa<Constant>(it.ValNode->getLLVMDbgValue())) {
          trace[index]->setParentBasicBlock(it.BB);
        }
      }
      if (curbbOnTraces.empty() ||
          curbbOnTraces.back() != trace[index]->getParentBasicBlock()) {
        curbbOnTraces.push_back(trace[index]->getParentBasicBlock());
        collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
        curbbOnTraces.pop_back();
        return;
      }
    } else if (0 <= index - 1 && index - 1 < trace.size() &&
               isa<SEGPhiNode>(trace[index])) {
      auto *phiNode = dyn_cast<SEGPhiNode>(trace[index]);
      for (const auto &it : *phiNode) {
        if (it.ValNode == trace[index - 1]) {
          if (it.BB) {
            if (curbbOnTraces.empty() || curbbOnTraces.back() != it.BB) {
              curbbOnTraces.push_back(it.BB);
              collectRelatedBBs(trace, index + 1, curbbOnTraces,
                                bbOnTracesPaths);
              curbbOnTraces.pop_back();
              return;
            }
          }
        }
      }
    }
  }
  collectRelatedBBs(trace, index + 1, curbbOnTraces, bbOnTracesPaths);
}

void EnhancedSEGWrapper::collectPathToEntryOnCFG(
    BasicBlock *startBB, BasicBlock *endBB,
    set<pair<BasicBlock *, CDType>> &visitedBBs,
    vector<pair<BasicBlock *, CDType>> &curPath,
    set<vector<pair<BasicBlock *, CDType>>> &totalPath) {
  ControlDependenceGraph &CDG = *(*CDGs)[startBB->getParent()];
  if (!CRA->isBBReachable(startBB, endBB) && startBB != endBB) {
    return;
  }
  if (startBB == endBB) {
    if (totalPath.find(curPath) == totalPath.end()) {
      totalPath.insert(curPath);
    }
    return;
  }
  CDType type = CDG.controls(startBB, endBB);
  if (type != CDType::DepNone) {
    visitedBBs.insert({startBB, type});
    curPath.push_back({startBB, type});
  }

  for (auto nextBB = succ_begin(startBB); nextBB != succ_end(startBB);
       nextBB++) {
    collectPathToEntryOnCFG(*nextBB, endBB, visitedBBs, curPath, totalPath);
  }
  if (type != CDType::DepNone) {
    visitedBBs.erase({startBB, type});
    curPath.pop_back();
  }
}

void EnhancedSEGWrapper::collectPathToEntryOnCDG(
    BasicBlock *startBB, BasicBlock *endBB,
    set<pair<BasicBlock *, CDType>> &visitedBBs,
    vector<pair<BasicBlock *, CDType>> &curPath,
    set<vector<pair<BasicBlock *, CDType>>> &totalPaths) {

  if (startBB == endBB) {
    totalPaths.insert(curPath);
    return;
  }

  ControlDependenceGraph &CDG = *(*CDGs)[startBB->getParent()];
  kvec<kpair<CDType, BasicBlock *>> CDeps;

  int NumDeps = CDG.get_dependents(endBB, CDeps);
  if (!NumDeps && !curPath.empty()) {
    totalPaths.insert(curPath);
    return;
  }

  int noneEmptyDeps = 0;
  for (int Index = 0; Index < NumDeps; ++Index) {
    BasicBlock *CDBB = CDeps[Index].second;
    auto type = CDeps[Index].first;

    if (!CDBB) {
      continue;
    }

    if (!CRA->isBBReachable(startBB, CDBB) && startBB != CDBB) {
      continue;
    }

    if (visitedBBs.find({CDBB, type}) != visitedBBs.end()) {
      continue;
    }
    noneEmptyDeps += 1;

    visitedBBs.insert({CDBB, type});
    curPath.push_back({CDBB, type});
    collectPathToEntryOnCDG(startBB, CDBB, visitedBBs, curPath, totalPaths);
    curPath.pop_back();
    visitedBBs.erase({CDBB, type});
  }

  if (!noneEmptyDeps && !curPath.empty()) {
    totalPaths.insert(curPath);
    return;
  }
}

template <typename T>
std::vector<T> concatenate(const std::vector<T> &v1, const std::vector<T> &v2) {
  std::vector<T> result = v1; // Start with all elements from v1
  result.insert(result.end(), v2.begin(),
                v2.end()); // Append all elements from v2
  return result;
}

void EnhancedSEGWrapper::collectBBsToEntry(
    EnhancedSEGTrace *trace,
    set<vector<pair<BasicBlock *, CDType>>> &totalCFGPaths) {

  auto bbOnTraces = trace->trace.bbs;
  if (trace->output_node->usedNode->getParentBasicBlock() ==
      trace->output_node->usedSite->getParentBasicBlock()) {
    bbOnTraces.push_back(trace->output_node->usedSite->getParentBasicBlock());
  }

  if (bbOnTraces.empty()) {
    return;
  }

  DEBUG_WITH_TYPE("condition", dbgs() << "Related bb in trace:\n");
  for (auto bb : bbOnTraces) {
    DEBUG_WITH_TYPE("condition", dbgs() << bb->getName() << " ");
  }
  DEBUG_WITH_TYPE("condition", dbgs() << "\n");
  vector<vector<pair<BasicBlock *, CDType>>> totalPathsSegments;
  BasicBlock *startBB = bbOnTraces.front();

  for (auto bb : bbOnTraces) {
    if (startBB == bb) {
      continue;
    }

    pair<BasicBlock *, BasicBlock *> startEndBB = {startBB, bb};
    set<vector<pair<BasicBlock *, CDType>>> totalPathsN;

    if (startEndBBsToPaths.find(startEndBB) != startEndBBsToPaths.end()) {
      totalPathsN.insert(startEndBBsToPaths[startEndBB].begin(),
                         startEndBBsToPaths[startEndBB].end());
    } else {
      set<pair<BasicBlock *, CDType>> visitedBBs;
      vector<pair<BasicBlock *, CDType>> curPath;
      collectPathToEntryOnCDG(startBB, bb, visitedBBs, curPath, totalPathsN);
      startEndBBsToPaths.insert({startEndBB, totalPathsN});
    }

    // for every two basic block, collect if conditions
    DEBUG_WITH_TYPE("condition", dbgs() << "Collect on CDG from "
                                        << startBB->getName() << " to "
                                        << bb->getName() << "\n");
    for (const auto &curPath : totalPathsN) {
      for (auto cur_bb : curPath) {
        DEBUG_WITH_TYPE("condition", dbgs() << cur_bb.first->getName() << " "
                                            << cur_bb.second << " ");
      }
      DEBUG_WITH_TYPE("condition", dbgs() << "\n");
    }
    DEBUG_WITH_TYPE("condition", dbgs() << "End Collect on CDG from "
                                        << startBB->getName() << " to "
                                        << bb->getName() << "\n\n");

    if (totalPathsN.empty()) {
      totalPathsN.clear();
      set<pair<BasicBlock *, CDType>> visitedBBs;
      vector<pair<BasicBlock *, CDType>> curPath;
      collectPathToEntryOnCFG(startBB, bb, visitedBBs, curPath, totalPathsN);
      DEBUG_WITH_TYPE("condition", dbgs() << "Collect on CFG from "
                                          << startBB->getName() << " to "
                                          << bb->getName() << "\n");
      for (const auto &cfgPath : totalPathsN) {
        for (auto cur_bb : cfgPath) {
          DEBUG_WITH_TYPE("condition", dbgs() << cur_bb.first->getName() << " "
                                              << cur_bb.second << " ");
        }
        DEBUG_WITH_TYPE("condition", dbgs() << "\n");
      }
      DEBUG_WITH_TYPE("condition", dbgs() << "End Collect on CFG from "
                                          << startBB->getName() << " to "
                                          << bb->getName() << "\n\n");
    }

    startBB = bb;

    // concatenate all sub paths between every two basic blocks
    if (totalPathsSegments.empty()) {
      totalPathsSegments.insert(totalPathsSegments.end(), totalPathsN.begin(),
                                totalPathsN.end());
    } else {
      vector<vector<pair<BasicBlock *, CDType>>> concatenatedPairs;
      for (const auto &l1 : totalPathsSegments) {
        for (const auto &l2 : totalPathsN) {
          concatenatedPairs.push_back(concatenate(l2, l1));
        }
      }
      totalPathsSegments = concatenatedPairs;
    }
  }
  totalCFGPaths.insert(totalPathsSegments.begin(), totalPathsSegments.end());

  DEBUG_WITH_TYPE("condition", dbgs() << "======Final BB Paths\n");
  for (const auto &curPath : totalCFGPaths) {
    for (auto bb : curPath) {
      DEBUG_WITH_TYPE("condition",
                      dbgs() << bb.first->getName() << " " << bb.second << " ");
    }
    DEBUG_WITH_TYPE("condition", dbgs() << "\n");
  }
  DEBUG_WITH_TYPE("condition", dbgs() << "======Finished\n");
}

void EnhancedSEGWrapper::dumpEnhancedTraceCond(const EnhancedSEGTrace *trace) {
  dbgs() << "[Input Node]: " << *trace->input_node->usedNode << "\n";
  if (trace->input_node->usedSite) {
    dbgs() << "[Input Site]: " << *trace->input_node->usedSite << "\n";
  }
  dbgs() << "[Output Node]: " << *trace->output_node->usedNode << "\n";
  if (trace->output_node->usedSite) {
    dbgs() << "[Output Site]: " << *trace->output_node->usedSite << "\n";
  }
  dbgs() << "\n";
  dbgs() << "[BBs]: ";
  for (auto bb : trace->trace.bbs) {
    dbgs() << " " << bb->getName();
  }
  dbgs() << "\n";
  dumpVectorDbg(trace->trace.trace);
}

// only collect constraint for intra slicing
void EnhancedSEGWrapper::collectConditions(EnhancedSEGTrace *enhanced_trace) {
  DEBUG_WITH_TYPE(
      "condition",
      dbgs() << "\n======Start Collect Condition for Trace======\n");

  auto vf_start = chrono::high_resolution_clock::now();
  // collect related basic blocks along the def-use chain
  set<vector<pair<BasicBlock *, CDType>>> totalCFGPaths;
  collectBBsToEntry(enhanced_trace, totalCFGPaths);
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_bb_path += vf_duration.count();
  DEBUG_WITH_TYPE("time", dbgs() << "Time for collect bb to entry: "
                                 << collect_bb_path / 1000 << "ms\n");

  vf_start = chrono::high_resolution_clock::now();
  // convert the BB path to condition node
  enhanced_trace->conditions = new ConditionNode(this, NODE_OR);
  for (const auto &path : totalCFGPaths) {
    if (!checkCurPathFeasibility(path)) {
      continue;
    }
    auto pathNode = path2IOCondition(path, enhanced_trace->trace.trace);
    if (!pathNode) {
      continue;
    }
    if (pathNode->type != NODE_CONST) {
      enhanced_trace->conditions->addChild(pathNode);
    }
  }
  vf_stop = chrono::high_resolution_clock::now();
  vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_whole_smt += vf_duration.count();
  DEBUG_WITH_TYPE("time", dbgs() << "Time for collect whole smt: "
                                 << collect_whole_smt / 1000 << "ms\n");
}

bool EnhancedSEGWrapper::checkCurPathFeasibility(
    vector<pair<BasicBlock *, CDType>> path) {
  if (feasibilityBBPaths.find(path) != feasibilityBBPaths.end()) {
    return feasibilityBBPaths[path] != SMTSolver::SMTRT_Unsat;
  }
  auto vf_start = chrono::high_resolution_clock::now();
  auto pathNode = new ConditionNode(this, NODE_AND);
  for (auto bbInfo : path) {
    TerminatorInst *CDTerminator = bbInfo.first->getTerminator();
    if (auto *brInst = dyn_cast<BranchInst>(CDTerminator)) {
      if (auto *icmpInst = dyn_cast<ICmpInst>(brInst->getCondition())) {
        auto curNode = new ConditionNode(
            this, SEGBuilder->getSymbolicExprGraph(bbInfo.first->getParent())
                      ->findNode(icmpInst));
        if (bbInfo.second == ControlDependenceGraph::DepFalse) {
          auto notNode = new ConditionNode(this, NODE_NOT);
          notNode->addChild(curNode);
          pathNode->addChild(notNode);
        } else {
          pathNode->addChild(curNode);
        }
      } else if (auto *biInst =
                     dyn_cast<BinaryOperator>(brInst->getCondition())) {
        DEBUG_WITH_TYPE("condition", dbgs() << "Binary Operator Instruction "
                                            << *biInst << "\n");
        vector<BinaryOperator *> worklist;
        vector<BinaryOperator::BinaryOps> opcodelist;
        ConditionNode *lastCondNode = nullptr;
        worklist.push_back(biInst);

        while (!worklist.empty()) {
          BinaryOperator *curBiInst = worklist.front();
          worklist.erase(worklist.begin());
          for (int i = 0; i < curBiInst->getNumOperands(); i++) {
            if (auto *newBiInst =
                    dyn_cast<BinaryOperator>(curBiInst->getOperand(i))) {
              worklist.push_back(newBiInst);
              opcodelist.push_back(biInst->getOpcode());
            } else if (auto *newIcmpInst =
                           dyn_cast<ICmpInst>(curBiInst->getOperand(i))) {
              lastCondNode = new ConditionNode(
                  this,
                  SEGBuilder->getSymbolicExprGraph(bbInfo.first->getParent())
                      ->findNode(icmpInst));
            }
          }
        }
      } else if (auto *callInst = dyn_cast<CallInst>(brInst->getCondition())) {
        if (callInst->getCalledFunction()->getName().equals(
                "llvm.is.constant.i64")) {
          continue;
        }
      } else {
        dbgs() << "!!!Unhandled Conditions " << *brInst->getCondition() << "\n";
      }
    } else {
      dbgs() << "!!!Unhandled Terminators " << *CDTerminator << "\n";
    }
  }
  // pruning infeasible paths
  auto smtDataExpr = condNode2SMTExprIntra(pathNode);
  SEGSolver->push();
  SEGSolver->add(smtDataExpr && pathNode->toSMTExpr(SEGSolver));
  auto checkRet = SEGSolver->check();
  SEGSolver->pop();

  feasibilityBBPaths.insert({path, checkRet});
  if (checkRet == SMTSolver::SMTRT_Unsat) {
    DEBUG_WITH_TYPE("condition", dbgs() << "Infeasible BB Path:\n");
    for (auto bb : path) {
      DEBUG_WITH_TYPE("condition",
                      dbgs() << bb.first->getName() << " " << bb.second << " ");
    }
    DEBUG_WITH_TYPE("condition", dbgs() << "\n\n");
  }
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  check_feasibile_time += vf_duration.count();
  return checkRet != SMTSolver::SMTRT_Unsat;
}

ConditionNode *
EnhancedSEGWrapper::path2IOCondition(vector<pair<BasicBlock *, CDType>> path,
                                     vector<SEGObject *> &guardedTrace) {
  auto pathNode = new ConditionNode(this, NODE_AND);
  auto vf_start = chrono::high_resolution_clock::now();

  for (auto bbInfo : path) {
    TerminatorInst *CDTerminator = bbInfo.first->getTerminator();
    if (auto *brInst = dyn_cast<BranchInst>(CDTerminator)) {
      if (auto *icmpInst = dyn_cast<ICmpInst>(brInst->getCondition())) {
        if (!checkifICMPIO(icmpInst, guardedTrace)) {
          continue;
        }
        auto curNode = new ConditionNode(
            this, SEGBuilder->getSymbolicExprGraph(bbInfo.first->getParent())
                      ->findNode(icmpInst));
        if (bbInfo.second == ControlDependenceGraph::DepFalse) {
          auto notNode = new ConditionNode(this, NODE_NOT);
          notNode->addChild(curNode);
          pathNode->addChild(notNode);
        } else {
          pathNode->addChild(curNode);
        }
      } else if (auto *biInst =
                     dyn_cast<BinaryOperator>(brInst->getCondition())) {
        vector<BinaryOperator *> worklist;
        vector<BinaryOperator::BinaryOps> opcodelist;
        ConditionNode *lastCondNode = nullptr;
        worklist.push_back(biInst);

        while (!worklist.empty()) {
          BinaryOperator *curBiInst = worklist.front();
          worklist.erase(worklist.begin());
          for (int i = 0; i < curBiInst->getNumOperands(); i++) {
            if (auto *newBiInst =
                    dyn_cast<BinaryOperator>(curBiInst->getOperand(i))) {
              worklist.push_back(newBiInst);
              opcodelist.push_back(biInst->getOpcode());
            } else if (auto *newIcmpInst =
                           dyn_cast<ICmpInst>(curBiInst->getOperand(i))) {
              if (!checkifICMPIO(newIcmpInst, guardedTrace)) {
                continue;
              }
              lastCondNode = new ConditionNode(
                  this,
                  SEGBuilder->getSymbolicExprGraph(bbInfo.first->getParent())
                      ->findNode(icmpInst));
            }
          }
        }
      } else if (auto *callInst = dyn_cast<CallInst>(brInst->getCondition())) {
        if (callInst->getCalledFunction()->getName().equals(
                "llvm.is.constant.i64")) {
          continue;
        }
      } else {
        dbgs() << "!!!Unhandled Conditions " << *brInst->getCondition() << "\n";
      }
    } else {
      dbgs() << "!!!Unhandled Terminators " << *CDTerminator << "\n";
    }
  }
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_trace_smt += vf_duration.count();

  if (pathNode->children.empty()) {
    return nullptr;
  }
  return pathNode;
}

bool EnhancedSEGWrapper::checkifICMPIO(ICmpInst *iCmpInst,
                                       vector<SEGObject *> &guardedTrace) {
  auto vf_start = chrono::high_resolution_clock::now();
  set<Value *> icmpValues = {iCmpInst};
  set<SEGNodeBase *> icmpNodes;
  set<SEGNodeBase *> invalidCondNode;
  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardTraces;

  value2EnhancedSEGNode(icmpValues, icmpNodes);
  condNode2FlowInter(icmpNodes, backwardTraces);

  for (auto &[icmpNode, traces] : backwardTraces) {

    if (traces.empty()) {
      invalidCondNode.insert(icmpNode);
      continue;
    }
    set<vector<SEGObject *>> invalidTraces;
    for (auto trace : traces) {
      if (trace.empty()) {
        invalidTraces.insert(trace);
        continue;
      }
      vector<SEGObject *> reversedTrace(trace.size());
      reverse_copy(trace.begin(), trace.end(), reversedTrace.begin());

      auto startNode = findFirstNode(reversedTrace);
      if (startNode->getLLVMDbgValue() &&
          isa<ConstantInt>(startNode->getLLVMDbgValue())) {
        invalidTraces.insert(trace);
      } else if (!isInputNode(startNode)) {
        invalidTraces.insert(trace);
      } else {
      }
    }
    if (invalidTraces.size() == traces.size()) {
      invalidCondNode.insert(icmpNode);
    }
  }

  //  if (invalidCondNode.size() == icmpNodes.size()) {
  //    outs() << "Not IO ICmp: ";
  //    printSourceCodeInfoWithValue(iCmpInst);
  //    outs() << *iCmpInst << "\n";
  //  }
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  check_whether_io += vf_duration.count();
  DEBUG_WITH_TYPE("time", dbgs() << "Time for I/O checking: "
                                 << check_whether_io / 1000 << "ms\n");
  return invalidCondNode.size() != icmpNodes.size();
}

void EnhancedSEGWrapper::canFindInput(vector<SEGObject *> trace,
                                      set<InputNode *> &inputNodes,
                                      bool intra) {
  if (trace.empty()) {
    return;
  }
  int startIndex = -1;
  SEGNodeBase *startNode = nullptr;
  for (int i = 0; i < trace.size(); i++) {
    if (auto *node = dyn_cast<SEGNodeBase>(trace[i])) {
      startNode = node;
      startIndex = i;
      break;
    }
  }
  if (startNode) {
    // verify if the parent function is peer function
    if (auto *argNode = dyn_cast<SEGArgumentNode>(startNode)) {
      auto func = argNode->getParentGraph()->getBaseFunc();
      if (intra || (!intra && isIndirectCall(func))) {
        string argName = "arg_";
        if (auto *argPseudoNode = dyn_cast<SEGPseudoArgumentNode>(startNode)) {
          for (auto i = 0;
               i < argNode->getParentGraph()->getNumCommonArgument(); i++) {
            if (argNode->getParentGraph()
                    ->getCommonArgument(i)
                    ->getLLVMValue() ==
                argPseudoNode->getAccessPath().get_base_ptr()) {
              argName += to_string(i);
              break;
            }
          }
          argName += ":";
          for (auto i = 0; i < argPseudoNode->getAccessPath().get_depth();
               i++) {
            argName += to_string(argPseudoNode->getAccessPath().get_offset(i));
            if (i != argPseudoNode->getAccessPath().get_depth() - 1) {
              argName += "_";
            }
          }
        } else if (auto *argComNode =
                       dyn_cast<SEGCommonArgumentNode>(argNode)) {
          for (auto i = 0;
               i < argNode->getParentGraph()->getNumCommonArgument(); i++) {
            if (argNode->getParentGraph()->getCommonArgument(i) == argComNode) {
              argName += to_string(i);
              break;
            }
          }
        }
        string pathFuncName =
            getCallSourceFile(func) + ":" + func->getName().str();
        auto input = new IndirectArgNode(pathFuncName, argName);
        input->usedNode = startNode;
        inputNodes.insert(input);
      }
    }

    else if (isa<SEGCallSiteOutputNode>(startNode)) {

    }
    // TODO: add arg of API as input
    else if (startNode->getLLVMDbgValue()) {
      auto value = startNode->getLLVMDbgValue();
      // verify if global variable
      if (isa<GlobalVariable>(value)) {
        auto input = new GlobalVarInNode(value->getName());
        input->usedNode = startNode;
        inputNodes.insert(input);
      }

      // if error code, verify if it is caused by API failure
      else if (auto *constNum = dyn_cast<ConstantInt>(value)) {
        if (!constNum->isZero() && trace.size() >= startIndex + 2) {
          if (auto *phiNode = dyn_cast<SEGPhiNode>(trace[startIndex + 1])) {
            set<ICmpInst *> icmpInsts;
            for (const auto &it : *phiNode) {
              if (it.ValNode == startNode) {
                findLastIcmp(it.BB, icmpInsts);
                for (auto ins : icmpInsts) {
                  set<InputNode *> errorInputs;
                  findErrorCodeInput(ins, errorInputs);
                  for (auto error : errorInputs) {
                    auto input =
                        new ErrorCodeNode(error, constNum->getSExtValue());
                    input->usedNode = startNode;
                    inputNodes.insert(input);
                  }
                }
              }
            }
          }
        }
      } else if (isa<CallInst>(value)) {

      } else if (auto *arg = dyn_cast<Argument>(value)) {
        // check if parent function is peer function, pseudo argument
        auto parent_func = startNode->getParentGraph()->getBaseFunc();
        if (intra || (!intra && isIndirectCall(parent_func))) {
          string pathFuncName = getCallSourceFile(parent_func) + ":" +
                                parent_func->getName().str();
          string argName = "arg_";
          bool found_arg = false;
          for (auto i = 0;
               i < startNode->getParentGraph()->getNumCommonArgument(); i++) {
            if (startNode->getParentGraph()
                    ->getCommonArgument(i)
                    ->getLLVMValue() == arg) {
              argName += to_string(i);
              found_arg = true;
              break;
            }
          }
          for (auto i = 0;
               i < startNode->getParentGraph()->getNumPseudoArgument(); i++) {
            if (startNode->getParentGraph()
                    ->getPseudoArgument(i)
                    ->getLLVMValue() == arg) {
              argName += to_string(i);
              argName += ":";
              auto argPseudoNode =
                  startNode->getParentGraph()->getPseudoArgument(i);
              for (auto j = 0; j < argPseudoNode->getAccessPath().get_depth();
                   i++) {
                argName +=
                    to_string(argPseudoNode->getAccessPath().get_offset(i));
                if (j != argPseudoNode->getAccessPath().get_depth() - 1) {
                  argName += "_";
                }
              }
              found_arg = true;
              break;
            }
          }
          if (!found_arg) {
            argName += arg->getName();
          }
          auto input = new IndirectArgNode(pathFuncName, argName);
          input->usedNode = startNode;
          inputNodes.insert(input);
        }
      } else if (isa<ConstantPointerNull>(value)) {
        if (startIndex + 1 < trace.size() &&
            isa<SEGOpcodeNode>(trace[startIndex + 1])) {
          // null used as icmp operand will be skipped
        }
      } else if (isa<AllocaInst>(value) || isa<PHINode>(value)) {

      } else {
        dbgs() << "!!!Not input start node: " << *startNode << "\n";
        dumpVectorDbg(trace);
      }
    }
  }

  for (auto node : trace) {
    if (!isa<SEGNodeBase>(node)) {
      continue;
    }

    auto *operandNode = dyn_cast<SEGNodeBase>(node);
    // if used in kernel-defined API
    for (auto it = operandNode->use_site_begin();
         it != operandNode->use_site_end(); it++) {
      // verify if the called function is API
      if (auto *csOutput = dyn_cast<SEGCallSiteOutputNode>(startNode)) {
        auto called = csOutput->getCallSite()->getCalledFunction();
        if (!called) {
          continue;
        }
        if (called->hasName() &&
            called->getName().equals("llvm.objectsize.i64.p0i8")) {
          continue;
        }
        if (intra || (!intra && isKernelOrCommonAPI(called->getName()))) {
          auto input = new ArgRetOfAPINode(called->getName(), -1);
          input->usedNode = startNode;
          input->usedSite = csOutput->getParentGraph()->findSite<SEGCallSite>(
              csOutput->getCallSite()->getLLVMDbgInstruction());
          inputNodes.insert(input);
        }
      } else if (operandNode->getLLVMDbgInstruction() &&
                 isa<CallInst>(operandNode->getLLVMDbgInstruction())) {
        auto called = cast<CallInst>(operandNode->getLLVMDbgInstruction())
                          ->getCalledFunction();
        if (called && called->hasName()) {
          // to refine
          if (called->getName().equals("llvm.objectsize.i64.p0i8")) {
            continue;
          }
          if (intra || (!intra && isKernelOrCommonAPI(called->getName()))) {
            auto input = new ArgRetOfAPINode(called->getName(), -1);
            input->usedNode = startNode;
            input->usedSite =
                startNode->getParentGraph()->findSite<SEGCallSite>(
                    operandNode->getLLVMDbgInstruction());
            inputNodes.insert(input);
          }
        }
      }
    }
  }
}

SMTExpr EnhancedSEGWrapper::condNode2SMTExprIntra(ConditionNode *condNode) {
  map<SEGNodeBase *, set<vector<SEGObject *>>> localCond2ValueFlows;
  condNode2FlowIntra(condNode->obtainNodes(), localCond2ValueFlows);
  return condDataDepToExpr(condNode, localCond2ValueFlows);
}

SMTExpr EnhancedSEGWrapper::condDataDepToExpr(
    ConditionNode *curNode,
    map<SEGNodeBase *, set<vector<SEGObject *>>> &cond2ValueFlows) {
  SMTExprVec dataDepExpr = SEGSolver->getSMTFactory().createEmptySMTExprVec();

  for (auto segNode : curNode->obtainNodes()) {
    SMTExprVec icmpVec = SEGSolver->getSMTFactory().createEmptySMTExprVec();
    for (auto opNode : segNode->Children.front()->Children) {
      SMTExprVec traceVec = SEGSolver->getSMTFactory().createEmptySMTExprVec();

      for (const auto &depTrace : cond2ValueFlows[opNode]) {
        SMTExprVec all = SEGSolver->getSMTFactory().createEmptySMTExprVec();
        vector<SEGNodeBase *> newDepTrace;
        for (auto node : depTrace) {
          if (auto *nodeBase = dyn_cast<SEGNodeBase>(node)) {
            newDepTrace.push_back(nodeBase);
          }
        }

        for (int i = newDepTrace.size() - 2; i >= 0; i--) {
          if (isa<SEGOperandNode>(newDepTrace[i])) {
            all.push_back(SEGSolver->getOrInsertExpr(newDepTrace[i]) ==
                          SEGSolver->getOrInsertExpr(newDepTrace[i + 1]));
          } else if (auto *NOpcode = dyn_cast<SEGOpcodeNode>(newDepTrace[i])) {
            all.push_back(SEGSolver->encodeOpcodeNode(NOpcode));
          }
        }

        SMTExpr bugConst = all.toAndExpr();
        traceVec.push_back(bugConst);
      }
      icmpVec.push_back(traceVec.toOrExpr());
    }

    auto *icmpOpNode = dyn_cast<SEGOpcodeNode>(segNode->Children.front());
    dataDepExpr.push_back(icmpVec.toAndExpr() &&
                          SEGSolver->encodeOpcodeNode(icmpOpNode) &&
                          SEGSolver->getOrInsertExpr(icmpOpNode) ==
                              SEGSolver->getOrInsertExpr(segNode));
  }
  return dataDepExpr.toAndExpr();
}

void EnhancedSEGWrapper::condNode2FlowInter(
    set<SEGNodeBase *> condNodes,
    map<SEGNodeBase *, set<vector<SEGObject *>>> &localCond2ValueFlows) {
  for (auto node : condNodes) { // and relation
    if (!isa<ICmpInst>(node->getLLVMDbgValue())) {
      continue;
    }
    if (cond2ValueFlowsInter.count(node)) {
      localCond2ValueFlows.insert({node, cond2ValueFlowsInter[node]});
      continue;
    }

    vector<SEGObject *> curTrace;
    set<vector<SEGObject *>> backwardTraces;

    vector<Function *> curCallTrace;
    auto curFunc = node->getParentGraph()->getBaseFunc();

    set<vector<Function *>> callTraces;
    funcCallUpperTracer(curFunc, curCallTrace, callTraces);

    for (auto callTrace : callTraces) {
      auto vf_start = chrono::high_resolution_clock::now();
      interValueFlowBackward(node, callTrace, curTrace, backwardTraces);
      auto vf_stop = chrono::high_resolution_clock::now();
      auto vf_duration =
          chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
      collect_inter_backward_time += vf_duration.count();
    }
    localCond2ValueFlows.insert({node, backwardTraces});
    cond2ValueFlowsInter.insert({node, backwardTraces});
  }
}

void EnhancedSEGWrapper::condNode2FlowIntra(
    set<SEGNodeBase *> condNodes,
    map<SEGNodeBase *, set<vector<SEGObject *>>> &localCond2ValueFlows) {

  for (auto node : condNodes) { // and relation
    if (!isa<ICmpInst>(node->getLLVMDbgValue())) {
      continue;
    }

    if (cond2ValueFlowsIntra.count(node)) {
      localCond2ValueFlows.insert({node, cond2ValueFlowsIntra[node]});
      continue;
    }
    vector<SEGObject *> curTrace;
    set<vector<SEGObject *>> backwardTraces;

    DEBUG_WITH_TYPE("time", dbgs() << "Backward for node: " << *node << "\n");
    auto vf_start = chrono::high_resolution_clock::now();
    intraValueFlowBackward(node, curTrace, backwardTraces);
    auto vf_stop = chrono::high_resolution_clock::now();
    auto vf_duration =
        chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
    collect_traces_time += vf_duration.count();
    DEBUG_WITH_TYPE("time", dbgs() << "Time for slicing at 547: "
                                   << collect_traces_time / 1000 << "ms\n");
    DEBUG_WITH_TYPE(
        "time", dbgs() << "Hit cache: " << count_obtain_backward_cache << "\n");
    cond2ValueFlowsIntra.insert({node, backwardTraces});
    localCond2ValueFlows.insert({node, backwardTraces});
  }
}

SMTExpr EnhancedSEGWrapper::condNode2SMTExprInter(ConditionNode *condNode) {
  map<SEGNodeBase *, set<vector<SEGObject *>>> localCond2ValueFlows;

  condNode2FlowInter(condNode->obtainNodes(), localCond2ValueFlows);
  return condDataDepToExpr(condNode, localCond2ValueFlows);
}

// here, we consider the case where p = q, p = not q, p => q or q => p
bool EnhancedSEGWrapper::isConditionAReduceB(ConditionNode *curCond,
                                             ConditionNode *otherCond) {
  if (cacheReducedAB.find({curCond, otherCond}) != cacheReducedAB.end()) {
    return true;
  }

  // todo: to be refined
  SEGNodeBase *icmpNode1, *icmpNode2;
  bool isTwoCondConverse = false;

  // fast version: only compare seg trace
  if (curCond->type == NODE_VAR && otherCond->type == NODE_VAR) {
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_VAR) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_VAR && otherCond->type == NODE_NOT) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->children[0]->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_NOT) {
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->children[0]->value;
  } else {
    return false;
  }
  if (!icmpNode1 || !icmpNode2) {
    return false;
  }

  auto llvmValue1 = icmpNode1->getLLVMDbgValue();
  auto llvmValue2 = icmpNode2->getLLVMDbgValue();

  if (!isa<ICmpInst>(llvmValue1) || !isa<ICmpInst>(llvmValue2)) {
    return false;
  }

  auto *curIcmp = dyn_cast<ICmpInst>(llvmValue1);
  auto *otherIcmp = dyn_cast<ICmpInst>(llvmValue2);

  auto curSEG =
      SEGBuilder->getSymbolicExprGraph(icmpNode1->getParentFunction());

  if (curSEG->findNode(otherIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(0)) &&
      isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                             curSEG->findNode(otherIcmp->getOperand(0)))) {
    if (isa<ConstantInt>(curIcmp->getOperand(1)) &&
        isa<ConstantInt>(otherIcmp->getOperand(1))) {
      auto *constVar1 = dyn_cast<ConstantInt>(curIcmp->getOperand(1));
      auto *constVar2 = dyn_cast<ConstantInt>(otherIcmp->getOperand(1));

      // TODO: refine reduce relationships
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (otherIcmp->getPredicate() == llvm::CmpInst::ICMP_EQ) {
          if (isTwoCondConverse) {
            // a == 1, not a == 2
            // or not a == 1, a == 2
            if (curCond->type != NODE_NOT) {
              DEBUG_WITH_TYPE("condition", dbgs() << "\n[1 Reduce 2 Const 1] "
                                                  << curCond->dump() << "\n");
              DEBUG_WITH_TYPE("condition", dbgs() << "[1 Reduce 2 Const 2] "
                                                  << otherCond->dump() << "\n");
              cacheReducedAB.insert({curCond, otherCond});
              return true;
            }
            return false;
          }
        }
      }
    }
  }

  auto smtDataExpr1 = condNode2SMTExprIntra(curCond);
  auto smtDataExpr2 = condNode2SMTExprIntra(otherCond);

  SEGSolver->push();
  SEGSolver->add(smtDataExpr1);
  SEGSolver->add(smtDataExpr2);
  SEGSolver->add(
      !(!curCond->toSMTExpr(SEGSolver) || otherCond->toSMTExpr(SEGSolver)));
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "Xor SMT String For Merge\n" <<
  //  SEGSolver->to_smt2() << "\n");
  auto checkRet = SEGSolver->check();

  SEGSolver->pop();
  if (checkRet == SMTSolver::SMTRT_Unsat) {
    DEBUG_WITH_TYPE("condition", dbgs() << "\n[1 Reduce 2 SMT 1] "
                                        << curCond->dump() << "\n");
    DEBUG_WITH_TYPE("condition", dbgs() << "[1 Reduce 2 SMT 2] "
                                        << otherCond->dump() << "\n");
    cacheReducedAB.insert({curCond, otherCond});
    return true;
  }
  return false;
}

bool EnhancedSEGWrapper::isConditionConflict(ConditionNode *curCond,
                                             ConditionNode *otherCond) {

  if (cacheConflictAB.find({curCond, otherCond}) != cacheConflictAB.end()) {
    return true;
  }

  SEGNodeBase *icmpNode1, *icmpNode2;
  bool isTwoCondConverse = false, isTwoCondSame = false;

  // fast version: only compare seg trace
  if (curCond->type == NODE_VAR && otherCond->type == NODE_VAR) {
    isTwoCondSame = true;
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_VAR) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_VAR && otherCond->type == NODE_NOT) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->children[0]->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_NOT) {
    isTwoCondSame = true;
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->children[0]->value;
  } else {
    return false;
  }

  if (!icmpNode1 || !icmpNode2) {
    return false;
  }

  auto llvmValue1 = icmpNode1->getLLVMDbgValue();
  auto llvmValue2 = icmpNode2->getLLVMDbgValue();

  if (llvmValue1 == llvmValue2) {
    return isTwoCondConverse;
  }

  if (!isa<ICmpInst>(llvmValue1) || !isa<ICmpInst>(llvmValue2)) {
    return false;
  }

  auto curIcmp = dyn_cast<ICmpInst>(llvmValue1);
  auto otherIcmp = dyn_cast<ICmpInst>(llvmValue2);

  auto curSEG =
      SEGBuilder->getSymbolicExprGraph(icmpNode1->getParentFunction());

  if (curSEG->findNode(otherIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(1)) &&
      curSEG->findNode(otherIcmp->getOperand(1)) &&

      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                              curSEG->findNode(otherIcmp->getOperand(0))) &&
      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                              curSEG->findNode(otherIcmp->getOperand(1))) &&
      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                              curSEG->findNode(otherIcmp->getOperand(1)))) {
    return false;
  }
  //
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "Verifying LLVM Value 1" <<
  //  *llvmValue1 << "\n"); DEBUG_WITH_TYPE("condition",  dbgs() << "Verifying
  //  LLVM Value 2" << *llvmValue2 << "\n");
  if (curSEG->findNode(otherIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(0)) &&
      isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                             curSEG->findNode(otherIcmp->getOperand(0)))) {

    if (curSEG->findNode(curIcmp->getOperand(1)) &&
        curSEG->findNode(otherIcmp->getOperand(1)) &&
        isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                               curSEG->findNode(otherIcmp->getOperand(1)))) {
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (isTwoCondConverse) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondConverse) {
          cacheConflictAB.insert({curCond, otherCond});
        }
        return isTwoCondConverse;
      } else if (otherIcmp->getPredicate() == curIcmp->getInversePredicate()) {
        if (isTwoCondSame) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondSame) {
          cacheConflictAB.insert({curCond, otherCond});
        }
        return isTwoCondSame;
      }
    } else if (isa<ConstantInt>(curIcmp->getOperand(1)) &&
               isa<ConstantInt>(otherIcmp->getOperand(1))) {
      auto *constVar1 = dyn_cast<ConstantInt>(curIcmp->getOperand(1));
      auto *constVar2 = dyn_cast<ConstantInt>(otherIcmp->getOperand(1));

      // TODO: refine reduce relationships
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (otherIcmp->getPredicate() == llvm::CmpInst::ICMP_EQ) {
          if (curCond->type == NODE_VAR && otherCond->type == NODE_VAR) {
            // a == 1, a == 2
            if (isTwoCondSame) {
              DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 Diff] "
                                                  << curCond->dump() << "\n");
              DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 Diff] "
                                                  << otherCond->dump() << "\n");
            }
            if (isTwoCondSame) {
              cacheConflictAB.insert({curCond, otherCond});
            }
            return isTwoCondSame;
          }
        }
      }
    }
  }

  if (curSEG->findNode(curIcmp->getOperand(0)) &&
      curSEG->findNode(otherIcmp->getOperand(1)) &&
      isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                             curSEG->findNode(otherIcmp->getOperand(1)))) {

    if (curSEG->findNode(curIcmp->getOperand(1)) &&
        curSEG->findNode(otherIcmp->getOperand(0)) &&
        isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                               curSEG->findNode(otherIcmp->getOperand(0)))) {
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (isTwoCondSame) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondSame) {
          cacheConflictAB.insert({curCond, otherCond});
        }
        return isTwoCondSame;
      } else if (otherIcmp->getPredicate() == curIcmp->getInversePredicate()) {
        if (isTwoCondConverse) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondConverse) {
          cacheConflictAB.insert({curCond, otherCond});
        }
        return isTwoCondConverse;
      }
    }
  }

  auto smtDataExpr1 = condNode2SMTExprIntra(curCond);
  auto smtDataExpr2 = condNode2SMTExprIntra(otherCond);

  SEGSolver->push();
  SEGSolver->add(smtDataExpr1 && smtDataExpr2 &&
                 curCond->toSMTExpr(SEGSolver) &&
                 otherCond->toSMTExpr(SEGSolver));
  auto checkRet = SEGSolver->check();
  SEGSolver->pop();
  if (checkRet == SMTSolver::SMTRT_Unsat) {
    DEBUG_WITH_TYPE("condition", dbgs() << "\n[Conflict Node 1 SMT] "
                                        << curCond->dump() << "\n");
    DEBUG_WITH_TYPE("condition", dbgs() << "[Conflict Node 2 SMT] "
                                        << otherCond->dump() << "\n");
    cacheConflictAB.insert({curCond, otherCond});
    return true;
  }
  return false;
}

// here, we consider the case where p = q, p = not q, p => q or q => p
bool EnhancedSEGWrapper::isConditionMerge(ConditionNode *curCond,
                                          ConditionNode *otherCond) {
  if (cacheMergeAB.find({curCond, otherCond}) != cacheMergeAB.end()) {
    return true;
  }

  // todo: to be refined
  SEGNodeBase *icmpNode1, *icmpNode2;
  bool isTwoCondConverse = false, isTwoCondSame = false;

  // fast version: only compare seg trace
  if (curCond->type == NODE_VAR && otherCond->type == NODE_VAR) {
    isTwoCondSame = true;
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_VAR) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->value;
  } else if (curCond->type == NODE_VAR && otherCond->type == NODE_NOT) {
    isTwoCondConverse = true;
    icmpNode1 = curCond->value;
    icmpNode2 = otherCond->children[0]->value;
  } else if (curCond->type == NODE_NOT && otherCond->type == NODE_NOT) {
    isTwoCondSame = true;
    icmpNode1 = curCond->children[0]->value;
    icmpNode2 = otherCond->children[0]->value;
  } else {
    return false;
  }

  if (!icmpNode1 || !icmpNode2) {
    return false;
  }

  auto llvmValue1 = icmpNode1->getLLVMDbgValue();
  auto llvmValue2 = icmpNode2->getLLVMDbgValue();

  if (llvmValue1 == llvmValue2) {
    return isTwoCondSame;
  }

  if (!isa<ICmpInst>(llvmValue1) || !isa<ICmpInst>(llvmValue2)) {
    return false;
  }

  auto *curIcmp = dyn_cast<ICmpInst>(llvmValue1);
  auto *otherIcmp = dyn_cast<ICmpInst>(llvmValue2);

  auto curSEG =
      SEGBuilder->getSymbolicExprGraph(icmpNode1->getParentFunction());

  if (curSEG->findNode(otherIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(1)) &&
      curSEG->findNode(otherIcmp->getOperand(1)) &&

      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                              curSEG->findNode(otherIcmp->getOperand(0))) &&
      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                              curSEG->findNode(otherIcmp->getOperand(1))) &&
      !isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                              curSEG->findNode(otherIcmp->getOperand(1)))) {
    return false;
  }

  if (curSEG->findNode(otherIcmp->getOperand(0)) &&
      curSEG->findNode(curIcmp->getOperand(0)) &&
      isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                             curSEG->findNode(otherIcmp->getOperand(0)))) {

    if (curSEG->findNode(curIcmp->getOperand(1)) &&
        curSEG->findNode(otherIcmp->getOperand(1)) &&
        isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                               curSEG->findNode(otherIcmp->getOperand(1)))) {
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (isTwoCondSame) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Merge Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Merge Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondSame) {
          cacheMergeAB.insert({curCond, otherCond});
        }
        return isTwoCondSame;

      } else if (otherIcmp->getPredicate() == curIcmp->getInversePredicate()) {
        if (isTwoCondConverse) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Merge Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Merge Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondConverse) {
          cacheMergeAB.insert({curCond, otherCond});
        }
        return isTwoCondConverse;
      }
    }
  }

  if (curSEG->findNode(curIcmp->getOperand(0)) &&
      curSEG->findNode(otherIcmp->getOperand(1)) &&
      isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(0)),
                             curSEG->findNode(otherIcmp->getOperand(1)))) {

    if (curSEG->findNode(curIcmp->getOperand(1)) &&
        curSEG->findNode(otherIcmp->getOperand(0)) &&
        isTwoSEGNodeValueEqual(curSEG->findNode(curIcmp->getOperand(1)),
                               curSEG->findNode(otherIcmp->getOperand(0)))) {
      if (otherIcmp->getPredicate() == curIcmp->getPredicate()) {
        if (isTwoCondConverse) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Merge Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Merge Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondConverse) {
          cacheMergeAB.insert({curCond, otherCond});
        }
        return isTwoCondConverse;
      } else if (otherIcmp->getPredicate() == curIcmp->getInversePredicate()) {
        if (isTwoCondSame) {
          DEBUG_WITH_TYPE("condition", dbgs() << "\n[Merge Node 1 Diff] "
                                              << curCond->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << "[Merge Node 2 Diff] "
                                              << otherCond->dump() << "\n");
        }
        if (isTwoCondSame) {
          cacheMergeAB.insert({curCond, otherCond});
        }
        return isTwoCondSame;
      }
    }
  }

  auto smtDataExpr1 = condNode2SMTExprIntra(curCond);
  auto smtDataExpr2 = condNode2SMTExprIntra(otherCond);

  SEGSolver->push();
  SEGSolver->add(smtDataExpr1);
  SEGSolver->add(smtDataExpr2);
  SEGSolver->add(curCond->toSMTExpr(SEGSolver) ^
                 otherCond->toSMTExpr(SEGSolver));
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "Xor SMT String For Merge\n" <<
  //  SEGSolver->to_smt2() << "\n");
  auto checkRet = SEGSolver->check();
  SEGSolver->pop();
  if (checkRet == SMTSolver::SMTRT_Unsat) {
    DEBUG_WITH_TYPE("condition", dbgs() << "\n[Merge Node 1 SMT] "
                                        << curCond->dump() << "\n");
    DEBUG_WITH_TYPE("condition", dbgs() << "[Merge Node 2 SMT] "
                                        << otherCond->dump() << "\n");
    cacheMergeAB.insert({curCond, otherCond});
    return true;
  }
  return false;
}

// the resulted intra slicing may be duplicated
void EnhancedSEGWrapper::intraValueFlow(SEGNodeBase *criterion,
                                        set<SEGTraceWithBB> &intraTraces) {
  vector<SEGObject *> curTrace;
  set<vector<SEGObject *>> forwardTraces, backwardTraces;

  auto vf_start = chrono::high_resolution_clock::now();
  intraValueFlowBackward(criterion, curTrace, backwardTraces);
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_backward_time += vf_duration.count();

  vf_start = chrono::high_resolution_clock::now();
  intraValueFlowForward(criterion, curTrace, forwardTraces);
  vf_stop = chrono::high_resolution_clock::now();
  vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_forward_time += vf_duration.count();

  vf_start = chrono::high_resolution_clock::now();
  //   dbgs() << "After intra, backward num: " << backwardTraces.size() << " "
  //   << *criterion << "\n"; dbgs() << "After intra, forward num: " <<
  //   forwardTraces.size() << " " << *criterion << "\n";
  for (auto forward : forwardTraces) {
    for (auto backward : backwardTraces) {
      reverse(backward.begin(), backward.end());
      vector<SEGObject *> biward(backward);
      if (forward.empty()) {
        continue;
      }
      biward.insert(biward.end(), forward.begin() + 1, forward.end());
      if (biward.empty()) {
        continue;
      }
      if (visitedTraces.count(biward)) {
        continue;
      }
      visitedTraces.insert(biward);
      vector<BasicBlock *> curbbOnTraces;
      vector<vector<BasicBlock *>> bbOnTracesPaths;
      collectRelatedBBs(biward, 0, curbbOnTraces, bbOnTracesPaths);
      for (auto relatedBBs : bbOnTracesPaths) {
        SEGTraceWithBB newtrace(biward, relatedBBs);
        intraTraces.insert(newtrace);
      }
    }
  }
  vf_stop = chrono::high_resolution_clock::now();
  vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  collect_concat_time += vf_duration.count();

  DEBUG_WITH_TYPE("time", dbgs() << "\nTime for forward slicing: "
                                 << collect_backward_time / 1000 << "ms\n");
  DEBUG_WITH_TYPE("time", dbgs() << "Time for backward slicing: "
                                 << collect_forward_time / 1000 << "ms\n");
  DEBUG_WITH_TYPE("time", dbgs() << "Time for concat slicing: "
                                 << collect_concat_time / 1000 << "ms\n");
  DEBUG_WITH_TYPE("time", dbgs() << "Forward trace: " << forwardTraces.size()
                                 << ", Bacward trace: " << backwardTraces.size()
                                 << "\n");
}

void EnhancedSEGWrapper::intraValueFlowBackward(
    SEGNodeBase *node, vector<SEGObject *> &curTrace,
    set<vector<SEGObject *>> &backwards) {
  if (find(curTrace.begin(), curTrace.end(), node) != curTrace.end()) {
    // cycle def-use
    return;
  }
  if (backwardIntraVisited.count(node)) {
    for (auto cachePath : backwardIntraVisited[node]) {
      count_obtain_backward_cache += 1;
      vector<SEGObject *> newPath(curTrace);
      newPath.insert(newPath.end(), cachePath.begin(), cachePath.end());
      backwards.insert(newPath);
    }
    return;
  }

  set<vector<SEGObject *>> localPaths;
  if (node->getLLVMDbgValue() && is_excopy_val(node->getLLVMDbgValue())) {
    backwards.insert(curTrace);
    vector<SEGObject *> emptyTrace;
    localPaths.insert(emptyTrace);
    backwardIntraVisited[node] = localPaths;
    return;
  }

  curTrace.push_back(node);
  if (node->getNumChildren() == 0) {
    localPaths.insert({node});
    backwards.insert(curTrace);
    backwardIntraVisited[node] = localPaths;
    curTrace.pop_back();
    return;
  }

  // fix Phi Node
  set<SEGNodeBase *> inComingValNoDup;
  if (auto *phiNode = dyn_cast<SEGPhiNode>(node)) {
    for (int i = 0; i < phiNode->size(); i++) {
      auto cur_incoming = phiNode->getIncomeNode(i)->ValNode;
      if (inComingValNoDup.count(cur_incoming)) {
        if (isa<ConstantInt>(cur_incoming->getLLVMDbgValue())) {
          auto newConstNode = new SEGSimpleOperandNode(
              cur_incoming,
              SEGBuilder->getSymbolicExprGraph(
                  phiNode->getIncomeNode(i)->BB->getParent()),
              false);
          for (int j = 0; j < phiNode->getNumChildren(); j++) {
            if (phiNode->getChild(j) == cur_incoming) {
              phiNode->Children[j] = newConstNode;
              break;
            }
          }
          phiNode->getIncomeNode(i)->ValNode = newConstNode;
          inComingValNoDup.insert(newConstNode);
        }
      } else {
        inComingValNoDup.insert(cur_incoming);
      }
    }
  }

  set<SEGNodeBase *> nodeDup;
  for (unsigned int i = 0; i < node->getNumChildren(); i++) {
    auto childNode = node->getChild(i);
    nodeDup.insert(childNode);
    // we do not track value flow from const as operand
    if (isa<SEGOpcodeNode>(node)) {
      if (childNode->getLLVMDbgValue()) {
        if (isa<ConstantPointerNull>(childNode->getLLVMDbgValue()) ||
            isa<ConstantInt>(childNode->getLLVMDbgValue())) {
          continue;
        }
      }
    }
    intraValueFlowBackward(childNode, curTrace, backwards);
    if (backwardIntraVisited.count(childNode)) {
      for (auto cachePath : backwardIntraVisited[childNode]) {
        vector<SEGObject *> newPath = {node};
        newPath.insert(newPath.end(), cachePath.begin(), cachePath.end());
        localPaths.insert(newPath);
      }
    }
  }

  backwardIntraVisited[node] = localPaths;
  curTrace.pop_back();
}

void EnhancedSEGWrapper::intraValueFlowForward(
    SEGNodeBase *node, vector<SEGObject *> &curTrace,
    set<vector<SEGObject *>> &forwards) {

  if (find(curTrace.begin(), curTrace.end(), node) != curTrace.end()) {
    // cycle def-use
    return;
  }

  if (forwardIntraVisited.count(node)) {
    for (auto cachePath : forwardIntraVisited[node]) {
      count_obtain_forward_cache += 1;
      vector<SEGObject *> newPath(curTrace);
      newPath.insert(newPath.end(), cachePath.begin(), cachePath.end());
      //      dbgs() << "\nVisit cache at 1547: " << *node << "\n";
      //      dbgs() << "cache path: \n";
      //      dumpVector(cachePath);
      //      dbgs() << "final path: \n";
      //      dumpVector(newPath);
      forwards.insert(newPath);
    }
    return;
  }

  set<vector<SEGObject *>> localPaths;
  if (node->getLLVMDbgValue() && is_excopy_val(node->getLLVMDbgValue())) {
    forwards.insert(curTrace);
    vector<SEGObject *> emptyTrace;
    localPaths.insert(emptyTrace);
    forwardIntraVisited[node] = localPaths;
    //    dbgs() << "\nCache for node at 1557: " << *node << "\n";
    //    for (auto x : localPaths) {
    //      dbgs() << "local path: \n";
    //      dumpVector(x);
    //    }
    return;
  }

  if (isa<SEGRegionNode>(node)) {
    forwards.insert(curTrace);
    vector<SEGObject *> emptyTrace;
    localPaths.insert(emptyTrace);
    forwardIntraVisited[node] = localPaths;
    //    dbgs() << "\nCache for node at 1569: " << *node << "\n";
    //    for (auto x : localPaths) {
    //      dbgs() << "local path: \n";
    //      dumpVector(x);
    //    }
    return;
  }

  curTrace.push_back(node);
  if (!node->getNumParents()) {
    localPaths.insert({node});
    forwards.insert(curTrace);
    forwardIntraVisited[node] = localPaths;
    //    dbgs() << "\nCache for node at 1582: " << *node << "\n";
    //    for (auto x : localPaths) {
    //      dbgs() << "local path: \n";
    //      dumpVector(x);
    //    }
    curTrace.pop_back();
    return;
  }

  set<SEGNodeBase *> nodeDup;
  for (auto It = node->parent_begin(); It != node->parent_end(); It++) {
    auto nextNode = (SEGNodeBase *)*It;
    nodeDup.insert(nextNode);
  }

  for (auto nextNode : nodeDup) {
    intraValueFlowForward(nextNode, curTrace, forwards);
    if (forwardIntraVisited.count(nextNode)) {
      for (auto cachePath : forwardIntraVisited[nextNode]) {
        vector<SEGObject *> newPath = {node};
        newPath.insert(newPath.end(), cachePath.begin(), cachePath.end());
        localPaths.insert(newPath);
      }
    }
  }
  forwardIntraVisited[node] = localPaths;
  //  dbgs() << "\nCache for node at 1607: " << *node << "\n";
  //  for (auto x : localPaths) {
  //    dbgs() << "local path: \n";
  //    dumpVector(x);
  //  }
  curTrace.pop_back();
}

// extend intra slicing to inter slicing
// TODO: check the stop critrion
void EnhancedSEGWrapper::obtainInterSlicing(
    EnhancedSEGTrace *intraTrace, set<EnhancedSEGTrace *> &interTraces) {

  if (intraTrace->trace.trace.empty()) {
    return;
  }

  auto startNode = intraTrace->trace.getFirstNode();
  auto endNode = intraTrace->trace.getLastNode();

  if (!startNode && !endNode) {
    return;
  }
  // find the node to start forward/backward slicing
  set<vector<SEGObject *>> forwardTraces, backwardTraces;
  auto curFunc = startNode->getParentGraph()->getBaseFunc();

  vector<SEGObject *> curTrace;
  vector<Function *> curCallTrace;
  set<vector<Function *>> callTraces;
  funcCallUpperTracer(curFunc, curCallTrace, callTraces);

  if (startNode && needBackward(startNode)) {
    // collect inter slicing along each call trace
    for (auto callTrace : callTraces) {
      auto vf_start = chrono::high_resolution_clock::now();
      interValueFlowBackward(startNode, callTrace, curTrace, backwardTraces);
      auto vf_stop = chrono::high_resolution_clock::now();
      auto vf_duration =
          chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
      collect_inter_backward_time += vf_duration.count();
    }
  }

  if (endNode && needForward(endNode)) {
    // collect inter slicing along each call trace
    for (auto callTrace : callTraces) {
      auto vf_start = chrono::high_resolution_clock::now();
      interValueFlowForward(endNode, callTrace, curTrace, forwardTraces);
      auto vf_stop = chrono::high_resolution_clock::now();
      auto vf_duration =
          chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
      collect_inter_forward_time += vf_duration.count();
    }
  }

  DEBUG_WITH_TYPE("time", dbgs()
                              << "Time for inter backward slicing: "
                              << collect_inter_backward_time / 1000 << "ms\n");
  DEBUG_WITH_TYPE("time", dbgs()
                              << "Time for inter forward slicing: "
                              << collect_inter_forward_time / 1000 << "ms\n");

  // transform intra enhanced trace to inter enhanced trace
  set<vector<SEGObject *>> interSEGTraces;
  if (!backwardTraces.empty() && !forwardTraces.empty()) {
    for (auto &interBackward : backwardTraces) {
      for (auto interForward : forwardTraces) {
        vector<SEGObject *> biward = interBackward;
        reverse(biward.begin(), biward.end());
        biward.insert(biward.end(), intraTrace->trace.trace.begin() + 1,
                      intraTrace->trace.trace.end());

        biward.insert(biward.end(), interForward.begin() + 1,
                      interForward.end());

        // recover condition and order information
        set<InputNode *> inputNodes;
        canFindInput(biward, inputNodes, false);

        set<OutputNode *> outputNodes;
        canFindOutput(biward, outputNodes, false, false);
        if (inputNodes.empty() || outputNodes.empty()) {
          continue;
        }

        for (auto input : inputNodes) {
          for (auto output : outputNodes) {
            if (!input || !output || !ifInOutputMatch(input, output)) {
              continue;
            }
            int start_idx =
                find(biward.begin(), biward.end(), input->usedNode) -
                biward.begin();
            int end_idx = find(biward.begin(), biward.end(), output->usedNode) -
                          biward.begin();
            vector<SEGObject *> sub_trace(biward.begin() + start_idx,
                                          biward.begin() + end_idx + 1);

            auto trace = new EnhancedSEGTrace(sub_trace, intraTrace->trace.bbs);
            // TODO: consider the condition and flow order of inter slicings
            // maybe recompute order based on inter-procedural reachability
            trace->conditions = intraTrace->conditions;
            trace->input_node = input;
            trace->output_node = output;

            bool found_exist = false;
            for (auto cur_item : interTraces) {
              if (isTwoEnhancedTraceEq(trace, cur_item)) {
                found_exist = true;
                break;
              }
            }
            if (!found_exist) {
              interTraces.insert(trace);
            }

            for (auto node : trace->trace.trace) {
              if (!node) {
                outs() << "Find null node in trace!\n";
              }
            }
          }
        }
      }
    }
  } else if (!backwardTraces.empty()) {
    for (auto &interBackward : backwardTraces) {
      vector<SEGObject *> biward = interBackward;
      reverse(biward.begin(), biward.end());
      biward.insert(biward.end(), intraTrace->trace.trace.begin() + 1,
                    intraTrace->trace.trace.end());

      // recover condition and order information
      set<InputNode *> inputNodes;
      canFindInput(biward, inputNodes, false);

      if (inputNodes.empty()) {
        continue;
      }

      for (auto input : inputNodes) {
        auto output = intraTrace->output_node;
        if (!input || !output || !ifInOutputMatch(input, output)) {
          continue;
        }
        int start_idx = find(biward.begin(), biward.end(), input->usedNode) -
                        biward.begin();
        int end_idx = find(biward.begin(), biward.end(), output->usedNode) -
                      biward.begin();
        vector<SEGObject *> sub_trace(biward.begin() + start_idx,
                                      biward.begin() + end_idx + 1);

        auto trace = new EnhancedSEGTrace(sub_trace, intraTrace->trace.bbs);
        // TODO: consider the condition and flow order of inter slicings
        // maybe recompute order based on inter-procedural reachability
        trace->conditions = intraTrace->conditions;
        trace->input_node = input;
        trace->output_node = output;
        bool found_exist = false;
        for (auto cur_item : interTraces) {
          if (isTwoEnhancedTraceEq(trace, cur_item)) {
            found_exist = true;
            break;
          }
        }
        if (!found_exist) {
          interTraces.insert(trace);
        }
        for (auto node : trace->trace.trace) {
          if (!node) {
            outs() << "Find null node in trace!\n";
          }
        }
      }
    }
  } else if (!forwardTraces.empty()) {
    for (auto interForward : forwardTraces) {
      vector<SEGObject *> biward = intraTrace->trace.trace;
      biward.insert(biward.end(), interForward.begin() + 1, interForward.end());

      set<OutputNode *> outputNodes;
      canFindOutput(biward, outputNodes, false, false);
      if (outputNodes.empty()) {
        continue;
      }
      for (auto output : outputNodes) {
        auto input = intraTrace->input_node;
        if (!input || !output || !ifInOutputMatch(input, output)) {
          continue;
        }
        int start_idx = find(biward.begin(), biward.end(), input->usedNode) -
                        biward.begin();
        int end_idx = find(biward.begin(), biward.end(), output->usedNode) -
                      biward.begin();
        vector<SEGObject *> sub_trace(biward.begin() + start_idx,
                                      biward.begin() + end_idx + 1);

        auto trace = new EnhancedSEGTrace(sub_trace, intraTrace->trace.bbs);
        // TODO: consider the condition and flow order of inter slicings
        // maybe recompute order based on inter-procedural reachability
        trace->conditions = intraTrace->conditions;
        trace->input_node = input;
        trace->output_node = output;
        bool found_exist = false;
        for (auto cur_item : interTraces) {
          if (isTwoEnhancedTraceEq(trace, cur_item)) {
            found_exist = true;
            break;
          }
        }
        if (!found_exist) {
          interTraces.insert(trace);
        }
        for (auto node : trace->trace.trace) {
          if (!node) {
            outs() << "Find null node in trace!\n";
          }
        }
      }
    }
  } else {
    bool found_exist = false;
    for (auto cur_item : interTraces) {
      if (isTwoEnhancedTraceEq(intraTrace, cur_item)) {
        found_exist = true;
        break;
      }
    }
    if (!found_exist) {
      interTraces.insert(intraTrace);
    }
    return;
  }
}

void EnhancedSEGWrapper::interValueFlowBackward(
    SEGNodeBase *node, vector<Function *> &callTrace,
    vector<SEGObject *> &curTrace, set<vector<SEGObject *>> &backwardInters) {
  if (!node) {
    return;
  }

  if (!match_def_use_context(curTrace)) {
    return;
  }

  if (find(curTrace.begin(), curTrace.end(), node) != curTrace.end()) {
    // cycle def-use
    return;
  }

  if (node->getLLVMDbgValue() && is_excopy_val(node->getLLVMDbgValue())) {
    backwardInters.insert(curTrace);
    return;
  }

  curTrace.push_back(node);
  bool callerCalleeRelated = false;

  // fix Phi Node
  set<SEGNodeBase *> inComingValNoDup;
  if (auto *phiNode = dyn_cast<SEGPhiNode>(node)) {
    for (int i = 0; i < phiNode->size(); i++) {
      auto cur_incoming = phiNode->getIncomeNode(i)->ValNode;
      if (inComingValNoDup.count(cur_incoming)) {
        if (isa<ConstantInt>(cur_incoming->getLLVMDbgValue())) {
          auto newConstNode = new SEGSimpleOperandNode(
              cur_incoming,
              SEGBuilder->getSymbolicExprGraph(
                  phiNode->getIncomeNode(i)->BB->getParent()),
              false);
          for (int j = 0; j < phiNode->getNumChildren(); j++) {
            if (phiNode->getChild(i) == cur_incoming) {
              phiNode->Children[i] = newConstNode;
              break;
            }
          }
          phiNode->getIncomeNode(i)->ValNode = newConstNode;
          inComingValNoDup.insert(newConstNode);
        }
      } else {
        inComingValNoDup.insert(cur_incoming);
      }
    }
  }

  set<SEGNodeBase *> nodeDup;
  // if has child, go to child
  for (unsigned int i = 0; i < node->getNumChildren(); i++) {
    if (nodeDup.find(node->getChild(i)) != nodeDup.end()) {
      continue;
    }

    if (isa<SEGPhiNode>(node)) {
      if (auto *constInt =
              dyn_cast<ConstantInt>(node->getChild(i)->getLLVMDbgValue())) {
        int value = constInt->getValue().getSExtValue();
        if (!value) { // TODO: omit success code?
          continue;
        }
      }
    }
    if (isa<SEGOpcodeNode>(
            node)) { // we do not track value flow from const as operand
      if (node->getChild(i)->getLLVMDbgValue()) {
        if (auto *constInt =
                dyn_cast<ConstantInt>(node->getChild(i)->getLLVMDbgValue())) {
          continue;
        }
      }
    }
    if (auto *ret_node = dyn_cast<SEGCommonReturnNode>(node)) {
      curTrace.push_back(ret_node->getReturnSite(node->getChild(i)));
    }
    nodeDup.insert(node->getChild(i));
    interValueFlowBackward(node->getChild(i), callTrace, curTrace,
                           backwardInters);
    if (isa<SEGCommonReturnNode>(node)) {
      curTrace.pop_back();
    }
  }

  if (node->getNumChildren() == 0 && !needBackward(node)) {
    backwardInters.insert(curTrace);
    curTrace.pop_back();
    return;
  }
  // if no child, check if we need to go to another caller/callee func
  if (isa<SEGPseudoArgumentNode>(node)) {
    callTrace.pop_back();
    if (callTrace.empty()) {
      backwardInters.insert(curTrace);
      callTrace.push_back(node->getParentGraph()->getBaseFunc());
      curTrace.pop_back();
      return;
    }

    auto caller = callTrace.back();
    auto callee = node->getParentGraph()->getBaseFunc();

    vector<SEGCallSite *> callSites;
    findCallSite(caller, callee, callSites);

    for (auto site : callSites) {
      curTrace.emplace_back(site);
      size_t index = ((const SEGPseudoArgumentNode *)node)->getIndex();
      auto pseudoInput = site->getPseudoInput(callee, index);
      interValueFlowBackward((SEGNodeBase *)pseudoInput, callTrace, curTrace,
                             backwardInters);
      curTrace.pop_back();
    }
    callTrace.push_back(callee);
  } else if (isa<SEGCommonArgumentNode>(node)) {
    callTrace.pop_back();
    if (callTrace.empty()) {
      backwardInters.insert(curTrace);
      callTrace.push_back(node->getParentGraph()->getBaseFunc());
      curTrace.pop_back();
      return;
    }
    auto caller = callTrace.back();
    auto callee = node->getParentGraph()->getBaseFunc();

    vector<SEGCallSite *> callSites;
    findCallSite(caller, callee, callSites);

    for (auto site : callSites) {
      curTrace.emplace_back(site);
      size_t index = ((const SEGCommonArgumentNode *)node)->getIndex();
      auto commonInput = site->getCommonInput(index);
      interValueFlowBackward((SEGNodeBase *)commonInput, callTrace, curTrace,
                             backwardInters);
      curTrace.pop_back();
    }
    callTrace.push_back(callee);
  } else if (isa<SEGCallSiteCommonOutputNode>(node)) {
    auto *CSONode = dyn_cast<SEGCallSiteCommonOutputNode>(node);
    auto callee = CSONode->getCallSite()->getCalledFunction();
    if (!callee) {
      backwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }
    auto calleeSEG = SEGBuilder->getSymbolicExprGraph(callee);
    if (!calleeSEG) { // APIs
      backwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }
    auto commonRet = calleeSEG->getCommonReturn();
    callTrace.push_back(callee);
    interValueFlowBackward((SEGNodeBase *)commonRet, callTrace, curTrace,
                           backwardInters);
    callTrace.pop_back();
  } else if (isa<SEGCallSitePseudoOutputNode>(node)) {
    auto *pseudoNode = dyn_cast<SEGCallSitePseudoOutputNode>(node);
    auto callee = pseudoNode->getCallee();
    if (!callee) {
      backwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }
    auto calleeSEG = SEGBuilder->getSymbolicExprGraph(callee);
    if (!calleeSEG) {
      backwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }
    size_t index = pseudoNode->getIndex();
    auto pseudoRet = calleeSEG->getPseudoReturn(index);
    callTrace.push_back(callee);
    interValueFlowBackward((SEGNodeBase *)pseudoRet, callTrace, curTrace,
                           backwardInters);

    callTrace.pop_back();
  } else if (node->getNumChildren() == 0) {
    backwardInters.insert(curTrace);
  }
  curTrace.pop_back();
}

void EnhancedSEGWrapper::interValueFlowForward(
    SEGNodeBase *node, vector<Function *> &callTrace,
    vector<SEGObject *> &curTrace, set<vector<SEGObject *>> &forwardInters) {
  // TODO: finish forward inter slicing
  if (!node) {
    return;
  }

  if (!match_def_use_context(curTrace)) {
    return;
  }

  if (find(curTrace.begin(), curTrace.end(), node) != curTrace.end()) {
    // cycle def-use
    return;
  }

  // todo: if we keep several paths to the same node?
  if (node->getLLVMDbgValue()) {
    auto nodeVal = node->getLLVMDbgValue();
    if (is_excopy_val(nodeVal)) {
      forwardInters.insert(curTrace);
      return;
    }
  }
  if (isa<SEGRegionNode>(node)) {
    forwardInters.insert(curTrace);
    return;
  }
  curTrace.push_back(node);
  set<SEGNodeBase *> nodeDup;

  bool has_parent = false;
  for (auto it = node->parent_begin(); it != node->parent_end(); it++) {
    auto nextNode = (SEGNodeBase *)*it;
    if (nodeDup.find(nextNode) != nodeDup.end()) {
      continue;
    }
    has_parent = true;
    nodeDup.insert(nextNode);
    if (auto *ret_node = dyn_cast<SEGCommonReturnNode>(nextNode)) {
      curTrace.emplace_back(ret_node->getReturnSite(node));
    }
    interValueFlowForward(nextNode, callTrace, curTrace, forwardInters);
    if (isa<SEGCommonReturnNode>(nextNode)) {
      curTrace.pop_back();
    }
  }

  if (!has_parent && !needForward(node)) {
    forwardInters.insert(curTrace);
    curTrace.pop_back();
    return;
  }

  bool isCallerCalleeRelated = false;
  if (isa<SEGCommonReturnNode>(node)) {
    isCallerCalleeRelated = true;
    callTrace.pop_back();
    if (callTrace.empty()) {
      forwardInters.insert(curTrace);
      callTrace.push_back(node->getParentGraph()->getBaseFunc());
      curTrace.pop_back();
      return;
    }

    auto caller = callTrace.back();
    auto callee = node->getParentGraph()->getBaseFunc();

    vector<SEGCallSite *> callSites;
    findCallSite(caller, callee, callSites);

    for (auto site : callSites) {
      auto commonOutput = site->getCommonOutput();
      interValueFlowForward((SEGNodeBase *)commonOutput, callTrace, curTrace,
                            forwardInters);
    }
    callTrace.push_back(callee);
  } else if (isa<SEGPseudoReturnNode>(node)) {
    isCallerCalleeRelated = true;
    callTrace.pop_back();
    if (callTrace.empty()) {
      forwardInters.insert(curTrace);
      callTrace.push_back(node->getParentGraph()->getBaseFunc());
      curTrace.pop_back();
      return;
    }

    auto caller = callTrace.back();
    auto callee = node->getParentGraph()->getBaseFunc();

    vector<SEGCallSite *> callSites;
    findCallSite(caller, callee, callSites);

    for (auto site : callSites) {
      size_t index = ((SEGPseudoReturnNode *)node)->getIndex();
      auto pseudoOutput = site->getPseudoOutput(callee, index);
      interValueFlowForward((SEGNodeBase *)pseudoOutput, callTrace, curTrace,
                            forwardInters);
    }
    callTrace.push_back(callee);
  } else if (isa<SEGCallSitePseudoInputNode>(node)) {
    isCallerCalleeRelated = true;
    auto *pseudoInput = dyn_cast<SEGCallSitePseudoInputNode>(node);
    auto callee = pseudoInput->getCallee();
    if (!callee) {
      forwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }
    auto calleeSEG = SEGBuilder->getSymbolicExprGraph(callee);
    if (!calleeSEG) {
      forwardInters.insert(curTrace);
      curTrace.pop_back();
      return;
    }

    size_t index = pseudoInput->getIndex();
    auto pseudoArg = calleeSEG->getPseudoArgument(index);
    callTrace.push_back(callee);
    curTrace.emplace_back(node->getParentGraph()->findSite<SEGCallSite>(
        pseudoInput->getCallSite().getInstruction()));
    interValueFlowForward((SEGNodeBase *)pseudoArg, callTrace, curTrace,
                          forwardInters);
    curTrace.pop_back();
    callTrace.pop_back();
  } else {
    // find if common input node
    for (auto it = node->use_site_begin(); it != node->use_site_end(); it++) {
      if (auto *SEGCS = dyn_cast<SEGCallSite>(*it)) {
        if (SEGCS->isCommonInput(node)) {
          isCallerCalleeRelated = true;
          auto callee = SEGCS->getCalledFunction();
          if (!callee) {
            continue;
          }
          auto calleeSEG = SEGBuilder->getSymbolicExprGraph(callee);
          if (!calleeSEG) {
            forwardInters.insert(curTrace);
            curTrace.pop_back();
            return;
          }

          size_t index = -1;
          for (int i = 0; i < SEGCS->getNumCommonInputs(); i++) {
            if (SEGCS->getCommonInput(i) == node) {
              index = i;
            }
          }
          auto commonArg = calleeSEG->getCommonArgument(index);
          callTrace.push_back(callee);
          curTrace.emplace_back(SEGCS);
          interValueFlowForward((SEGNodeBase *)commonArg, callTrace, curTrace,
                                forwardInters);
          curTrace.pop_back();
          callTrace.pop_back();
        }
      }
    }
  }

  if (!isCallerCalleeRelated && !has_parent) {
    forwardInters.insert(curTrace);
  }

  curTrace.pop_back();
}

void EnhancedSEGWrapper::findCallSite(Function *Caller, Function *Callee,
                                      vector<SEGCallSite *> &callSites) {

  SymbolicExprGraph *callerSEG = SEGBuilder->getSymbolicExprGraph(Caller);
  for (auto &B : *Caller) {
    for (auto &I : B) {
      CallSite CS(&I);
      if (!CS) {
        continue;
      }

      if (CS.getCalledFunction() && CS.getCalledFunction() == Callee) {
        callSites.push_back(callerSEG->findSite<SEGCallSite>(&I));
      }
    }
  }
}

void EnhancedSEGWrapper::funcCallLowerTracer(Function *func,
                                             vector<Function *> &curTrace,
                                             set<vector<Function *>> &traces) {

  curTrace.push_back(func);

  if (caller2CalleeMap.find(func) == caller2CalleeMap.end()) {
    traces.insert(curTrace);
    curTrace.pop_back();
    return;
  }

  for (auto callee : caller2CalleeMap[func]) {
    funcCallLowerTracer(callee, curTrace, traces);
  }

  curTrace.pop_back();
}

void EnhancedSEGWrapper::funcCallUpperTracer(Function *func,
                                             vector<Function *> &curTrace,
                                             set<vector<Function *>> &traces) {
  curTrace.push_back(func);

  if (callee2CallerMap.find(func) == callee2CallerMap.end() ||
      isIndirectCall(func)) {
    auto reversedCallTrace = curTrace;
    reverse(reversedCallTrace.begin(), reversedCallTrace.end());
    traces.insert(reversedCallTrace);
    curTrace.pop_back();
    return;
  }

  for (auto caller : callee2CallerMap[func]) {
    funcCallUpperTracer(caller, curTrace, traces);
  }
  curTrace.pop_back();
}

bool EnhancedSEGWrapper::needBackward(SEGNodeBase *node) {

  if (isa<SEGArgumentNode>(node)) {
    if (isIndirectCall(node->getParentGraph()->getBaseFunc())) {
      //      dbgs() << "Stop Backward " << *node << "\n");
      //      dbgs() << "Meet Indirect Call " <<
      //      node->getParentGraph()->getBaseFunc()->getName() << "\n");
      return false;
    }
    return true;
  } else if (auto *CSONode =
                 dyn_cast<SEGCallSiteOutputNode>(node)) { // into caller
    auto callee = CSONode->getCallSite()->getCalledFunction();
    if (!callee || !SEGBuilder->getSymbolicExprGraph(callee)) {
      //      dbgs() << "Stop Backward " << *node << "\n");
      //      dbgs() << "Meet API Output " << callee->getName() << "\n");
      return false;
    }
    // return value of API
    if (isKernelOrCommonAPI(callee->getName())) {
      //      dbgs() << "Stop Backward " << *node << "\n");
      //      dbgs() << "Meet API Output " << callee->getName() << "\n");
      return false;
    }
    return true;
  }
  return false;
}

bool EnhancedSEGWrapper::needForward(SEGNodeBase *node) {
  if (isa<SEGReturnNode>(node)) {
    if (isIndirectCall(node->getParentGraph()->getBaseFunc())) {
      //      dbgs() << "Stop Forward " << *node << "\n");
      //      dbgs() << "Meet Indirect Call " <<
      //      node->getParentGraph()->getBaseFunc()->getName() << "\n");
      return false;
    }
    return true;
  } else if (auto *CSOInput = dyn_cast<SEGCallSitePseudoInputNode>(node)) {
    auto callee = CSOInput->getCallee();
    if (!callee || !SEGBuilder->getSymbolicExprGraph(callee)) {
      //      dbgs() << "Stop Forward " << *node << "\n");
      //      dbgs() << "Meet API Input " << callee->getName() << "\n");
      return false;
    }
    if (isKernelOrCommonAPI(callee->getName())) {
      //      dbgs() << "Stop Forward " << *node << "\n");
      //      dbgs() << "Meet API Input " << callee->getName() << "\n");
      return false;
    }
    return true;
  } else { // find if common input
    bool isCommonOutput = false;
    bool findNotAPICallee = false;

    for (auto it = node->use_site_begin(); it != node->use_site_end(); it++) {
      if (auto *SEGCS = dyn_cast<SEGCallSite>(*it)) {
        if (SEGCS->isCommonInput(node)) {
          isCommonOutput = true;
          Function *callee = SEGCS->getCalledFunction();
          if (!callee || !SEGBuilder->getSymbolicExprGraph(callee)) {
            //            dbgs() << "Meet API Input " << callee->getName() <<
            //            "\n");
            continue;
          }
          if (isKernelOrCommonAPI(callee->getName())) {
            //            dbgs() << "Meet API Input " << callee->getName() <<
            //            "\n");
            continue;
          }
          findNotAPICallee = true;
        }
      }
    }
    if (!isCommonOutput) {
      return true;
    } else if (isCommonOutput && findNotAPICallee) {
      return true;
    } else {
      //      dbgs() << "Stop Forward " << *node << "\n");
      return false;
    }
  }
}

// remove cycle in graph
void EnhancedSEGWrapper::removeCallGraphCycle(
    map<Function *, set<Function *>> &graph,
    map<Function *, set<Function *>> &tree) {

  map<Function *, int> indegree;
  queue<Function *> q;

  // 初始化入度为0的节点
  for (auto &[node, neighbors] : graph) {
    indegree[node] = 0;
    set<Function *> callees;
    tree[node] = callees;
  }

  // 计算每个节点的入度
  for (auto &[node, neighbors] : graph) {
    for (auto &neighbor : neighbors) {
      indegree[neighbor]++;
    }
  }

  // 将入度为0的节点加入队列
  for (auto &[node, degree] : indegree) {
    if (degree == 0) {
      q.push(node);
    }
  }

  // 拓扑排序
  while (!q.empty()) {
    auto node = q.front();
    q.pop();

    if (graph.find(node) == graph.end()) {
      continue;
    }
    // 将节点加入拓扑排序结果
    for (auto &neighbor : graph[node]) {
      tree[node].insert(neighbor);
      indegree[neighbor]--;

      if (indegree[neighbor] == 0) {
        q.push(neighbor);
      }
    }
  }

  // 检查是否存在环
  if (tree.size() != graph.size()) {
    throw std::runtime_error("Graph contains a cycle");
  }
}
void EnhancedSEGWrapper::computeCallGraph() {
  map<Function *, set<Function *>> callGraphCycle;
  for (CBCallGraph::const_iterator node_it = CBCG->begin();
       node_it != CBCG->end(); node_it++) {
    auto func = (Function *)node_it->first;
    if (!func || func->isDeclaration()) {
      continue;
    }
    for (auto callee_it = node_it->second->begin();
         callee_it != node_it->second->end(); callee_it++) {
      if (!callee_it->first) {
        continue;
      }

      Function *callee = callee_it->second->getFunction();
      if (!callee) {
        continue;
      }
      if (callee->isDeclaration() || callee->isIntrinsic()) {
        continue;
      }
      if (callee->getName().startswith("asan.")) {
        continue;
      }
      if (callGraphCycle.find(func) == callGraphCycle.end()) {
        set<Function *> children;
        callGraphCycle[func] = children;
      }
      callGraphCycle[func].insert(callee);
    }
  }

  removeCallGraphCycle(callGraphCycle, caller2CalleeMap);

  for (auto it = caller2CalleeMap.begin(); it != caller2CalleeMap.end(); it++) {
    Function *caller = it->first;
    for (auto subIt = it->second.begin(); subIt != it->second.end(); subIt++) {
      if (callee2CallerMap.find(*subIt) == callee2CallerMap.end()) {
        set<Function *> callers;
        callee2CallerMap[*subIt] = callers; // key: callee, value: set of
        // callers
      }
      callee2CallerMap[*subIt].insert(caller);
    }
  }
}

void EnhancedSEGWrapper::computeIndirectCall() {
  map<Function *, int> func2NumUser;
  map<Function *, int> func2NumCallUser;

  int numTotalFunc = 0;
  int numAddressTaken = 0;
  int numDirectCall = 0;
  int numIndirectCall = 0;

  for (Function &F : *M) {
    if (F.isDeclaration() || F.isIntrinsic()) {
      continue;
    }

    numTotalFunc += 1;
    if (F.getName().startswith("asan.")) {
      continue;
    }

    if (F.hasAddressTaken()) { // If the function is address taken
      numAddressTaken += 1;

      int numUser = 0;
      stack<Value *> s;
      s.push(&F);
      set<Value *> processedValues;
      while (!s.empty()) {
        Value *cur_user = s.top();
        s.pop();
        processedValues.insert(cur_user);

        if (isa<Instruction>(cur_user)) {
          numUser += 1;
          continue;
        }
        for (auto user = cur_user->user_begin(); user != cur_user->user_end();
             user++) {
          if (processedValues.find(*user) != processedValues.end()) {
            continue;
          }
          s.push(*user);
        }
      }
      func2NumUser.insert({&F, numUser}); // get number of users in total
    } else {
      numDirectCall += 1;
    }

    for (BasicBlock &B : F) {
      for (Instruction &I : B) {
        if (auto *callInst = dyn_cast<CallInst>(&I)) {
          if (!callInst->getCalledValue()) {
            continue;
          }
          Value *called = callInst->getCalledValue()->stripPointerCasts();
          if (auto *func = dyn_cast<Function>(called)) { // direct call
            auto it = func2NumCallUser.find(func);
            if (it == func2NumCallUser.end()) {
              func2NumCallUser.insert(
                  {func, 1}); // get number of call instruction users
            } else {
              it->second += 1;
            }
          }
        }
      }
    }
  }

  for (auto &it1 : func2NumUser) {
    auto it2 = func2NumCallUser.find(it1.first);
    if (it2 == func2NumCallUser.end()) {
      numIndirectCall += 1;
      indirectCalls.insert(it1.first);
    } else {
      if (it1.second > it2->second) {
        numIndirectCall += 1;
        indirectCalls.insert(it1.first);
      } else {
        numDirectCall += 1;
      }
    }
  }
}

bool EnhancedSEGWrapper::isIndirectCall(Function *func) {
  return indirectCalls.find(func) != indirectCalls.end();
}

bool EnhancedSEGWrapper::isKernelOrCommonAPI(StringRef funcName) {
  // TODO: determine API based on defination of function
  set<string> notKernelAPI = {"__dynamic_dev_dbg", "_printk", "_dev_err",
                              "llvm.objectsize.i64.p0i8"};
  if (notKernelAPI.count(funcName)) {
    return false;
  }
  auto func = M->getFunction(funcName);
  if (!func) {
    //    dbgs() << "***[Kernel API]***: " << funcName << "\n");
    return true;
  }
  if (func->getName().find("clearblue") != string::npos) {
    return false;
  }
  if (func->isIntrinsic() || func->isDeclaration()) {
    //    dbgs() << "***[Kernel API]***: " << funcName << "\n");
    return true;
  }

  auto src_file = getCallSourceFile(func);
  if (src_file.compare(src_file.length() - 2, 2, ".h") == 0) {
    //    dbgs() << "***[Kernel API]***: " << funcName << "\n";
    return true;
  }
  //  dbgs() << "***[Not Kernel API]***: " << funcName << "\n");
  return false;
}

string EnhancedSEGWrapper::getCallSourceFile(Function *F) {
  int start_line = -1, end_line;
  string source_file = "";

  for (BasicBlock &B : *F) {
    for (Instruction &I : B) {
      int line = DIA->getSrcLine(&I);
      if (line == 0) {
        continue;
      }
      if (start_line == -1) {
        start_line = line;
        end_line = start_line;
        if (source_file == "" &&
            DIA->getSrcFile(&I).find("drivers/") != string::npos) {
          source_file = DIA->getSrcFile(&I);
          source_file = source_file.substr(source_file.find("drivers/"));
        }
        if (source_file == "" && DIA->getSrcFile(&I).find("") != string::npos) {
          source_file = DIA->getSrcFile(&I);
          source_file = source_file.substr(source_file.find(""));
        }
        if (source_file == "" &&
            DIA->getSrcFile(&I).find("sound/") != string::npos) {
          source_file = DIA->getSrcFile(&I);
          source_file = source_file.substr(source_file.find("sound/"));
        }
      }
      end_line = line;
    }
  }
  return source_file;
}
Function *EnhancedSEGWrapper::getFuncByName(string fileFuncName) {
  string filePath = fileFuncName.substr(0, fileFuncName.find(':'));
  string funcName = fileFuncName.substr(fileFuncName.find(':') + 1);

  //  cleanString(funcName);
  //  for (auto &F : *M) {
  //    if (getCallSourceFile(&F) != filePath) {
  //      continue;
  //    }
  //    string curFuncName = F.getName();
  //    cleanString(curFuncName);
  //
  //    if (funcName == curFuncName) {
  //      return &F;
  //    }
  //  }
  //  return nullptr;
  return M->getFunction(funcName);
}

bool compareSEGVector(vector<SEGObject *> vec1, vector<SEGObject *> vec2) {
  seg_cmp comparator;

  if (vec1.size() == vec2.size()) {
    for (int i = 0; i < vec1.size(); i++) {
      if (comparator(vec1[i], vec2[i])) {
        continue;
      } else if (comparator(vec2[i], vec1[i])) {
        return false; // vec2 is less than vec1 at index i
      }
    }
    return true;
  }
  return vec1.size() < vec2.size();
}

// some rare cases that two SEG nodes essentially always carry on the same
// value, but are different llvm value or different SEG nodes,
// TODO: I tentatively use seg trace matching to
bool EnhancedSEGWrapper::isTwoSEGNodeValueEqual(SEGNodeBase *node1,
                                                SEGNodeBase *node2) {

  map<Value *, Value *, llvm_cmp> matchedValues;

  vector<SEGObject *> curTrace;
  set<vector<SEGObject *>> intraTraceNodeVec1Set, intraTraceNodeVec2Set;

  intraValueFlowBackward(node1, curTrace, intraTraceNodeVec1Set);
  intraValueFlowBackward(node2, curTrace, intraTraceNodeVec2Set);

  if (intraTraceNodeVec1Set.size() != intraTraceNodeVec2Set.size()) {
    return false;
  }

  vector<vector<SEGObject *>> intraTraceNodeVec1(intraTraceNodeVec1Set.begin(),
                                                 intraTraceNodeVec1Set.end()),
      intraTraceNodeVec2(intraTraceNodeVec2Set.begin(),
                         intraTraceNodeVec2Set.end());

  sort(intraTraceNodeVec1.begin(), intraTraceNodeVec1.end(), compareSEGVector);
  sort(intraTraceNodeVec2.begin(), intraTraceNodeVec2.end(), compareSEGVector);

  for (int i = 0; i < intraTraceNodeVec1.size(); i++) {
    auto trace1 = intraTraceNodeVec1[i];
    auto trace2 = intraTraceNodeVec2[i];

    if (trace1.size() != trace2.size()) {
      return false;
    }

    for (int j = 0; j < trace1.size(); j++) {
      auto curNode1 = trace1[j];
      auto curNode2 = trace2[j];

      if (curNode1 == curNode2) {
        continue;
      }

      //      if (!isPatchSEGNodeMatched(node1, node2, matchedValues)) {
      //        return false;
      //      }
    }
  }
  return true;
}

bool EnhancedSEGWrapper::check_reachability_inter(Instruction *src_inst,
                                                  Instruction *dst_inst) {
  auto src_func = src_inst->getParent()->getParent();
  auto dst_func = dst_inst->getParent()->getParent();

  // step 1. if in the same function, just invoke isReachable
  if (src_func == dst_func) {
    return CRA->isReachable(src_inst, dst_inst);
  }

  auto inst_pair = make_pair(src_inst, dst_inst);
  auto iter = reachabilityMap.find(inst_pair);
  if (iter != reachabilityMap.end()) {
    return iter->second;
  }
  set<pair<Function *, pair<SEGCallSite *, SEGCallSite *>>> func2cs12;
  find_common_caller(src_func, dst_func, func2cs12);

  // case 3: func1 and func2 have common caller
  for (auto &item : func2cs12) {
    auto common_caller = item.first;
    auto cs_set = item.second;
    if (common_caller == src_func) {
      if (CRA->isReachable(src_inst, cs_set.second->getLLVMDbgInstruction())) {
        reachabilityMap[inst_pair] = true;
        return true;
      }
    } else if (common_caller == dst_func) {
      if (CRA->isReachable(cs_set.first->getLLVMDbgInstruction(), dst_inst)) {
        reachabilityMap[inst_pair] = true;
        return true;
      }
    } else {
      if (CRA->isReachable(cs_set.first->getLLVMDbgInstruction(),
                           cs_set.second->getLLVMDbgInstruction())) {
        reachabilityMap[inst_pair] = true;
        return true;
      }
    }
  }
  reachabilityMap[inst_pair] = false;
  return false;
}

void EnhancedSEGWrapper::find_common_caller(
    Function *func1, Function *func2,
    set<pair<Function *, pair<SEGCallSite *, SEGCallSite *>>> &func2cs) {

  CBCallGraphNode *src_fnode = (*CBCG)[func1];
  CBCallGraphNode *dst_fnode = (*CBCG)[func2];

  if (src_fnode == dst_fnode) {
    func2cs.insert({func1, make_pair(nullptr, nullptr)});
    return;
  }

  auto fpair_iter = commonCaller2CS.find({func1, func2});
  if (fpair_iter != commonCaller2CS.end()) {
    func2cs.insert(fpair_iter->second.begin(), fpair_iter->second.end());
    return;
  }

  auto reverse_fpair_iter = commonCaller2CS.find({func2, func1});
  if (reverse_fpair_iter != commonCaller2CS.end()) {
    for (auto &pair : reverse_fpair_iter->second) {
      auto caller = pair.first;
      auto cs_pair = pair.second;
      func2cs.insert({caller, {cs_pair.second, cs_pair.first}});
    }
    return;
  }

  DenseMap<CBCallGraphNode *, set<SEGCallSite *>> src_caller2cs;
  DenseMap<CBCallGraphNode *, set<SEGCallSite *>> dst_caller2cs;

  //  find_all_caller_dfs(src_fnode, history_calltrace, caller2cs_func1);
  //  find_all_caller_dfs(dst_fnode, history_calltrace, caller2cs_func2);

  find_all_callers_bfs(src_fnode, src_caller2cs);
  find_all_callers_bfs(dst_fnode, dst_caller2cs);

  // TODO: find least common caller
  // case 1: func1 (transitively) invokes func2
  auto dst_iter = dst_caller2cs.find(src_fnode);
  if (dst_iter != dst_caller2cs.end()) {
    for (auto &cur_cs : dst_iter->second) {
      func2cs.insert({func1, make_pair(cur_cs, cur_cs)});
    }
  }

  // case 2: func2 (transitively) invokes func1
  auto src_iter = src_caller2cs.find(dst_fnode);
  if (src_iter != src_caller2cs.end()) {
    for (auto &cur_cs : src_iter->second) {
      func2cs.insert({func2, make_pair(cur_cs, cur_cs)});
    }
  }

  // case 3: func1 and func2 have common caller
  vector<CBCallGraphNode *> callers1, callers2;
  callers1.reserve(src_caller2cs.size());
  callers2.reserve(dst_caller2cs.size());
  for (auto &kv : src_caller2cs)
    callers1.push_back(kv.first);
  for (auto &kv : dst_caller2cs)
    callers2.push_back(kv.first);

  // Find intersection of keys
  vector<CBCallGraphNode *> common_callers;
  common_callers.reserve(min(callers1.size(), callers2.size()));
  set_intersection(callers1.begin(), callers1.end(), callers2.begin(),
                   callers2.end(), back_inserter(common_callers));

  for (auto &caller : common_callers) {
    auto common_caller = caller->getFunction();
    auto cs_set1 = src_caller2cs[caller];
    auto cs_set2 = dst_caller2cs[caller];
    if (cs_set1 == cs_set2)
      continue;
    for (auto &cs1 : cs_set1) {
      for (auto &cs2 : cs_set2) {
        if (cs1 == cs2)
          continue;
        func2cs.insert({common_caller, make_pair(cs1, cs2)});
      }
    }
  }
  commonCaller2CS[{func1, func2}] = func2cs;
}

void EnhancedSEGWrapper::find_all_callers_bfs(
    CBCallGraphNode *node,
    DenseMap<CBCallGraphNode *, set<SEGCallSite *>> &caller2cs) {
  auto funcIter = func2AllCallsites.find(node);
  if (funcIter != func2AllCallsites.end()) {
    caller2cs = funcIter->second;
    return;
  }

  auto nodeIter = node2SCCRoot.find(node);
  if (nodeIter != node2SCCRoot.end()) {
    auto rootSCC = nodeIter->second;
    auto sccIter = SCC2CallerCS.find(rootSCC);
    if (sccIter != SCC2CallerCS.end()) {
      auto &scc_caller2cs = sccIter->second;
      caller2cs.insert(scc_caller2cs.begin(), scc_caller2cs.end());
      func2AllCallsites[node] = caller2cs;
    }
    return;
  }

  Tarjan(node);

  set<CBCallGraphNode *> visited;
  queue<CBCallGraphNode *> worklist;
  worklist.push(node);
  while (!worklist.empty()) {
    CBCallGraphNode *cur_node = worklist.front();
    Function *cur_func = cur_node->getFunction();
    worklist.pop();
    if (cur_func->isDeclaration() || cur_func->isIntrinsic())
      continue;
    if (visited.find(cur_node) != visited.end())
      continue;
    auto iter = func2AllCallsites.find(cur_node);
    if (iter != func2AllCallsites.end()) {
      // dbgs() << "Already cached during while, take caller2cs: " <<
      // iter->second.size()<< "\n");
      for (auto &pair : iter->second) {
        auto caller = pair.first;
        auto cs_set = pair.second;
        visited.emplace(caller);
        caller2cs[caller].insert(cs_set.begin(), cs_set.end());
      }
      continue;
    }
    nodeIter = node2SCCRoot.find(cur_node);
    if (nodeIter != node2SCCRoot.end()) {
      auto scc_root = nodeIter->second;
      auto sccIter = SCC2CallerCS.find(scc_root);
      if (sccIter != SCC2CallerCS.end()) {
        auto scc_caller2cs = sccIter->second;
        for (auto &pair : scc_caller2cs) {
          auto caller = pair.first;
          auto cs_set = pair.second;
          visited.emplace(caller);
          caller2cs[caller].insert(cs_set.begin(), cs_set.end());
        }
        continue;
      }
    }
    visited.emplace(cur_node);
    for (auto it = cur_node->caller_begin(), ie = cur_node->caller_end();
         it != ie; ++it) {
      Value *call_value = it->first;
      CBCallGraphNode *caller = it->second;
      if (!call_value || is_excopy_val(call_value) || caller == cur_node)
        continue;
      auto caller_seg = SEGBuilder->getSymbolicExprGraph(caller->getFunction());
      auto caller_cs =
          caller_seg->findSite<SEGCallSite>(dyn_cast<Instruction>(call_value));
      caller2cs[caller].emplace(caller_cs);
      worklist.push(caller);
    }
  }
  func2AllCallsites[node] = caller2cs;

  nodeIter = node2SCCRoot.find(node);
  if (nodeIter != node2SCCRoot.end()) {
    // if inside a scc
    auto rootSCC = nodeIter->second;
    auto sccIter = SCC2CallerCS.find(rootSCC);
    if (sccIter == SCC2CallerCS.end()) {
      // dbgs() << "Found SCC, store caller2cs: " << caller2cs.size() << "\n");
      SCC2CallerCS[rootSCC] = caller2cs;
    }
  }
}

void EnhancedSEGWrapper::Tarjan(CBCallGraphNode *node) {

  if (SCCs.find(node) != SCCs.end() ||
      node2SCCRoot.find(node) != node2SCCRoot.end())
    return;

  dfn[node] = low[node] = ++token;
  tarjanStack.emplace(node);
  isInStack.emplace(node);
  for (auto it = node->caller_begin(), ie = node->caller_end(); it != ie;
       ++it) {
    Value *value = it->first;
    CBCallGraphNode *caller = it->second;
    if (!value || is_excopy_val(value))
      continue;
    if (!dfn[caller]) {
      Tarjan(caller);
      low[node] = min(low[node], low[caller]);
    } else if (isInStack.count(caller)) {
      low[node] = min(low[node], dfn[caller]);
    }
  }

  if (low[node] == dfn[node]) {
    CBCallGraphNode *member;
    set<CBCallGraphNode *> &sccMembers = SCCs[node];
    do {
      member = tarjanStack.top();
      tarjanStack.pop();
      isInStack.erase(member);
      sccMembers.emplace(member);
    } while (node != member);
    if (sccMembers.size() == 1) {
      return;
    }
    for (auto &member : sccMembers) {
      node2SCCRoot[member] = node;
    }
  }
}

void EnhancedSEGWrapper::updateTraceOrder(
    map<SEGNodeBase *, set<EnhancedSEGTrace *>> &groupedTraces) {
  auto compare_inst_reach = [this](Instruction *lhs, Instruction *rhs) {
    if (check_reachability_inter(lhs, rhs)) {
      return -1;
    } else if (check_reachability_inter(rhs, lhs)) {
      return 1;
    }
    return 0;
  };

  for (auto group : groupedTraces) {
    map<Instruction *, int> store_orders;
    set<Instruction *> instructions;
    DEBUG_WITH_TYPE("statistics", dbgs()
                                      << "\nInput: " << *group.first << "\n");

    for (auto trace : group.second) {
      auto site = trace->output_node->usedSite->getInstruction();
      if (!site) {
        continue;
      }
      instructions.insert(site);
    }

    if (instructions.empty()) {
      continue;
    }

    vector<Instruction *> instructionVec(instructions.begin(),
                                         instructions.end());
    map<Instruction *, vector<Instruction *>> graph;
    for (auto inst1 : instructionVec) {
      for (auto inst2 : instructionVec) {
        if (inst1 != inst2) {
          int result = compare_inst_reach(inst1, inst2);
          if (result == -1) {
            graph[inst1].push_back(inst2);
          } else if (result == 1) {
            graph[inst2].push_back(inst1);
          }
        }
      }
    }

    map<Instruction *, int> inDegree;
    queue<Instruction *> zeroInDegree;
    vector<Instruction *> topOrder;

    for (auto inst1 : instructionVec) {
      for (auto inst2 : graph[inst1]) {
        inDegree[inst2]++;
      }
    }

    for (auto inst : instructionVec) {
      if (inDegree[inst] == 0) {
        zeroInDegree.push(inst);
      }
    }

    while (!zeroInDegree.empty()) {
      auto inst = zeroInDegree.front();
      zeroInDegree.pop();
      topOrder.push_back(inst);

      for (auto v : graph[inst]) {
        if (--inDegree[v] == 0) {
          zeroInDegree.push(v);
        }
      }
    }

    if (topOrder.size() != instructionVec.size()) {
      errs() << "!!!Loop exist!";
    }

    int currentPriority = 1;
    store_orders[topOrder[0]] = 1; // Assign first priority
    printSourceCodeInfoWithValue(topOrder[0]);
    DEBUG_WITH_TYPE("statistics", dbgs() << "Order: " << currentPriority
                                         << ", Site: " << *topOrder[0] << "\n");

    set<Instruction *> curInstInPriors = {topOrder[0]};
    for (size_t i = 1; i < topOrder.size(); ++i) {
      // Compare with the previous element
      bool need_increase = false;
      for (auto cur_inst : curInstInPriors) {
        if (compare_inst_reach(cur_inst, topOrder[i])) {
          need_increase = true;
          break;
        }
      }
      if (need_increase) {
        currentPriority++;
        curInstInPriors.clear();
        curInstInPriors.insert(topOrder[i]);
      } else {
        curInstInPriors.insert(topOrder[i]);
      }

      //      if (compare_inst_reach(topOrder[i - 1], topOrder[i]) ||
      //          compare_inst_reach(topOrder[i], topOrder[i - 1])) {
      //        // Increment priority if they are not equal
      //        currentPriority++;
      //      }
      store_orders[topOrder[i]] = currentPriority; // Assign priority
      printSourceCodeInfoWithValue(topOrder[i]);
      DEBUG_WITH_TYPE("statistics", dbgs()
                                        << "Order: " << currentPriority
                                        << ", Site: " << *topOrder[i] << "\n");
    }

    for (auto trace : group.second) {
      auto site = trace->output_node->usedSite->getInstruction();
      if (!site) {
        continue;
      }
      trace->output_order = store_orders[site];
    }
  }
}

// check if the context of current def-use chain is matched
bool EnhancedSEGWrapper::match_def_use_context(
    const vector<SEGObject *> &history_trace) {

  if (history_trace.size() < 2)
    return true;
  stack<SEGCallSite *> ctx_stack;
  map<SEGCallSite *, Function *> indirectCall2Callee;

  // note that our history trace is in backward order
  for (int i = 0; i < history_trace.size() - 1; i++) {
    auto cur_node = history_trace[i];
    auto next_node = history_trace[i + 1];
    if (cur_node->getParentGraph() != next_node->getParentGraph()) {
      // backward, from caller to callee
      if (isa<SEGCallSiteOutputNode>(cur_node) &&
          isa<SEGReturnNode>(next_node)) {
        auto *output_node = dyn_cast<SEGCallSiteOutputNode>(cur_node);
        auto caller_cs = (SEGCallSite *)output_node->getCallSite();
        ctx_stack.push(caller_cs);
        auto calledValue = caller_cs->getLLVMCallSite().getCalledValue();
        if (calledValue && !isa<Function>(calledValue) &&
            !isa<Constant>(calledValue) && !isa<InlineAsm>(calledValue)) {
          auto iter = indirectCall2Callee.insert(
              map<SEGCallSite *, Function *>::value_type(caller_cs, nullptr));
          if (!iter.second) {
            if (iter.first->second !=
                next_node->getParentGraph()->getBaseFunc()) {
              return false;
            }
          } else {
            iter.first->second = next_node->getParentGraph()->getBaseFunc();
          }
        }
      }
      // backward, from callee to caller
      if (isa<SEGArgumentNode>(cur_node) && isa<SEGCallSite>(next_node)) {
        /*
         * %struct.A* %obj in invoke_fp
         * call void @invoke_fp(%struct.A* %0), !dbg !50 in simple_fp
         */

        auto *caller_cs = dyn_cast<SEGCallSite>(next_node);
        auto calledValue = caller_cs->getLLVMCallSite().getCalledValue();
        if (calledValue && !isa<Function>(calledValue) &&
            !isa<Constant>(calledValue) && !isa<InlineAsm>(calledValue)) {
          auto iter = indirectCall2Callee.insert(
              map<SEGCallSite *, Function *>::value_type(caller_cs, nullptr));
          if (!iter.second) {
            if (iter.first->second !=
                cur_node->getParentGraph()->getBaseFunc()) {
              return false;
            }
          } else {
            iter.first->second = cur_node->getParentGraph()->getBaseFunc();
          }
        }
        if (ctx_stack.empty()) {
          continue;
        }
        if (caller_cs == ctx_stack.top()) {
          ctx_stack.pop();
        } else {
          return false;
        }
      }

      // forward, from callee to caller
      if (isa<SEGReturnNode>(cur_node) &&
          isa<SEGCallSiteOutputNode>(next_node)) {
        /*
         * ret i8* %call, !dbg !48 in create_A
         * %call = call i8* @create_A(), !dbg !44 in simple_fp
         */
        auto caller_cs =
            (SEGCallSite *)dyn_cast<SEGCallSiteOutputNode>(next_node)
                ->getCallSite();
        auto calledValue = caller_cs->getLLVMCallSite().getCalledValue();
        if (calledValue && !isa<Function>(calledValue) &&
            !isa<Constant>(calledValue) && !isa<InlineAsm>(calledValue)) {
          auto iter = indirectCall2Callee.insert(
              map<SEGCallSite *, Function *>::value_type(caller_cs, nullptr));
          if (!iter.second) {
            if (iter.first->second !=
                cur_node->getParentGraph()->getBaseFunc()) {
              return false;
            }
          } else {
            iter.first->second = cur_node->getParentGraph()->getBaseFunc();
          }
        }
        if (ctx_stack.empty()) {
          continue;
        }
        if (caller_cs == ctx_stack.top()) {
          ctx_stack.pop();
        } else {
          return false;
        }
      }

      // forward, from callee to caller
      if (isa<SEGCallSite>(cur_node) && isa<SEGArgumentNode>(next_node)) {
        auto *caller_cs = dyn_cast<SEGCallSite>(cur_node);
        auto calledValue = caller_cs->getLLVMCallSite().getCalledValue();
        if (calledValue && !isa<Function>(calledValue) &&
            !isa<Constant>(calledValue) && !isa<InlineAsm>(calledValue)) {
          auto iter = indirectCall2Callee.insert(
              map<SEGCallSite *, Function *>::value_type(caller_cs, nullptr));
          if (!iter.second) {
            if (iter.first->second !=
                cur_node->getParentGraph()->getBaseFunc()) {
              return false;
            }
          } else {
            iter.first->second = cur_node->getParentGraph()->getBaseFunc();
          }
        }
        ctx_stack.push(caller_cs);
      }
    }
  }
  return true;
}

bool EnhancedSEGWrapper::isTransitiveCallee(Function *func1, Function *func2) {
  if (func1 == func2) {
    return true;
  }
  if (caller2CalleeMap.find(func1) == caller2CalleeMap.end()) {
    return false;
  }
  auto callees = caller2CalleeMap[func1];
  if (callees.find(func2) == callees.end()) {
    return false;
  }
  return true;
}

void EnhancedSEGWrapper::findLastIcmp(BasicBlock *bb,
                                      set<ICmpInst *> &icmpInsts) {
  vector<BasicBlock *> worklist;
  set<BasicBlock *> handledBBs;

  worklist.push_back(bb);
  while (!worklist.empty()) {
    BasicBlock *curBB = worklist.front();
    worklist.erase(worklist.begin());
    handledBBs.insert(curBB);

    auto lastInst = &curBB->getInstList().back();
    if (isa<BranchInst>(lastInst)) {
      auto *brInst = dyn_cast<BranchInst>(lastInst);
      if (brInst->isConditional()) {
        icmpInsts.insert(dyn_cast<ICmpInst>(brInst->getCondition()));
      } else {
        for (auto nextBB = pred_begin(curBB); nextBB != pred_end(curBB);
             nextBB++) {
          if (handledBBs.find(*nextBB) == handledBBs.end()) {
            worklist.push_back(*nextBB);
          }
        }
      }
    } else {
      for (auto nextBB = pred_begin(curBB); nextBB != pred_end(curBB);
           nextBB++) {
        if (handledBBs.find(*nextBB) == handledBBs.end()) {
          worklist.push_back(*nextBB);
        }
      }
    }
  }
}

void EnhancedSEGWrapper::findErrorCodeInput(ICmpInst *icmpInst,
                                            set<InputNode *> &icmpInputs) {
  if (!icmpInst) {
    return;
  }

  set<SEGNodeBase *> icmpNodes;
  set<Value *> icmpValues = {icmpInst};
  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardTraces;

  value2EnhancedSEGNode(icmpValues, icmpNodes);
  condNode2FlowInter(icmpNodes, backwardTraces);

  set<SEGNodeBase *> invalidCondNode;
  for (auto &[icmpNode, traces] : backwardTraces) {
    for (auto trace : traces) {
      vector<SEGObject *> reversedTrace(trace.size());
      reverse_copy(trace.begin(), trace.end(), reversedTrace.begin());
      auto startNode = findFirstNode(reversedTrace);
      if (isa<SEGCallSiteOutputNode>(startNode) ||
          isa<SEGCallSitePseudoOutputNode>(startNode)) {
        canFindInput(reversedTrace, icmpInputs);
      }
    }
  }
  return;
}

void EnhancedSEGWrapper::canFindOutput(const vector<SEGObject *> trace,
                                       set<OutputNode *> &outputNodes,
                                       bool isBenign, bool intra) {
  if (trace.empty()) {
    return;
  }
  int endIndex = -1;
  SEGNodeBase *endNode = nullptr;
  for (int i = trace.size() - 1; i >= 0; i--) {
    if (auto *node = dyn_cast<SEGNodeBase>(trace[i])) {
      endNode = node;
      endIndex = i;
      break;
    }
  }
  if (endNode) {
    // verify if the parent function is peer function
    if (auto *retNode = dyn_cast<SEGCommonReturnNode>(endNode)) {
      auto func = retNode->getParentGraph()->getBaseFunc();
      if (intra || (!intra && isIndirectCall(func))) {
        string pathFuncName =
            getCallSourceFile(func) + ":" + func->getName().str();
        auto output = new IndirectRetNode(pathFuncName);
        output->usedNode = retNode;
        if (endIndex + 1 < trace.size() &&
            isa<SEGReturnSite>(trace[endIndex + 1])) {
          output->usedSite = (SEGSiteBase *)trace[endIndex + 1];
        } else {
          output->usedSite =
              retNode->getReturnSite((SEGNodeBase *)trace[endIndex - 1]);
        }
        outputNodes.insert(output);
      }
    }
  }

  if (!isBenign) {
    obtainSensitive(trace, outputNodes);
  }

  for (auto node : trace) {
    if (auto *operandNode = dyn_cast<SEGNodeBase>(node)) {
      // if used in kernel-defined API
      for (auto it = operandNode->use_site_begin();
           it != operandNode->use_site_end(); it++) {
        if (auto *SEGCS = dyn_cast<SEGCallSite>(*it)) {
          if (!SEGCS->isCommonInput(operandNode)) {
            continue;
          }
          Function *callee = SEGCS->getCalledFunction();
          if (!callee) {
            continue;
          }
          if (intra ||
              (!intra && isKernelOrCommonAPI(
                             callee->getName()))) { // cannot be pseudoInput

            auto type = operandNode->getLLVMType();
            if (!type->isPointerTy()) {
              continue;
            }
            auto output = new CustomizedAPINode(
                callee->getName(), SEGCS->getInputIndex(operandNode),
                SEGCS->getParentGraph()->getBaseFunc()->getName());
            output->usedNode = operandNode;
            output->usedSite = SEGCS;
            outputNodes.insert(output);
          }
        }
      }
    }
  }
}

bool EnhancedSEGWrapper::ifInOutputMatch(InputNode *start, OutputNode *end) {
  // todo: refine rules here
  if (start->type == ErrorCode && end->type == IndirectRet) {
    return true;
  }
  if (start->type == ArgRetOfAPI && end->type == IndirectRet) {
    return true;
  }
  if (start->type == IndirectArg && end->type == CustmoizedAPI) {
    return true;
  }
  if (start->type == IndirectArg && end->type == SensitiveAPI) {
    return true;
  }
  if (start->type == IndirectArg && end->type == SensitiveOp) {
    return true;
  }
  if (start->type == GlobalVarIn && end->type == CustmoizedAPI) {
    return true;
  }
  if (start->type == GlobalVarIn && end->type == SensitiveAPI) {
    return true;
  }
  if (start->type == GlobalVarIn && end->type == SensitiveOp) {
    return true;
  }
  if (start->type == ArgRetOfAPI && end->type == SensitiveOp) {
    return true;
  }
  if (start->type == ArgRetOfAPI && end->type == SensitiveAPI) {
    return true;
  }
  if (start->type == ArgRetOfAPI && end->type == CustmoizedAPI) {
    return true;
  }
  if (start->type == ArgRetOfAPI && end->type == GlobalVarOut) {
    return true;
  }
  if (start->type == IndirectArg && end->type == GlobalVarOut) {
    return true;
  }
  if (start->type == SensitiveIn && end->type == GlobalVarOut) {
    return true;
  }
  if (start->type == SensitiveIn && end->type == IndirectRet) {
    return true;
  }
  return false;
}

bool EnhancedSEGWrapper::isInputNode(SEGNodeBase *startNode, bool intra) {
  if (!startNode) {
    return false;
  }
  if (auto *argNode = dyn_cast<SEGArgumentNode>(startNode)) {
    auto func = argNode->getParentGraph()->getBaseFunc();
    if (intra || (!intra && isIndirectCall(func))) {
      return true;
    }
  } else if (auto *csOutput = dyn_cast<SEGCallSiteOutputNode>(startNode)) {
    auto called = csOutput->getCallSite()->getCalledFunction();
    if (!called) {
      return false;
    }
    if (called->hasName() &&
        called->getName().equals("llvm.objectsize.i64.p0i8")) {
      return false;
    }
    if (intra || (!intra && isKernelOrCommonAPI(called->getName()))) {
      return true;
    }
  } else if (startNode->getLLVMDbgValue()) {
    auto value = startNode->getLLVMDbgValue();
    // verify if global variable
    if (isa<GlobalVariable>(value)) {
      return true;
    } else if (auto *arg = dyn_cast<Argument>(value)) {
      // check if parent function is peer function, pseudo argument
      auto parent_func = startNode->getParentGraph()->getBaseFunc();
      if (intra || (!intra && isIndirectCall(parent_func))) {
        return true;
      }
    } else if (auto *call = dyn_cast<CallInst>(value)) {
      auto called = call->getCalledFunction();
      if (called && called->hasName()) {
        // to refine
        if (called->getName().equals("llvm.objectsize.i64.p0i8")) {
          return false;
        }
        if (intra || (!intra && isKernelOrCommonAPI(called->getName()))) {
          return true;
        }
      }
    }
  }
  return false;
}

SEGNodeBase *EnhancedSEGWrapper::findFirstNode(vector<SEGObject *> trace) {
  SEGNodeBase *startNode = nullptr;
  for (int i = 0; i < trace.size(); i++) {
    if (auto *node = dyn_cast<SEGNodeBase>(trace[i])) {
      startNode = node;
      return startNode;
    }
  }
  return nullptr;
}