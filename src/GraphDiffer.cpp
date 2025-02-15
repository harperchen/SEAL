
#include "GraphDiffer.h"
#include "DriverSpecs.h"
#include "NodeHelper.h"
#include "UtilsHelper.h"
#include "ValueHelper.h"

GraphDiffer::GraphDiffer(EnhancedSEGWrapper *pSEGWrapper,
                         SymbolicExprGraphSolver *pSEGSolver) {
  SEGSolver = pSEGSolver;
  SEGWrapper = pSEGWrapper;
  //  computePeerFuncs(peerFile);
}

void GraphDiffer::parseValueFlowChanges(set<Value *> &addedValues,
                                        set<Value *> &removedValues) {

  matchABSEGNodes(addedValues, removedValues);

  obtainIntraSlicing();

  diffABIntraTraces();

  intra2InterTraces();

  dbgs() << "\n=========2 [Print GraphDiffer Statistics] =======\n";
  dbgs() << "[# Added   SEG Nodes]: " << addedSEGNodes.size() << "\n";
  dbgs() << "[# Removed SEG Nodes]: " << removedSEGNodes.size() << "\n";
  dbgs() << "[# Matched Conditions]: " << matchedConditions.size() << "\n";
  dbgs() << "[# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "[# Matched SEG Nodes After]: " << matchedNodesAfter.size() << "\n";
  dbgs() << "[# Matched LLVM Value Before]: " << matchedIRsBefore.size()
         << "\n";
  dbgs() << "[# Matched LLVM Value After]: " << matchedIRsAfter.size() << "\n";
}

// give a llvm value, obtain all SEG nodes related to the value (instruction)
void GraphDiffer::matchABSEGNodes(set<Value *> &addedValues,
                                  set<Value *> &removedValues) {
  // for added and removed values, we just transform value to seg node
  SEGWrapper->value2EnhancedSEGNode(addedValues, addedSEGNodes);
  SEGWrapper->value2EnhancedSEGNode(removedValues, removedSEGNodes);

  // for matched values, we further match their seg nodes
  for (auto [value1, value2] : matchedIRsBefore) {
    set<Value *> beforeValue = {value1}, afterValue = {value2};
    set<SEGNodeBase *> beforeNodes, afterNodes;

    SEGWrapper->value2EnhancedSEGNode(beforeValue, beforeNodes);
    SEGWrapper->value2EnhancedSEGNode(afterValue, afterNodes);

    for (auto node1 : beforeNodes) {
      if (matchedNodesBefore.count(node1)) {
        continue;
      }
      if (node1->getLLVMDbgValue() &&
          isCurrentValueSkipMatch(node1->getLLVMDbgValue())) {
        continue;
      }
      bool find_match = false;
      for (auto node2 : afterNodes) {
        if (node2->getLLVMDbgValue() &&
            isCurrentValueSkipMatch(node2->getLLVMDbgValue())) {
          continue;
        }
        if (!isPatchSEGNodeMatched(node1, node2)) {
          continue;
        }
        if (matchedNodesAfter.count(node2) &&
            matchedNodesAfter[node2] != node1) {
          dbgs() << "!!![Alert Already Matched Before Node] " << *node1 << "\n";
          dbgs() << "!!![Alert Already Matched After Node] " << *node2 << "\n";
          dbgs() << "!!![Alert Already Matched Before Node Origin] "
                 << *matchedNodesAfter.find(node2)->second << "\n";
          continue;
        }

        find_match = true;
        matchedNodesBefore.insert({node1, node2});
        matchedNodesAfter.insert({node2, node1});
        break;
      }
      // TODO: what if no SEG Node matches?
      if (!find_match) {
        dbgs() << "\n!!!No matched node before " << *node1 << "\n";
        for (auto node3 : afterNodes) {
          dbgs() << "!!!Check all after node " << *node3 << "\n";
          dbgs() << isPatchSEGNodeMatched(node1, node3) << "\n";
        }
      }
    }

    for (auto node2 : afterNodes) {
      if (matchedNodesAfter.count(node2)) {
        continue;
      }
      if (node2->getLLVMDbgValue() &&
          isCurrentValueSkipMatch(node2->getLLVMDbgValue())) {
        continue;
      }
      dbgs() << "\n!!!No matched node after " << *node2 << "\n";
      // dbgs() << (matchedNodesAfter.find(node2) == matchedNodesAfter.end())
      //        << "\n";
      // for (auto node3 : beforeNodes) {
      //   dbgs() << "!!!Check all before node " << *node3 << " "
      //          << isPatchSEGNodeMatched(node2, node3)
      //          << "\n";
      // }
    }
  }

  dbgs() << "\n=======2.1 [Match SEG Nodes From Matched LLVM Values]========\n";
  dbgs() << "[# Added   SEG Nodes]: " << addedSEGNodes.size() << "\n";
  dbgs() << "[# Removed SEG Nodes]: " << removedSEGNodes.size() << "\n";
  dbgs() << "[# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "[# Matched SEG Nodes After]: " << matchedNodesAfter.size() << "\n";
  dbgs() << "[# Matched LLVM Value Before]: " << matchedIRsBefore.size()
         << "\n";
  dbgs() << "[# Matched LLVM Value After]: " << matchedIRsAfter.size() << "\n";
}

void GraphDiffer::obtainIntraSlicingStage1(
    set<SEGTraceWithBB> &intraSEGTracesBefore,
    set<SEGTraceWithBB> &intraSEGTracesAfter) {

  for (auto addNode : addedSEGNodes) {
    processedAfterNodes.insert(addNode);
    afterGraphs.insert(addNode->getParentGraph());
    SEGWrapper->intraValueFlow(addNode, intraSEGTracesAfter);
  }

  for (auto removedNode : removedSEGNodes) {
    processedBeforeNodes.insert(removedNode);
    beforeGraphs.insert(removedNode->getParentGraph());
    SEGWrapper->intraValueFlow(removedNode, intraSEGTracesBefore);
  }

  for (auto [beforeNode, afterNode] : matchedNodesBefore) {
    if (!beforeNode->getParentGraph()->getBaseFunc()->getName().startswith(
            "before.patch.")) {
      continue;
    }
    if (!afterNode->getParentGraph()->getBaseFunc()->getName().startswith(
            "after.patch.")) {
      continue;
    }
    if (!changedFuncs.count(beforeNode->getParentFunction())) {
      continue;
    }

    if (!changedFuncs.count(afterNode->getParentFunction())) {
      continue;
    }
    beforeGraphs.insert(beforeNode->getParentGraph());
    afterGraphs.insert(afterNode->getParentGraph());
    processedBeforeNodes.insert((SEGNodeBase *)beforeNode);
    processedAfterNodes.insert((SEGNodeBase *)afterNode);
    SEGWrapper->intraValueFlow((SEGNodeBase *)afterNode, intraSEGTracesAfter);
    SEGWrapper->intraValueFlow((SEGNodeBase *)beforeNode, intraSEGTracesBefore);
  }

  dbgs() << "\n=======2.2 [Obtain Intra SEG Slicing]========\n";
  dbgs() << "2.2 [# Before SEG Traces Stage 1]: " << intraSEGTracesBefore.size()
         << "\n";
  dbgs() << "2.2 [# After  SEG Traces Stage 1]: " << intraSEGTracesAfter.size()
         << "\n";
  dbgs() << "2.2 [# Backward Visited Stage 1]: "
         << SEGWrapper->backwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Forward  Visited Stage 1]: "
         << SEGWrapper->forwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes After]: " << matchedNodesAfter.size()
         << "\n";
}

void GraphDiffer::obtainIntraSlicingStage2(
    set<SEGTraceWithBB> &intraSEGTracesBefore,
    set<SEGTraceWithBB> &intraSEGTracesAfter) {
  //    for (auto before_SEG : beforeGraphs) {
  //      for (auto it = before_SEG->non_value_node_begin();
  //           it != before_SEG->non_value_node_end(); it++) {
  //        auto beforeNode = *it;
  //        if (processedBeforeNodes.count(beforeNode)) {
  //          continue;
  //        }
  //        if (isa<SEGOpcodeNode>(beforeNode)) {
  //          continue;
  //        }
  //        processedBeforeNodes.insert(beforeNode);
  //        SEGWrapper->obtainIntraEnhancedSlicing(beforeNode,
  //        tmpBeforeIntraTrace);
  //      }
  //      for (auto it = before_SEG->value_node_begin();
  //           it != before_SEG->value_node_end(); it++) {
  //        auto beforeNode = it->second;
  //        if (processedBeforeNodes.count(beforeNode)) {
  //          continue;
  //        }
  //        if (is_excopy_val(it->first)) {
  //          continue;
  //        }
  //        if (isa<ConstantInt>(it->first)) {
  //          continue;
  //        }
  //        processedBeforeNodes.insert(beforeNode);
  //        SEGWrapper->obtainIntraEnhancedSlicing(beforeNode,
  //        tmpBeforeIntraTrace);
  //      }
  //    }
  //
  //    for (auto after_SEG : afterGraphs) {
  //      for (auto it = after_SEG->non_value_node_begin();
  //           it != after_SEG->non_value_node_end(); it++) {
  //        auto afterNode = *it;
  //        if (processedAfterNodes.count(afterNode)) {
  //          continue;
  //        }
  //        if (isa<SEGOpcodeNode>(afterNode)) {
  //          continue;
  //        }
  //        processedAfterNodes.insert(afterNode);
  //        SEGWrapper->obtainIntraEnhancedSlicing(afterNode,
  //        tmpAfterIntraTrace);
  //      }
  //      for (auto it = after_SEG->value_node_begin();
  //           it != after_SEG->value_node_end(); it++) {
  //        auto afterNode = it->second;
  //        if (processedAfterNodes.count(afterNode)) {
  //          continue;
  //        }
  //        if (is_excopy_val(it->first)) {
  //          continue;
  //        }
  //        if (isa<ConstantInt>(it->first)) {
  //          continue;
  //        }
  //        processedAfterNodes.insert(afterNode);
  //        SEGWrapper->obtainIntraEnhancedSlicing(afterNode,
  //        tmpAfterIntraTrace);
  //      }
  //    }

  set<SEGNodeBase *> beforeNeedComputed, afterNeedComputed;

  for (auto trace : intraSEGTracesBefore) {
    for (auto node : trace.trace) {
      if (isa<SEGOpcodeNode>(node)) {
        continue;
      }

      if (auto *operandNode = dyn_cast<SEGNodeBase>(node)) {
        if (operandNode->getLLVMDbgInstruction()) {
          if (is_excopy_val(operandNode->getLLVMDbgInstruction())) {
            continue;
          }
          if (isa<ConstantInt>(operandNode->getLLVMDbgInstruction())) {
            continue;
          }
        }
        if (!processedBeforeNodes.count(operandNode)) {
          processedBeforeNodes.insert(operandNode);
          beforeNeedComputed.insert(operandNode);
        }
      }
    }
  }

  for (auto trace : intraSEGTracesAfter) {
    for (auto node : trace.trace) {
      if (isa<SEGOpcodeNode>(node)) {
        continue;
      }

      if (auto *operandNode = dyn_cast<SEGNodeBase>(node)) {
        if (operandNode->getLLVMDbgInstruction()) {
          if (is_excopy_val(operandNode->getLLVMDbgInstruction())) {
            continue;
          }
          if (isa<ConstantInt>(operandNode->getLLVMDbgInstruction())) {
            continue;
          }
        }
        if (!processedAfterNodes.count(operandNode)) {
          processedAfterNodes.insert(operandNode);
          afterNeedComputed.insert(operandNode);
        }
      }
    }
  }

  for (auto node : beforeNeedComputed) {
    SEGWrapper->intraValueFlow(node, intraSEGTracesBefore);
  }
  for (auto node : afterNeedComputed) {
    SEGWrapper->intraValueFlow(node, intraSEGTracesAfter);
  }

  //    for (auto trace1 : tmpBeforeIntraTrace) {
  //      dbgs() << "2.2 [# Before SEG Traces Stage 2]" << "\n";
  //      dumpVector(trace1->trace);
  //    }
  //
  //    for (auto trace2 : tmpAfterIntraTrace) {
  //      dbgs() << "2.2 [# After SEG Traces Stage 2]" << "\n";
  //
  //      dumpVector(trace2->trace);
  //    }

  dbgs() << "\n2.2 [# Before SEG Traces Stage 2]: "
         << intraSEGTracesBefore.size() << "\n";
  dbgs() << "2.2 [# After  SEG Traces Stage 2]: " << intraSEGTracesAfter.size()
         << "\n";
  dbgs() << "2.2 [# Backward Visited Stage 2]: "
         << SEGWrapper->backwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Forward  Visited Stage 2]: "
         << SEGWrapper->forwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes After]: " << matchedNodesAfter.size()
         << "\n";
}

void GraphDiffer::obtainIntraSlicingStage3(
    set<SEGTraceWithBB> &intraSEGTracesBefore,
    set<SEGTraceWithBB> &intraSEGTracesAfter) {
  set<EnhancedSEGTrace *> tmpBeforeIntraTrace;
  set<EnhancedSEGTrace *> tmpAfterIntraTrace;

  SEGWrapper->obtainIntraEnhancedSlicing(intraSEGTracesBefore,
                                         tmpBeforeIntraTrace);
  SEGWrapper->obtainIntraEnhancedSlicing(intraSEGTracesAfter,
                                         tmpAfterIntraTrace);

  dbgs() << "\n2.2 [# Before SEG Traces Stage 3]: "
         << tmpBeforeIntraTrace.size() << "\n";
  dbgs() << "2.2 [# After  SEG Traces Stage 3]: " << tmpAfterIntraTrace.size()
         << "\n";
  dbgs() << "2.2 [# Backward Visited Stage 3]: "
         << SEGWrapper->backwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Forward  Visited Stage 3]: "
         << SEGWrapper->forwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes After]: " << matchedNodesAfter.size()
         << "\n";

  set<EnhancedSEGTrace *> toBeRemoved;

  for (auto it1 = tmpBeforeIntraTrace.begin(); it1 != tmpBeforeIntraTrace.end();
       it1++) {
    if (toBeRemoved.count(*it1)) {
      continue;
    }
    for (auto it2 = it1; it2 != tmpBeforeIntraTrace.end(); it2++) {
      if (it1 == it2) {
        continue;
      }
      auto trace1 = *it1;
      auto trace2 = *it2;
      if (trace1->input_node == trace2->input_node &&
          trace1->output_node == trace2->output_node) {
        if (trace1->trace.isSubSEGTrace(trace2->trace)) {
          toBeRemoved.insert(*it1);
          break;
        }

        if (trace2->trace.isSubSEGTrace(trace1->trace)) {
          toBeRemoved.insert(*it2);
          break;
        }
      }
    }
  }

  for (auto item : tmpBeforeIntraTrace) {
    if (toBeRemoved.count(item)) {
      continue;
    }
    bool found_exist = false;
    for (auto cur_item : beforeIntraTraces) {
      if (SEGWrapper->isTwoEnhancedTraceEq(item, cur_item)) {
        found_exist = true;
        break;
      }
    }
    if (!found_exist) {
      beforeIntraTraces.insert(item);
    }
  }

  toBeRemoved.clear();
  for (auto it1 = tmpAfterIntraTrace.begin(); it1 != tmpAfterIntraTrace.end();
       it1++) {
    if (toBeRemoved.count(*it1)) {
      continue;
    }
    for (auto it2 = it1; it2 != tmpAfterIntraTrace.end(); it2++) {
      if (it1 == it2) {
        continue;
      }
      auto trace1 = *it1;
      auto trace2 = *it2;
      if (trace1->input_node == trace2->input_node &&
          trace1->output_node == trace2->output_node) {
        if (trace1->trace.isSubSEGTrace(trace2->trace)) {
          toBeRemoved.insert(*it1);
          break;
        }

        if (trace2->trace.isSubSEGTrace(trace1->trace)) {
          toBeRemoved.insert(*it2);
          break;
        }
      }
    }
  }

  for (auto item : tmpAfterIntraTrace) {
    if (toBeRemoved.count(item)) {
      continue;
    }
    bool found_exist = false;
    for (auto cur_item : afterIntraTraces) {
      if (SEGWrapper->isTwoEnhancedTraceEq(item, cur_item)) {
        found_exist = true;
        break;
      }
    }
    if (!found_exist) {
      afterIntraTraces.insert(item);
    }
  }

  //    for (auto trace1 : beforeIntraTraces) {
  //      dbgs() << "\n2.2 [# Before SEG Traces Stage 4]" << "\n";
  //      dumpEnhancedTrace(trace1);
  //    }
  //
  //    for (auto trace2 : afterIntraTraces) {
  //      dbgs() << "\n2.2 [# After SEG Traces Stage 4]" << "\n";
  //      dumpEnhancedTrace(trace2);
  //    }

  dbgs() << "\n2.2 [# Before SEG Traces Stage 4]: " << beforeIntraTraces.size()
         << "\n";
  dbgs() << "2.2 [# After  SEG Traces Stage 4]: " << afterIntraTraces.size()
         << "\n";
  dbgs() << "2.2 [# Backward Visited Stage 4]: "
         << SEGWrapper->backwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Forward  Visited Stage 4]: "
         << SEGWrapper->forwardIntraVisited.size() << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "2.2 [# Matched SEG Nodes After]: " << matchedNodesAfter.size()
         << "\n";

  //  for (auto trace: beforeIntraTraces) {
  //    DEBUG_WITH_TYPE("statistics", dbgs() << "\n2.2 [Before SEG Traces]:\n");
  //    dumpVector(trace->trace);
  //  }
  //
  //  for (auto trace: afterIntraTraces) {
  //    DEBUG_WITH_TYPE("statistics", dbgs() << "\n2.2 [After SEG Traces]:\n");
  //    dumpVector(trace->trace);
  //  }
}

void GraphDiffer::obtainIntraSlicing() {
  set<SEGTraceWithBB> intraSEGTracesBefore;
  set<SEGTraceWithBB> intraSEGTracesAfter;

  obtainIntraSlicingStage1(intraSEGTracesBefore, intraSEGTracesAfter);
  obtainIntraSlicingStage2(intraSEGTracesBefore, intraSEGTracesAfter);
  obtainIntraSlicingStage3(intraSEGTracesBefore, intraSEGTracesAfter);

  dbgs() << "\n[# Added   SEG Nodes]: " << addedSEGNodes.size() << "\n";
  dbgs() << "[# Removed SEG Nodes]: " << removedSEGNodes.size() << "\n";
  dbgs() << "[# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "[# Matched SEG Nodes After]: " << matchedNodesAfter.size() << "\n";
  dbgs() << "[# Matched LLVM Value Before]: " << matchedIRsBefore.size()
         << "\n";
  dbgs() << "[# Matched LLVM Value After]: " << matchedIRsAfter.size() << "\n";

  // update order based on CFG reachability
  map<SEGNodeBase *, set<EnhancedSEGTrace *>> groupedAddedTraces;
  map<SEGNodeBase *, set<EnhancedSEGTrace *>> groupedRemovedTraces;
  for (const auto &trace : afterIntraTraces) {
    groupedAddedTraces[trace->input_node->usedNode].insert(trace);
  }
  for (const auto &trace : beforeIntraTraces) {
    groupedRemovedTraces[trace->input_node->usedNode].insert(trace);
  }

  SEGWrapper->updateTraceOrder(groupedAddedTraces);
  SEGWrapper->updateTraceOrder(groupedRemovedTraces);

  for (auto [node1, node2] : matchedNodesBefore) {
    if (changedFuncs.count(node1->getParentGraph()->getBaseFunc())) {
      DEBUG_WITH_TYPE("statistics", dbgs() << "2.2 Matched Nodes Before\n"
                                           << *node1 << "\n"
                                           << *node2 << "\n");
    }
  }
}

// if all intra enhanced slicing matched, then they are matchedNodes
void GraphDiffer::diffABIntraTraces() {

  auto tmp1 = matchedIRsBefore;

  auto tmp3 = matchedNodesBefore;

  dbgs() << "\n=======2.3 [Diff Intra SEG Traces]========\n";

  map<EnhancedSEGTrace *, EnhancedSEGTrace *> condMatchTrace;
  map<EnhancedSEGTrace *, EnhancedSEGTrace *> orderMatchTrace;

  for (auto trace1 : beforeIntraTraces) {
    set<EnhancedSEGTrace *> matchedForTrace1;
    for (auto trace2 : afterIntraTraces) {
      if (!isTwoEnhancedTraceMatch(trace1, trace2)) {
        continue;
      }
      matchedForTrace1.insert(trace2);
    }
    if (matchedForTrace1.size() > 1) {
      dbgs() << "\n!!![Collide Before Trace 1]:\n";
      SEGWrapper->dumpEnhancedTraceCond(trace1);
      for (auto trace2 : matchedForTrace1) {
        dbgs() << "!!![Collide After Trace 1]:\n";
        SEGWrapper->dumpEnhancedTraceCond(trace2);
      }
    }
  }

  for (auto trace1 : beforeIntraTraces) {
    for (auto trace2 : afterIntraTraces) {
      if (unchangedIntraTraces.count(trace2)) {
        continue;
      }
      if (trace1->trace.trace.size() != trace2->trace.trace.size()) {
        continue;
      }

      if (!isTwoEnhancedTraceMatch(trace1, trace2)) {
        //        dbgs() << "2.3 [Compare     Intra Slicings]: \n";
        //        dumpVectorDbg(trace1->trace.trace);
        //        if (trace1->input_node->usedSite) {
        //          dbgs() << "[Input Site]: " << *trace1->input_node->usedSite
        //          << "\n";
        //        }
        //        if (trace1->output_node->usedSite) {
        //          dbgs() << "[Output Site]: " <<
        //          *trace1->output_node->usedSite << "\n";
        //        }
        //
        //        dbgs() << "\n2.3 [Compare   Intra Slicings]: \n";
        //        dumpVectorDbg(trace2->trace.trace);
        //        if (trace2->input_node->usedSite) {
        //          dbgs() << "[Input Site]: " << *trace2->input_node->usedSite
        //          << "\n";
        //        }
        //        if (trace2->output_node->usedSite) {
        //          dbgs() << "[Output Site]: " <<
        //          *trace2->output_node->usedSite << "\n";
        //        }

        //        outs() << isTwoEnhancedTraceMatch(trace1, trace2) << "\n";
        continue;
      }

      unchangedIntraTraces.insert({trace1, trace2});
      unchangedIntraTraces.insert({trace2, trace1});
      break;
    }
  }

  for (auto trace1 : beforeIntraTraces) {
    if (unchangedIntraTraces.count(trace1)) {
      continue;
    }
    bool find_match = false;
    removedIntraTraces.insert(trace1);
    for (auto trace2 : afterIntraTraces) {
      if (unchangedIntraTraces.count(trace2)) {
        continue;
      }
      if (!isTwoSEGTraceMatched(trace1->trace, trace2->trace)) {
        continue;
      }

      if (condMatchTrace.count(trace2) || orderMatchTrace.count(trace2)) {
        continue;
      }

      find_match = true;
      if (!isTwoConditionMatched(trace1->conditions, trace2->conditions)) {
        DEBUG_WITH_TYPE(
            "statistics",
            dbgs() << "\n=======2.3 [Conditional Intra Traces]========\n");
        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "\n[Changed Cond Trace Before]:\n");
        trace1->trace.dump();

        DEBUG_WITH_TYPE("statistics", dbgs()
                                          << "[Changed Cond Trace After]:\n");
        trace2->trace.dump();
        condMatchTrace.insert({trace1, trace2});
        condMatchTrace.insert({trace2, trace1});
      }

      else if (!isTwoFlowOrderMatched(trace1, trace2)) {
        DEBUG_WITH_TYPE(
            "statistics",
            dbgs() << "\n=======2.3 [Order Changed Intra Traces]========\n");
        DEBUG_WITH_TYPE("statistics", dbgs()
                                          << "\n[Order Cond Trace Before]:\n");
        trace1->trace.dump();

        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "Before order: " << trace1->output_order
                               << ", node: " << *trace1->output_node << "\n");
        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "Before order: " << trace1->output_order
                               << ", site: " << *trace1->output_node->usedSite
                               << "\n");

        DEBUG_WITH_TYPE("statistics", dbgs() << "[Order Cond Trace After]:\n");
        trace2->trace.dump();

        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "After order: " << trace2->output_order
                               << ", site: " << *trace2->output_node << "\n");
        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "After order: " << trace2->output_order
                               << ", site: " << *trace2->output_node->usedSite
                               << "\n");
        orderMatchTrace.insert({trace1, trace2});
        orderMatchTrace.insert({trace2, trace1});
      } else {
        DEBUG_WITH_TYPE("statistics",
                        dbgs() << "[Order and Cond Match Before]:\n");
        trace1->trace.dump();
        DEBUG_WITH_TYPE("statistics", dbgs()
                                          << "[Order and Cond Match After]:\n");
        trace2->trace.dump();
      }
      break;
    }

    if (!find_match) {
      DEBUG_WITH_TYPE(
          "statistics",
          dbgs() << "\n==========2.3 [Removed Intra Traces]========\n");
      trace1->trace.dump();
      for (auto trace2 : afterIntraTraces) {
        if (unchangedIntraTraces.find(trace2) != unchangedIntraTraces.end()) {
          continue;
        }
        if (condMatchTrace.count(trace2) || orderMatchTrace.count(trace2)) {
          continue;
        }
        if (trace1->trace.trace.size() == trace2->trace.trace.size()) {
          trace2->trace.dump();
          DEBUG_WITH_TYPE("statistics", dbgs() << isTwoSEGTraceMatched(
                                            trace1->trace, trace2->trace));
          DEBUG_WITH_TYPE("statistics",
                          dbgs() << isTwoEnhancedTraceMatch(trace1, trace2));
        }
      }
    }
  }

  for (auto trace2 : afterIntraTraces) {
    if (unchangedIntraTraces.count(trace2)) {
      continue;
    }
    addedIntraTraces.insert(trace2);
    if (condMatchTrace.count(trace2) || orderMatchTrace.count(trace2)) {
      continue;
    }
    DEBUG_WITH_TYPE("statistics",
                    dbgs() << "\n==========2.3 [Added Intra Traces]========\n");
    trace2->trace.dump();
    for (auto trace1 : beforeIntraTraces) {
      if (unchangedIntraTraces.find(trace1) != unchangedIntraTraces.end()) {
        continue;
      }
      if (condMatchTrace.count(trace1) || orderMatchTrace.count(trace1)) {
        continue;
      }
      if (trace1->trace.trace.size() == trace2->trace.trace.size()) {
        trace1->trace.dump();
        DEBUG_WITH_TYPE("statistics", dbgs() << isTwoSEGTraceMatched(
                                          trace1->trace, trace2->trace));
        DEBUG_WITH_TYPE("statistics",
                        dbgs() << isTwoEnhancedTraceMatch(trace1, trace2));
      }
    }
  }

  //  for (auto [node1, node2]: matchedNodesBefore) {
  //    dbgs() << "2.2 Matched Nodes Before\n" << *node1 << "\n" << *node2 <<
  //    "\n");
  //  }

  for (auto [beforeIR, afterIR] : matchedIRsBefore) {
    if (auto *bb = dyn_cast<BasicBlock>(beforeIR)) {
      //      if (!changedFuncs.count(bb->getParent())) {
      //        continue;
      //      }
      DEBUG_WITH_TYPE("statistics", dbgs() << "2.3 Matched BB Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");

    } else if (auto *inst = dyn_cast<Instruction>(beforeIR)) {
      //      if (!changedFuncs.count(inst->getParent()->getParent())) {
      //        continue;
      //      }
      DEBUG_WITH_TYPE("statistics", dbgs() << "2.3 Matched IR Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");
    } else {
      DEBUG_WITH_TYPE("statistics", dbgs() << "2.3 Matched Value Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");
    }
  }

  set<string> conditionOutputLines;
  for (auto [cur_cond, matched_cond] : matchedConditions) {
    if (matched_cond.size() > 1) {
      dbgs() << "\n!!!Current fast condition: " << cur_cond->dump() << "\n";
      for (auto other : matched_cond) {
        dbgs() << "!!!Multiple fast matched condition: " << other->dump()
               << "\n";
      }
    }
  }
  for (auto [cur_cond, matched_cond] : matchedConditionSMTs) {
    if (matched_cond.size() > 1) {
      dbgs() << "\n!!!Current smt condition: " << cur_cond->dump() << "\n";
      for (auto other : matched_cond) {
        dbgs() << "!!!Multiple smt matched condition: " << other->dump()
               << "\n";
      }
    }
  }

  for (auto line : conditionOutputLines) {
    DEBUG_WITH_TYPE("statistics", dbgs() << line);
  }
  dbgs() << "2.3 [Matched   Intra Conditions]:" << matchedConditions.size()
         << "\n";
  dbgs() << "2.3 [Unchanged Intra Slicings]: "
         << unchangedIntraTraces.size() / 2 << "\n";
  dbgs() << "2.3 [Added     Intra Slicings]: "
         << addedIntraTraces.size() - condMatchTrace.size() / 2 -
                orderMatchTrace.size() / 2
         << "\n";
  dbgs() << "2.3 [Removed   Intra Slicings]: "
         << removedIntraTraces.size() - condMatchTrace.size() / 2 -
                orderMatchTrace.size() / 2
         << "\n";
  dbgs() << "2.3 [Condition Intra Slicings]: " << condMatchTrace.size() / 2
         << "\n";
  dbgs() << "2.3 [Order     Intra Slicings]: " << orderMatchTrace.size() / 2
         << "\n";

  dbgs() << "\n[# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "[# Matched SEG Nodes After]: " << matchedNodesAfter.size() << "\n";
  dbgs() << "[# Matched LLVM Value Before]: " << matchedIRsBefore.size()
         << "\n";
  dbgs() << "[# Matched LLVM Value After]: " << matchedIRsAfter.size() << "\n";

  for (auto trace : addedIntraTraces) {
    if (orderMatchTrace.count(trace)) {
      continue;
    }
    if (condMatchTrace.count(trace)) {
      continue;
    }
    if (unchangedIntraTraces.count(trace)) {
      continue;
    }
    dbgs() << "2.3 [Added     Intra Slicings]: \n";
    SEGWrapper->dumpEnhancedTraceCond(trace);
  }
  for (auto trace : removedIntraTraces) {
    if (orderMatchTrace.count(trace)) {
      continue;
    }
    if (condMatchTrace.count(trace)) {
      continue;
    }
    if (unchangedIntraTraces.count(trace)) {
      continue;
    }
    dbgs() << "2.3 [Removed   Intra Slicings]: \n";
    SEGWrapper->dumpEnhancedTraceCond(trace);
  }

  //  for (auto [trace1, trace2]: condMatchTrace) {
  //    dbgs() << "2.3 [Added     Intra Slicings]: \n";
  //    SEGWrapper->dumpEnhancedTraceCond(trace1);
  //    dbgs() << "2.3 [Removed   Intra Slicings]: \n";
  //    SEGWrapper->dumpEnhancedTraceCond(trace2);
  //    outs() << isTwoEnhancedTraceMatch(trace1, trace2) << "\n";
  //  }
}

void GraphDiffer::intra2InterTraces() {
  // only extend changed intra seg traces to inter
  set<EnhancedSEGTrace *> addedTmpTraces, removedTmpTraces;

  // extend to Inter (_, S+)
  for (auto trace : addedIntraTraces) {
    SEGWrapper->obtainInterSlicing(trace, addedTmpTraces);
  }
  // extend to Inter (S-, _)
  for (auto trace : removedIntraTraces) {
    SEGWrapper->obtainInterSlicing(trace, removedTmpTraces);
  }
  map<SEGNodeBase *, set<EnhancedSEGTrace *>> groupedAddedTraces;
  map<SEGNodeBase *, set<EnhancedSEGTrace *>> groupedRemovedTraces;
  for (const auto &trace : addedTmpTraces) {
    groupedAddedTraces[trace->input_node->usedNode].insert(trace);
  }
  for (const auto &trace : removedTmpTraces) {
    for (auto node : trace->trace.trace) {
      if (!node) {
        outs() << "Found null node in before trace\n";
      }
    }
    groupedRemovedTraces[trace->input_node->usedNode].insert(trace);
  }

  SEGWrapper->updateTraceOrder(groupedAddedTraces);
  SEGWrapper->updateTraceOrder(groupedRemovedTraces);

  for (auto [node1, node2] : matchedNodesBefore) {
    if (changedFuncs.count(node1->getParentGraph()->getBaseFunc())) {
      DEBUG_WITH_TYPE("statistics", dbgs() << "2.4 Matched Nodes Before\n"
                                           << *node1 << "\n"
                                           << *node2 << "\n");
    }
  }

  // filter out mapped inter slicing between added and removed traces
  classifyInterEnhancedTraces(removedTmpTraces, addedTmpTraces);
}

// four result: added, removed, changed, unchanged
void GraphDiffer::classifyInterEnhancedTraces(
    set<EnhancedSEGTrace *> &beforeInterTraces,
    set<EnhancedSEGTrace *> &afterInterTraces) {
  DEBUG_WITH_TYPE(
      "statistics",
      dbgs() << "\n=======2.4 [Extend Intra to Inter Slicings]========\n");

  for (auto beforeTrace : beforeInterTraces) {
    bool find_match = false;
    for (auto afterTrace : afterInterTraces) {
      if (!isTwoSEGTraceMatched(beforeTrace->trace, afterTrace->trace)) {
        continue;
      }
      if (changedCondInterTraces.count(afterTrace)) {
        beforeTrace->trace.dump();
        afterTrace->trace.dump();
        changedCondInterTraces[afterTrace]->trace.dump();
        continue;
      }
      if (changedOrderInterTraces.count(afterTrace)) {
        continue;
      }

      find_match = true;
      if (!isTwoConditionMatched(beforeTrace->conditions,
                                 afterTrace->conditions)) {

        DEBUG_WITH_TYPE(
            "statistics",
            dbgs() << "\n=======2.4 [Conditional Inter Traces]========\n");
        DEBUG_WITH_TYPE("statistics", dbgs() << "\n[Changed Cond Before]:\n");
        beforeTrace->trace.dump();

        DEBUG_WITH_TYPE("statistics", dbgs() << "[Changed Cond After]:\n");
        afterTrace->trace.dump();
        changedCondInterTraces.insert({beforeTrace, afterTrace});
        changedCondInterTraces.insert({afterTrace, beforeTrace});
      } else if (!isTwoFlowOrderMatched(beforeTrace, afterTrace)) {
        DEBUG_WITH_TYPE(
            "statistics",
            dbgs() << "\n=======2.4 [Order Changed Inter Traces]========\n");
        DEBUG_WITH_TYPE("statistics", dbgs() << "[Changed Order Before]:\n");
        beforeTrace->trace.dump();

        DEBUG_WITH_TYPE("statistics", dbgs() << "[Changed Order After]:\n");
        afterTrace->trace.dump();
        changedOrderInterTraces.insert({beforeTrace, afterTrace});
        changedOrderInterTraces.insert({afterTrace, beforeTrace});
      }
      break;
    }

    if (!find_match) {
      if (removedInterTraces.count(beforeTrace) == 0) {
        DEBUG_WITH_TYPE(
            "statistics",
            dbgs() << "\n===========2.4 [Removed Inter Trace]==========\n");
        beforeTrace->trace.dump();
        removedInterTraces.insert(beforeTrace);
      }
    }
  }

  for (auto afterTrace : afterInterTraces) {
    if (!changedCondInterTraces.count(afterTrace) &&
        !changedOrderInterTraces.count(afterTrace) &&
        !addedInterTraces.count(afterTrace)) {
      DEBUG_WITH_TYPE(
          "statistics",
          dbgs() << "\n===========2.4 [Added Inter Trace]==========\n");
      afterTrace->trace.dump();
      // for (auto before : beforeInterTraces) {
      //   if (afterTrace->trace.trace.size() == before->trace.trace.size()) {
      //     before->trace.dump();
      //     DEBUG_WITH_TYPE(
      //         "statistics",
      //         dbgs() << isTwoSEGTraceMatched(before->trace,
      //         afterTrace->trace)
      //                << "\n");
      //   }
      // }
      addedInterTraces.insert(afterTrace);
    }
  }

  dbgs() << "\n=======2.4 [Intra to Inter Slicings]========\n";

  dbgs() << "2.4 [Added   Inter Slicings]: " << addedInterTraces.size() << "\n";
  dbgs() << "2.4 [Removed Inter Slicings]: " << removedInterTraces.size()
         << "\n";
  dbgs() << "2.4 [Cond    Inter Slicings]: "
         << changedCondInterTraces.size() / 2 << "\n";
  dbgs() << "2.4 [Order   Inter Slicings]: "
         << changedOrderInterTraces.size() / 2 << "\n";

  dbgs() << "\n[# Matched SEG Nodes Before]: " << matchedNodesBefore.size()
         << "\n";
  dbgs() << "[# Matched SEG Nodes After]: " << matchedNodesAfter.size() << "\n";
  dbgs() << "[# Matched LLVM Value Before]: " << matchedIRsBefore.size()
         << "\n";
  dbgs() << "[# Matched LLVM Value After]: " << matchedIRsAfter.size() << "\n";
}

bool GraphDiffer::isTwoEnhancedTraceMatch(EnhancedSEGTrace *trace1,
                                          EnhancedSEGTrace *trace2) {
  if (!isTwoSEGTraceMatched(trace1->trace, trace2->trace)) {
    return false;
  }
  if (!isTwoIONodeMatched(trace1, trace2)) {
    return false;
  }
  if (!isTwoConditionMatched(trace1->conditions, trace2->conditions)) {
    return false;
  }
  if (!isTwoFlowOrderMatched(trace1, trace2)) {
    return false;
  }
  return true;
}

bool GraphDiffer::isTwoSEGTraceMatchedWithPhi(
    const vector<SEGObject *> &trace1, const vector<SEGObject *> &trace2) {

  if (trace1.size() != trace2.size()) {
    return false;
  }
  for (int i = 0; i < trace1.size(); i++) {
    auto node1 = trace1.at(i);
    auto node2 = trace2.at(i);

    if (node1 == node2) {
      continue;
    }

    if (matchedNodesBefore.count(node1)) {
      if (node2 == matchedNodesBefore[node1]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesAfter.count(node1)) {
      if (node2 == matchedNodesAfter[node1]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesBefore.count(node2)) {
      if (node1 == matchedNodesBefore[node2]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesAfter.count(node2)) {
      if (node1 == matchedNodesAfter[node2]) {
        continue;
      } else {
        return false;
      }
    }

    if (isa<SEGOperandNode>(node1) && isa<SEGOperandNode>(node2)) {
      auto *segNode1 = dyn_cast<SEGNodeBase>(node1);
      auto *segNode2 = dyn_cast<SEGNodeBase>(node2);
      if (!isPatchSEGNodeMatched(segNode1, segNode2)) {
        // special treatment for phi node
        if (isa<SEGPhiNode>(node1) && isa<SEGPhiNode>(node2)) {
          auto *phiNode1 = dyn_cast<SEGPhiNode>(node1);
          auto *phiNode2 = dyn_cast<SEGPhiNode>(node2);
          set<BasicBlock *> bbNodes1, bbNodes2;

          for (const auto &it : *phiNode1) {
            if (it.ValNode == trace1.at(i - 1)) {
              bbNodes1.insert(it.BB);
            } else if (it.ValNode->getLLVMDbgValue() &&
                       trace1[i - 1]->getLLVMDbgValue()) {
              if (it.ValNode->getLLVMDbgValue() ==
                  trace1[i - 1]->getLLVMDbgValue()) {
                bbNodes1.insert(it.BB);
              }
            }
          }
          for (const auto &it : *phiNode2) {
            if (it.ValNode == trace2.at(i - 1)) {
              bbNodes2.insert(it.BB);
            } else if (it.ValNode->getLLVMDbgValue() &&
                       trace1[i - 1]->getLLVMDbgValue()) {
              if (it.ValNode->getLLVMDbgValue() ==
                  trace1[i - 1]->getLLVMDbgValue()) {
                bbNodes2.insert(it.BB);
              }
            }
          }

          map<BasicBlock *, BasicBlock *> matchedBBs;
          for (auto bbNode1 : bbNodes1) {
            for (auto bbNode2 : bbNodes2) {
              if (matchedBBs.count(bbNode2)) {
                continue;
              }
              if (isTwoValueMatchedHelper(bbNode1, bbNode2)) {
                matchedBBs.insert({bbNode1, bbNode2});
              }
            }
          }
          if (!matchedBBs.empty()) {
            continue;
          } else {
            return false;
          }
        } else {
          return false;
        }
      }
      if (node1->getParentGraph()->getBaseFunc()->getName().startswith(
              "before.patch") &&
          node1->getLLVMDbgValue() && node2->getLLVMDbgValue() &&
          node2->getParentGraph()->getBaseFunc()->getName().startswith(
              "after.patch")) {
        //        dbgs() << "Added into matched node at 1255:\n";
        //        dbgs() << *node1 << "\n";
        //        dbgs() << *node2 << "\n";

        if (isa<Constant>(node1->getLLVMDbgValue()) &&
            isa<Constant>(node2->getLLVMDbgValue())) {
          continue;
        }
        matchedNodesBefore.insert({node1, node2});
        matchedNodesAfter.insert({node2, node1});
      }
    }
  }
  return true;
}

bool GraphDiffer::isTwoSEGTraceMatchedWithoutPhi(
    const vector<SEGObject *> &trace1, const vector<SEGObject *> &trace2) {

  vector<SEGObject *> trace1WithNoPhi, trace2WithNoPhi;
  for (auto node : trace1) {
    if (!isa<SEGPhiNode>(node)) {
      trace1WithNoPhi.push_back(node);
    }
  }
  for (auto node : trace2) {
    if (!isa<SEGPhiNode>(node)) {
      trace2WithNoPhi.push_back(node);
    }
  }
  if (trace1WithNoPhi.size() != trace2WithNoPhi.size()) {
    return false;
  }
  for (int i = 0; i < trace1WithNoPhi.size(); i++) {
    auto node1 = trace1WithNoPhi.at(i);
    auto node2 = trace2WithNoPhi.at(i);

    if (node1 == node2) {
      continue;
    }

    if (matchedNodesBefore.count(node1)) {
      if (node2 == matchedNodesBefore[node1]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesAfter.count(node1)) {
      if (node2 == matchedNodesAfter[node1]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesBefore.count(node2)) {
      if (node1 == matchedNodesBefore[node2]) {
        continue;
      } else {
        return false;
      }
    }

    if (matchedNodesAfter.count(node2)) {
      if (node1 == matchedNodesAfter[node2]) {
        continue;
      } else {
        return false;
      }
    }

    if (isa<SEGOperandNode>(node1) && isa<SEGOperandNode>(node2)) {
      auto *segNode1 = dyn_cast<SEGNodeBase>(node1);
      auto *segNode2 = dyn_cast<SEGNodeBase>(node2);
      if (!isPatchSEGNodeMatched(segNode1, segNode2)) {
        return false;
      }
      if (node1->getParentGraph()->getBaseFunc()->getName().startswith(
              "before.patch") &&
          node1->getLLVMDbgValue() && node2->getLLVMDbgValue() &&
          node2->getParentGraph()->getBaseFunc()->getName().startswith(
              "after.patch")) {
        if (isa<Constant>(node1->getLLVMDbgValue()) &&
            isa<Constant>(node2->getLLVMDbgValue())) {
          continue;
        }
        matchedNodesBefore.insert({node1, node2});
        matchedNodesAfter.insert({node2, node1});
      }
    }
  }
  return true;
}

bool GraphDiffer::isTwoIONodeMatched(EnhancedSEGTrace *trace1,
                                     EnhancedSEGTrace *trace2) {
  if (!isPatchSEGNodeMatched(trace1->input_node->usedNode,
                             trace2->input_node->usedNode)) {
    return false;
  }

  if (!isPatchSEGNodeMatched(trace1->output_node->usedNode,
                             trace2->output_node->usedNode)) {
    return false;
  }
  if (!isPatchSEGSiteMatched(trace1->input_node->usedSite,
                             trace2->input_node->usedSite)) {
    return false;
  }

  if (!isPatchSEGSiteMatched(trace1->output_node->usedSite,
                             trace2->output_node->usedSite)) {
    return false;
  }
  return true;
}

// can be invoked for both before/after patch and all before or all after patch
bool GraphDiffer::isTwoSEGTraceMatched(SEGTraceWithBB &trace1,
                                       SEGTraceWithBB &trace2) {

  if (!isTwoSEGTraceMatchedWithPhi(trace1.trace, trace2.trace)) {
    if (!isTwoSEGTraceMatchedWithoutPhi(trace1.trace, trace2.trace)) {
      return false;
    }
  }

  // dbgs() << "\n[Match bbs for trace1]:\n";
  // trace1.dump();
  // dbgs() << "[Match bbs for trace2]:\n";
  // trace2.dump();

  // compare basic block, filter out obviously unmatched bbs
  if (trace1.bbs.size() != trace2.bbs.size()) {
    return false;
  }

  for (int i = 0; i < trace1.bbs.size(); i++) {
    auto bb1 = trace1.bbs[i];
    auto bb2 = trace2.bbs[i];
    if (bb1 == bb2) {
      continue;
    }
    if (bb1->getParent() == bb2->getParent()) {
      if (bb1 != bb2) {
        return false;
      } else {
        continue;
      }
    }
    if (matchedIRsBefore.count(bb1)) {
      if (matchedIRsBefore[bb1] == bb2) {
        continue;
      } else {
        return false;
      }
    }
    if (matchedIRsAfter.count(bb2)) {
      if (matchedIRsAfter[bb2] == bb1) {
        continue;
      } else {
        return false;
      }
    }
    // unmatched basic block may have same irs
    //    if (!isTwoValueMatchedHelper(bb1, bb2)) {
    //      return false;
    //    }
  }
  return true;
}

bool GraphDiffer::isTwoConditionMatched(ConditionNode *cond1,
                                        ConditionNode *cond2) {
  if (isTwoConditionMatchedFast(cond1, cond2)) {
    return true;
  }
  if (isTwoConditionMatchedSMT(cond1, cond2)) {
    return true;
  }
  return false;
}

// A fast way to compare two condition tree
// when the tree structure is exactly the same,
// return true
bool GraphDiffer::isTwoConditionMatchedFast(ConditionNode *cond1,
                                            ConditionNode *cond2) {

  if (matchedConditions.count(cond1)) {
    if (matchedConditions[cond1].count(cond2)) {
      return true;
    }
  }

  if (cond1->type != cond2->type)
    return false;
  if ((cond1->value == nullptr) ^ (cond2->value == nullptr))
    return false;

  if (cond1->value != nullptr && cond2->value != nullptr) {
    if (cond1->value == cond2->value) {
      return true;
    }
    if (matchedNodesBefore.count(cond1->value)) {
      if (matchedNodesBefore[cond1->value] != cond2->value) {
        return false;
      } else {
        //        dbgs() << "Add into matched node at 1120: ";
        //        dbgs() << *cond1->value << ", ";
        //        dbgs() << *cond2->value << "\n";

        matchedConditions[cond1].insert(cond2);
        matchedConditions[cond2].insert(cond1);
        matchedConditionsNum += 1;
        return true;
      }
    }

    if (matchedNodesAfter.count(cond2->value)) {
      if (matchedNodesAfter[cond2->value] != cond1->value) {
        return false;
      } else {
        //        dbgs() << "Add into matched node at 1134: ";
        //        dbgs() << *cond1->value << ", ";
        //        dbgs() << *cond2->value << "\n";
        matchedConditions[cond1].insert(cond2);
        matchedConditions[cond2].insert(cond1);
        matchedConditionsNum += 1;
        return true;
      }
    }

    if (!matchedNodesBefore.count(cond1->value) &&
        !matchedNodesAfter.count(cond2->value)) {
      if (isPatchSEGNodeMatched(cond1->value, cond2->value)) {
        if (cond1->value->getParentGraph()->getBaseFunc()->getName().startswith(
                "before.patch") &&
            cond2->value->getParentGraph()->getBaseFunc()->getName().startswith(
                "after.patch")) {
          //          dbgs() << "Add into matched node at 1147: ";
          //          dbgs() << *cond1->value << ", ";
          //          dbgs() << *cond2->value << "\n";
          matchedNodesBefore.insert({cond1->value, cond2->value});
          matchedNodesAfter.insert({cond2->value, cond1->value});

          matchedConditions[cond1].insert(cond2);
          matchedConditions[cond2].insert(cond1);
          matchedConditionsNum += 1;
        }
        return true;
      } else {
        return false;
      }
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
      if (isTwoConditionMatchedFast(i, j)) {
        matchedCondNodes.insert(j);
        find_match = true;
        break;
      }
    }
    if (!find_match) {
      return false;
    }
  }
  matchedConditionsNum += 1;
  matchedConditions[cond1].insert(cond2);
  matchedConditions[cond2].insert(cond1);
  return true;
}

// A more precise way to diff two conditions
// especially for the case where the tree structures are different,
// but these two conditions are exactly the same
// Warn: the scope of smt matched should be a super set of fast match
bool GraphDiffer::isTwoConditionMatchedSMT(ConditionNode *cond1,
                                           ConditionNode *cond2) {
  if (matchedConditionSMTs.count(cond1)) {
    if (matchedConditionSMTs[cond1].count(cond2)) {
      return true;
    }
  }

  DEBUG_WITH_TYPE("condition", dbgs() << "[Turn to SMT Diff Checking]\n");
  DEBUG_WITH_TYPE("condition", dbgs() << cond1->dump() << "\n");
  DEBUG_WITH_TYPE("condition", dbgs() << cond2->dump() << "\n");
  set<SEGNodeBase *> nodeInCond1, nodeInCond2;
  map<SEGNodeBase *, SEGNodeBase *> matchedNodesInCond12;
  map<SEGNodeBase *, SEGNodeBase *> matchedNodesInCond21;

  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardTraces;
  SEGWrapper->condNode2FlowIntra(cond1->obtainNodes(), backwardTraces);
  for (auto [node, traces] : backwardTraces) { // and relation
    if (traces.empty()) {
      continue;
    }
    nodeInCond1.insert(node);
    for (auto trace : traces) {
      if (trace.empty()) {
        continue;
      }
      auto startNode = trace.back();
      if (startNode->getLLVMDbgValue() &&
          isa<Constant>(startNode->getLLVMDbgValue())) {
        continue;
      }
      nodeInCond1.insert((SEGNodeBase *)startNode);
    }
  }
  backwardTraces.clear();
  SEGWrapper->condNode2FlowIntra(cond2->obtainNodes(), backwardTraces);
  for (auto [node, traces] : backwardTraces) { // and relation
    if (traces.empty()) {
      continue;
    }
    nodeInCond2.insert(node);
    for (auto trace : traces) {
      if (trace.empty()) {
        continue;
      }
      auto startNode = trace.back();
      if (startNode->getLLVMDbgValue() &&
          isa<Constant>(startNode->getLLVMDbgValue())) {
        continue;
      }
      nodeInCond2.insert((SEGNodeBase *)startNode);
    }
  }

  for (auto node1 : nodeInCond1) {
    if (matchedNodesBefore.count(node1) &&
        nodeInCond2.count((SEGNodeBase *)matchedNodesBefore[node1]) &&
        matchedNodesInCond21.find((SEGNodeBase *)matchedNodesBefore[node1]) ==
            matchedNodesInCond21.end()) {
      matchedNodesInCond12.insert(
          {node1, (SEGNodeBase *)matchedNodesBefore[node1]});
      matchedNodesInCond21.insert(
          {(SEGNodeBase *)matchedNodesBefore[node1], node1});
    } else {
      for (auto node2 : nodeInCond2) {
        if (matchedNodesInCond21.count(node2) == 0 &&
            isPatchSEGNodeMatched(node1, node2)) {
          if (node1->getParentGraph()->getBaseFunc()->getName().startswith(
                  "before.patch") &&
              node2->getParentGraph()->getBaseFunc()->getName().startswith(
                  "after.patch")) {
            matchedNodesInCond12.insert({node1, node2});
            matchedNodesInCond21.insert({node2, node1});
            //            dbgs() << "Added into matched node at 1045:\n";
            //            dbgs() << *node1 << "\n";
            //            dbgs() << *node2 << "\n";
            matchedNodesBefore.insert({node1, node2});
            matchedNodesAfter.insert({node2, node1});
          }
        }
      }
    }
  }

  for (auto node2 : nodeInCond2) {
    if (matchedNodesAfter.count(node2) &&
        nodeInCond1.count((SEGNodeBase *)matchedNodesAfter[node2]) &&
        matchedNodesInCond12.find((SEGNodeBase *)matchedNodesAfter[node2]) ==
            matchedNodesInCond12.end()) {
      matchedNodesInCond21.insert(
          {node2, (SEGNodeBase *)matchedNodesAfter[node2]});
      matchedNodesInCond12.insert(
          {(SEGNodeBase *)matchedNodesAfter[node2], node2});
    }
  }

  // first, we try to compare value-flows for node in conditions
  if (matchedNodesInCond12.empty() && matchedNodesInCond21.empty()) {
    return false;
  }

  if (condPairFeasibility.count({cond1, cond2})) {
    return condPairFeasibility[{cond1, cond2}] == SMTSolver::SMTRT_Unsat;
  }
  // then, we employ SMT solver to determine the feasibility
  auto smtDataExpr1 = SEGWrapper->condNode2SMTExprIntra(cond1);
  auto smtDataExpr2 = SEGWrapper->condNode2SMTExprIntra(cond2);

  SEGSolver->push();
  for (auto [node1, node2] : matchedNodesInCond12) {
    SEGSolver->add(SEGSolver->getOrInsertExpr(node1) ==
                   SEGSolver->getOrInsertExpr(node2));
  }
  SEGSolver->add(cond1->toSMTExpr(SEGSolver) ^ cond2->toSMTExpr(SEGSolver));
  SEGSolver->add(smtDataExpr1);
  SEGSolver->add(smtDataExpr2);
  auto checkRet = SEGSolver->check();
  SEGSolver->pop();

  condPairFeasibility[{cond1, cond2}] = checkRet;
  condPairFeasibility[{cond2, cond1}] = checkRet;

  if (checkRet == SMTSolver::SMTRT_Unsat) {
    matchedConditionsNum += 1;
    matchedConditionSMTs[cond1].insert(cond2);
    matchedConditionSMTs[cond2].insert(cond1);
    return true;
  }
  return false;
}

bool GraphDiffer::isTwoFlowOrderMatched(EnhancedSEGTrace *trace1,
                                        EnhancedSEGTrace *trace2) {
  return true;
  auto site1 = trace1->output_node->usedSite->getInstruction();
  auto site2 = trace2->output_node->usedSite->getInstruction();
  if (matchedIRsBefore.count(site1)) {
    if (matchedIRsBefore[site1] != site2) {
      return false;
    } else {
      if (trace1->output_order != trace2->output_order) {
        return false;
      } else {
        return true;
      }
    }
  }
  if (matchedIRsAfter.count(site1)) {
    if (matchedIRsAfter[site1] != site2) {
      return false;
    } else {
      if (trace1->output_order != trace2->output_order) {
        return false;
      } else {
        return true;
      }
    }
  }

  if (matchedIRsBefore.count(site2)) {
    if (matchedIRsBefore[site2] != site1) {
      return false;
    } else {
      if (trace1->output_order != trace2->output_order) {
        return false;
      } else {
        return true;
      }
    }
  }

  if (matchedIRsAfter.count(site2)) {
    if (matchedIRsAfter[site2] != site1) {
      return false;
    } else {
      if (trace1->output_order != trace2->output_order) {
        return false;
      } else {
        return true;
      }
    }
  }

  if (!isTwoIRMatched(site1, site2)) {
    return false;
  } else {
    if (trace1->output_order != trace2->output_order) {
      return false;
    } else {
      return true;
    }
  }
}

bool GraphDiffer::isTwoConditionSubMatched(ConditionNode *cond1,
                                           ConditionNode *cond2) {

  if (cond1->type != cond2->type)
    return false;
  if ((cond1->value == nullptr) ^ (cond2->value == nullptr))
    return false;

  if (cond1->value != nullptr && cond2->value != nullptr) {
    if (matchedNodesBefore.count(cond1->value) &&
        matchedNodesBefore[cond1->value] != cond2->value) {
      return false;
    }

    if (matchedNodesAfter.count(cond2->value) &&
        matchedNodesAfter[cond2->value] != cond1->value) {
      return false;
    }

    if (matchedNodesBefore.find(cond1->value) == matchedNodesBefore.end() &&
        matchedNodesAfter.find(cond2->value) == matchedNodesAfter.end()) {
      if (!isPatchSEGNodeMatched(cond1->value, cond2->value)) {
        return false;
      } else {
        if (cond1->value->getParentGraph()->getBaseFunc()->getName().startswith(
                "before.patch") &&
            cond2->value->getParentGraph()->getBaseFunc()->getName().startswith(
                "after.patch")) {
          //          dbgs() << "Add into matched node at 843:\n";
          //          dbgs() << *cond1->value << "\n";
          //          dbgs() << *cond2->value << "\n";
          matchedNodesBefore.insert({cond1->value, cond2->value});
          matchedNodesAfter.insert({cond2->value, cond1->value});
        }
      }
    }
  }
  if (cond1->children.size() > cond2->children.size())
    return false;

  set<ConditionNode *> matchedCondNodes;
  for (auto i : cond1->children) {
    bool find_match = false;
    for (auto j : cond2->children) {
      if (matchedCondNodes.find(j) != matchedCondNodes.end()) {
        continue;
      }
      if (isTwoConditionMatchedFast(i, j)) {
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

void GraphDiffer::diffTwoPathCondNum(map<Instruction *, CDType> &cond1,
                                     map<Instruction *, CDType> &cond2,
                                     map<Instruction *, CDType> &diff) {

  set<Instruction *> matchedPair2;

  for (auto pair1 : cond1) {
    bool find_match = false;

    for (auto pair2 : cond2) {
      if (matchedPair2.find(pair2.first) != matchedPair2.end()) {
        continue;
      }
      if (pair1.first->getOpcode() != pair2.first->getOpcode()) {
        continue;
      }
      if (matchedIRsAfter.find(pair2.first) != matchedIRsAfter.end() &&
          matchedIRsAfter[pair2.first] != pair1.first) {
        continue;
      }

      if (matchedIRsBefore.find(pair1.first) != matchedIRsBefore.end() &&
          matchedIRsBefore[pair1.first] != pair2.first) {
        continue;
      }

      if (pair1.second != pair2.second) {
        continue;
      }

      find_match = true;
      matchedPair2.insert(pair2.first);
    }

    if (!find_match) {
      diff.insert(pair1);
    }
  }

  for (auto pair2 : cond2) {
    if (matchedPair2.find(pair2.first) == matchedPair2.end()) {
      diff.insert(pair2);
    }
  }
}

void GraphDiffer::findHasSubTree(
    ConditionNode *cond1, ConditionNode *cond2,
    map<ConditionNode *, ConditionNode *> &matchedSubTree,
    map<ConditionNode *, ConditionNode *> &subMatchedSubTree) {

  vector<ConditionNode *> nodeStacks;
  vector<vector<NodeType>> pathConds;
  vector<NodeType> firstPathCond;

  nodeStacks.push_back(cond2);
  pathConds.push_back(firstPathCond);

  while (!nodeStacks.empty()) {
    auto curNode = nodeStacks.front();
    auto curPathCond = pathConds.front();
    nodeStacks.erase(nodeStacks.begin());
    pathConds.erase(pathConds.begin());
    findIfCond2SubTreeCond1(cond1, curNode, curPathCond, matchedSubTree,
                            subMatchedSubTree);
    if (matchedSubTree.find(curNode) != matchedSubTree.end()) {
      continue;
    }
    curPathCond.push_back(curNode->type);
    for (auto child : curNode->children) {
      nodeStacks.push_back(child);
      pathConds.push_back(curPathCond);
    }
  }
}

void GraphDiffer::findIfCond2SubTreeCond1(
    ConditionNode *cond1, ConditionNode *cond2, vector<NodeType> pathCond2,
    map<ConditionNode *, ConditionNode *> &matchedSubTree,
    map<ConditionNode *, ConditionNode *> &subMatchedSubTree) {

  // iterate on cond1, to find if there is a match to cond2
  vector<ConditionNode *> nodeStacks;
  vector<vector<NodeType>> pathConds;
  vector<NodeType> firstPathCond;

  nodeStacks.push_back(cond1);
  pathConds.push_back(firstPathCond);
  while (!nodeStacks.empty()) {
    auto curNode = nodeStacks.front();
    auto curPathCond = pathConds.front();
    nodeStacks.erase(nodeStacks.begin());
    pathConds.erase(pathConds.begin());
    if (matchedSubTree.find(curNode) != matchedSubTree.end()) {
      continue;
    }
    if (isTwoConditionMatchedFast(curNode, cond2) && pathCond2 == curPathCond &&
        matchedSubTree.find(cond2) == matchedSubTree.end() &&
        matchedSubTree.find(curNode) == matchedSubTree.end()) {
      //      dbgs() << "\nFIND SUB Tree A\n");
      //      dbgs() << curNode->dump();
      //      dbgs() << "\nFIND SUB Tree B\n");
      //      dbgs() << cond2->dump();
      matchedSubTree.insert({cond2, curNode});
      matchedSubTree.insert({curNode, cond2});
      break;
    } else if (isTwoConditionSubMatched(cond2, curNode) &&
               pathCond2 == curPathCond &&
               subMatchedSubTree.find(curNode) == subMatchedSubTree.end()) {
      //      dbgs() << "\nFIND SUB SUB Tree A\n");
      //      dbgs() << cond2->dump();
      //      dbgs() << "\nFIND SUB SUB Tree B\n");
      //      dbgs() << curNode->dump();
      subMatchedSubTree.insert({curNode, cond2});
      break;
    } else if (isTwoConditionSubMatched(curNode, cond2) &&
               pathCond2 == curPathCond &&
               subMatchedSubTree.find(cond2) == subMatchedSubTree.end()) {
      //      dbgs() << "\nFIND SUB SUB Tree A\n");
      //      dbgs() << curNode->dump();
      //      dbgs() << "\nFIND SUB SUB Tree B\n");
      //      dbgs() << cond2->dump();
      subMatchedSubTree.insert({cond2, curNode});
      break;
    }

    curPathCond.push_back(curNode->type);
    for (auto child : curNode->children) {
      nodeStacks.push_back(child);
      pathConds.push_back(curPathCond);
    }
  }
}

map<OutputNode *, pair<int, int>>
GraphDiffer::diffTwoOrder(map<OutputNode *, int> &site2order1,
                          map<OutputNode *, int> &site2order2) {
  map<OutputNode *, pair<int, int>> diffOrders;
  map<OutputNode *, OutputNode *> matchedOutput;
  for (auto [output1, order1] : site2order1) {
    bool found_match = false;
    auto site1 = output1->usedSite->getInstruction();
    for (auto [output2, order2] : site2order2) {
      if (matchedOutput.count(output2)) {
        continue;
      }
      auto site2 = output2->usedSite->getInstruction();
      if (matchedIRsBefore.count(site1)) {
        if (matchedIRsBefore[site1] != site2) {
          continue;
        } else {
          matchedOutput.insert({output1, output2});
          matchedOutput.insert({output2, output1});
          if (order1 != order2) {
            diffOrders.insert({output2, {order1, order2}});
          }
          found_match = true;
          break;
        }
      }
      if (matchedIRsAfter.count(site1)) {
        if (matchedIRsAfter[site1] != site2) {
          continue;
        } else {
          matchedOutput.insert({output1, output2});
          matchedOutput.insert({output2, output1});
          if (order1 != order2) {
            diffOrders.insert({output2, {order1, order2}});
          }
          found_match = true;
          break;
        }
      }

      if (matchedIRsBefore.count(site2)) {
        if (matchedIRsBefore[site2] != site1) {
          continue;
        } else {
          matchedOutput.insert({output1, output2});
          matchedOutput.insert({output2, output1});
          if (order1 != order2) {
            diffOrders.insert({output2, {order1, order2}});
          }
          found_match = true;
          break;
        }
      }
      if (matchedIRsAfter.count(site2)) {
        if (matchedIRsAfter[site2] != site1) {
          continue;
        } else {
          matchedOutput.insert({output1, output2});
          matchedOutput.insert({output2, output1});
          if (order1 != order2) {
            diffOrders.insert({output2, {order1, order2}});
          }
          found_match = true;
          break;
        }
      }

      if (!isTwoIRMatched(site1, site2)) {
        continue;
      }

      matchedOutput.insert({output1, output2});
      matchedOutput.insert({output2, output1});
      if (order1 != order2) {
        diffOrders.insert({output2, {order1, order2}});
      }
      found_match = true;
      break;
    }
  }
  return diffOrders;
}

void GraphDiffer::diffTwoConditionSEGNodes(ConditionNode *condMap1,
                                           ConditionNode *condMap2,
                                           set<SEGNodeBase *> &diffCondNodes) {

  DEBUG_WITH_TYPE("condition", dbgs() << "Diff Cond1\n");
  DEBUG_WITH_TYPE("condition", dbgs() << condMap1->dump());
  DEBUG_WITH_TYPE("condition", dbgs() << "Diff Cond2\n");
  DEBUG_WITH_TYPE("condition", dbgs() << condMap2->dump());

  set<SEGNodeBase *> nodeSet1 = condMap1->obtainNodes();
  set<SEGNodeBase *> nodeSet2 = condMap2->obtainNodes();

  map<SEGNodeBase *, SEGNodeBase *> nodeMaps;
  for (SEGNodeBase *cond1 : nodeSet1) {
    for (SEGNodeBase *cond2 : nodeSet2) {
      if (nodeMaps.find(cond2) != nodeMaps.end()) {
        continue;
      }
      if (matchedNodesAfter.find(cond1) != matchedNodesAfter.end() &&
          matchedNodesAfter.find(cond1)->second == cond2) {
        nodeMaps.insert({cond1, cond2});
        nodeMaps.insert({cond2, cond2});
        break;
      }

      if (matchedNodesAfter.find(cond2) != matchedNodesAfter.end() &&
          matchedNodesAfter.find(cond2)->second == cond1) {
        nodeMaps.insert({cond1, cond2});
        nodeMaps.insert({cond2, cond2});
        break;
      }

      if (matchedNodesAfter.find(cond1) == matchedNodesAfter.end() &&
          matchedNodesBefore.find(cond1) == matchedNodesBefore.end()) {
        if (!isPatchSEGNodeMatched(cond1, cond2)) {
          continue;
        }
        nodeMaps.insert({cond1, cond2});
        nodeMaps.insert({cond2, cond2});
        matchedNodesBefore.insert({cond1, cond2});
        matchedNodesAfter.insert({cond2, cond1});
        break;
      }

      if (matchedNodesAfter.find(cond2) == matchedNodesAfter.end() &&
          matchedNodesBefore.find(cond2) == matchedNodesBefore.end()) {
        if (!isPatchSEGNodeMatched(cond1, cond2)) {
          continue;
        }
        nodeMaps.insert({cond1, cond2});
        nodeMaps.insert({cond2, cond2});
        matchedNodesBefore.insert({cond1, cond2});
        matchedNodesAfter.insert({cond2, cond1});
        break;
      }
    }
  }

  //  for (auto [node1, node2] : nodeMaps) {
  //    dbgs() << valueToString(node1->getLLVMDbgValue()) << ":"
  //           << valueToString(node2->getLLVMDbgValue()) << "\n";
  //  }

  for (auto node : nodeSet1) {
    if (matchedNodesBefore.count(node) == 0) {
      diffCondNodes.insert(node);
    }
  }
  for (auto node : nodeSet2) {
    if (matchedNodesAfter.count(node) == 0) {
      diffCondNodes.insert(node);
    }
  }
}

ConditionNode *GraphDiffer::diffTwoConditions(ConditionNode *condMap1,
                                              ConditionNode *condMap2) {

  DEBUG_WITH_TYPE("condition", dbgs() << "Diff Cond1\n");
  DEBUG_WITH_TYPE("condition", dbgs() << condMap1->dump());
  DEBUG_WITH_TYPE("condition", dbgs() << "Diff Cond2\n");
  DEBUG_WITH_TYPE("condition", dbgs() << condMap2->dump());
  map<ConditionNode *, ConditionNode *> matchedCondNodes;
  map<ConditionNode *, ConditionNode *> subMatchedCondNodes;
  findHasSubTree(condMap1, condMap2, matchedCondNodes, subMatchedCondNodes);

  int matchedAndNode = 0, matchedSingleNode = 0;

  for (auto [subCond1, subCond2] : subMatchedCondNodes) {
    //    dbgs() << "\nBefore SubCond1\n");
    //    dbgs() << subCond1->dump();
    //    dbgs() << "Before SubCond2\n");
    //    dbgs() << subCond2->dump();
    if (subCond1->type == NODE_CONST && subCond2->type == NODE_CONST) {
      continue;
    }
    if (subCond1->type == NODE_AND) {
      for (auto child : subCond1->children) {
        for (auto j : subCond2->children) {
          if (isTwoConditionMatched(child, j)) {
            child->clear();
            break;
          }
        }
      }
    }
    //    dbgs() << "\nAfter Sub SubCond1\n");
    //    dbgs() << subCond1->dump();
    //    dbgs() << "After SubCond2\n");
    //     dbgs() << subCond2->dump();
  }

  for (auto [subCond1, subCond2] : matchedCondNodes) {
    //    dbgs() << "\nBefore SubCond1\n");
    //    dbgs() << subCond1->dump();
    //    dbgs() << "Before SubCond2\n");
    //    dbgs() << subCond2->dump();
    if (subCond1->type == NODE_CONST && subCond2->type == NODE_CONST) {
      continue;
    }
    if (subCond1->type == NODE_AND) {
      matchedAndNode += 2;
      subCond1->clear();
      subCond2->clear();
    }
    //    dbgs() << "After SubCond1\n");
    //    dbgs() << subCond1->dump();
    //    dbgs() << "After SubCond2\n");
    //     dbgs() << subCond2->dump();
  }

  for (auto [subCond1, subCond2] : matchedCondNodes) {
    //    dbgs() << "\nBefore SubCond1\n");
    //    dbgs() << subCond1->dump();
    //    dbgs() << "Before SubCond2\n");
    //    dbgs() << subCond2->dump();
    if (subCond1->type == NODE_CONST && subCond2->type == NODE_CONST) {
      continue;
    }
    if (subCond1->type != NODE_AND) {
      matchedSingleNode += 2;
      subCond1->clear();
      subCond2->clear();
    }
    //    dbgs() << "After SubCond1\n");
    //    dbgs() << condMap1->dump();
    //    dbgs() << "After SubCond2\n");
    //    dbgs() << condMap2->dump();
  }

  //  dbgs() << "After Cond1\n");
  //  dbgs() << condMap1->dump();
  //  dbgs() << "After Cond2\n");
  //  dbgs() << condMap2->dump();
  condMap1->simplify();
  condMap2->simplify();
  //  dbgs() << "After Cond1\n");
  //  dbgs() << condMap1->dump();
  //  dbgs() << "After Cond2\n");
  //  dbgs() << condMap2->dump();

  ConditionNode *diffNode = new ConditionNode(SEGWrapper, NODE_AND);
  ConditionNode *notNode = new ConditionNode(SEGWrapper, NODE_NOT);
  notNode->addChild(condMap1);
  diffNode->addChild(notNode);
  diffNode->addChild(condMap2);
  // dbgs() << "Before Diff\n");
  // dbgs() << diffNode->dump();
  diffNode->simplify();

  DEBUG_WITH_TYPE("condition", dbgs() << "\nMatched Cond Node "
                                      << matchedCondNodes.size() << "\n");
  DEBUG_WITH_TYPE("condition",
                  dbgs() << "Matched And Cond Node " << matchedAndNode << "\n");
  DEBUG_WITH_TYPE("condition", dbgs() << "Matched Single Cond Node "
                                      << matchedSingleNode << "\n");
  DEBUG_WITH_TYPE("condition", dbgs() << "After Diff\n");
  DEBUG_WITH_TYPE("condition", dbgs() << diffNode->dump());
  //  exit(0);
  if (diffNode->type == NODE_CONST) {
    return nullptr;
  }
  return diffNode;
}

bool GraphDiffer::isPeerFunc(string name1, string name2) {
  auto func1 = SEGWrapper->getFuncByName(name1);
  auto func2 = SEGWrapper->getFuncByName(name2);
  if (!func1 || !func2) {
    return false;
  }

  auto funcName1 = func1->getName();
  auto funcName2 = func2->getName();

  if (func2PeerFuncs.find(funcName1) == func2PeerFuncs.end()) {
    return false;
  }
  if (func2PeerFuncs.find(funcName2) == func2PeerFuncs.end()) {
    return false;
  }
  auto candidate = func2PeerFuncs[funcName1];
  if (find(candidate.begin(), candidate.end(), funcName2) == candidate.end()) {
    return false;
  }
  return true;
}

void GraphDiffer::computePeerFuncs(string fileName) {
  if (fileName.empty()) {
    return;
  }

  std::ifstream inFile(fileName);

  if (!inFile.is_open()) {
    std::cerr << "Unable to open file " << fileName << std::endl;
  } else {
    std::string line;
    while (std::getline(inFile, line)) {
      istringstream iss(line);
      set<string> funcNames;

      string func;
      while (getline(iss, func, ' ')) {
        funcNames.insert(func);
      }

      for (const auto &curFuncName : funcNames) { // for each func
        auto *curFunc = SEGWrapper->getFuncByName(curFuncName);
        if (!curFunc || SEGWrapper->isKernelOrCommonAPI(curFunc->getName())) {
          continue;
        }
        set<string> beforePeerFuncNames;
        set<string> afterPeerFuncNames;
        set<string> normalPeerFuncNames;

        // make the other funcs as its peer functions
        for (const auto &peerFuncName : funcNames) {
          auto *peerFunc = SEGWrapper->getFuncByName(peerFuncName);
          if (!peerFunc ||
              SEGWrapper->isKernelOrCommonAPI(peerFunc->getName())) {
            normalPeerFuncNames.insert(peerFuncName);
            continue;
          }

          if (curFunc && !SEGWrapper->isKernelOrCommonAPI(curFunc->getName())) {
            if (curFunc->getName().find("before.patch") == 0 and
                peerFunc->getName().find("before.patch") == 0) {
              beforePeerFuncNames.insert(peerFunc->getName());
              afterPeerFuncNames.insert(findABMatchFunc(peerFunc->getName()));
            } else if (curFunc->getName().find("after.patch") == 0 and
                       peerFunc->getName().find("after.patch") == 0) {
              afterPeerFuncNames.insert(peerFunc->getName());
              beforePeerFuncNames.insert(findABMatchFunc(peerFunc->getName()));
            } else if (curFunc->getName().find(".patch.") == string::npos and
                       peerFunc->getName().find(".patch.") == string::npos) {
              normalPeerFuncNames.insert(peerFunc->getName());
            }
          }
        }

        if (!beforePeerFuncNames.empty()) {
          if (curFunc->getName().find("before.patch") == 0) {
            func2PeerFuncs.insert({curFunc->getName(), beforePeerFuncNames});
            func2PeerFuncs.insert(
                {findABMatchFunc(curFunc->getName()), afterPeerFuncNames});
          }
          if (curFunc->getName().find("after.patch") == 0) {
            func2PeerFuncs.insert({curFunc->getName(), afterPeerFuncNames});
            func2PeerFuncs.insert(
                {findABMatchFunc(curFunc->getName()), beforePeerFuncNames});
          }
        }
        if (!normalPeerFuncNames.empty()) {
          if (curFunc) {
            func2PeerFuncs.insert({curFunc->getName(), normalPeerFuncNames});
          } else {
            func2PeerFuncs.insert({curFuncName, normalPeerFuncNames});
          }
        }
      }
    }
    inFile.close();
  }
}

void GraphDiffer::loadPeerFuncLines(string peer_file) {
  std::ifstream peerFile(peer_file);
  set<string> funcNames;

  if (!peerFile.is_open()) {
    std::cerr << "Unable to open file " << peer_file << std::endl;
  } else {
    string peerLine;
    while (getline(peerFile, peerLine)) {
      istringstream iss(peerLine);
      string func;
      while (getline(iss, func, ' ')) {
        funcNames.insert(func);
      }
    }
  }

  set<string> realFuncNames;
  // make the other funcs as its peer functions
  for (const auto &peerFuncName : funcNames) {
    auto *peerFunc = SEGWrapper->getFuncByName(peerFuncName);
    if (!peerFunc || SEGWrapper->isKernelOrCommonAPI(peerFunc->getName())) {
      //      realFuncNames.insert(peerFuncName);
      continue;
    }
    realFuncNames.insert(peerFunc->getName());
  }

  for (auto curFunc : realFuncNames) {
    set<string> normalPeerFuncNames;
    set<string> beforePeerFuncNames;
    set<string> afterPeerFuncNames;

    for (auto peerFunc : realFuncNames) {

      if (curFunc.find("before.patch") == 0 and
          peerFunc.find("before.patch") == 0) {
        beforePeerFuncNames.insert(peerFunc);
        afterPeerFuncNames.insert(findABMatchFunc(peerFunc));
      } else if (curFunc.find("after.patch") == 0 and
                 peerFunc.find("after.patch") == 0) {
        afterPeerFuncNames.insert(peerFunc);
        beforePeerFuncNames.insert(findABMatchFunc(peerFunc));
      } else if (curFunc.find(".patch.") == string::npos and
                 peerFunc.find(".patch.") == string::npos) {
        normalPeerFuncNames.insert(peerFunc);
      }
    }
    if (!beforePeerFuncNames.empty()) {
      if (curFunc.find("before.patch") == 0) {
        func2PeerFuncs.insert({curFunc, beforePeerFuncNames});
        func2PeerFuncs.insert({findABMatchFunc(curFunc), afterPeerFuncNames});
      }
      if (curFunc.find("after.patch") == 0) {
        func2PeerFuncs.insert({curFunc, afterPeerFuncNames});
        func2PeerFuncs.insert({findABMatchFunc(curFunc), beforePeerFuncNames});
      }
    }
    if (!normalPeerFuncNames.empty()) {
      func2PeerFuncs.insert({curFunc, normalPeerFuncNames});
    }
  }
}

void GraphDiffer::getPeerFuncs(Function *indirect,
                               vector<Function *> &results) {
  if (!indirect) {
    return;
  }
  if (func2PeerFuncs.find(indirect->getName()) == func2PeerFuncs.end()) {
    return;
  }
  for (const auto &name : func2PeerFuncs[indirect->getName()]) {
    if (SEGWrapper->M->getFunction(name)) {
      results.push_back(SEGWrapper->M->getFunction(name));
    }
  }
}

// used during bug detection
bool GraphDiffer::isOrderMatched(
    vector<int> &originalOrders,
    vector<shared_ptr<VulnerabilityTrace>> &traces) {
  return true;
}
