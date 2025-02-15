#ifndef CLEARBLUE_SINGLESRCSINGLESINK_H
#define CLEARBLUE_SINGLESRCSINGLESINK_H

#include "Checker/PSA/Vulnerability.h"
#include "IR/SEG/SymbolicExprGraph.h"

#include "DriverSpecs.h"
#include "GraphDiffer.h"
#include "SensitiveOps.h"
#include "UtilsHelper.h"

class CustomSrcSink {

public:
  bool fast_mode = false;
  vector<Function *> peerFuncs;
  InputNode *inputNode = nullptr;
  OutputNode *outputNode = nullptr;
  GraphDiffer *graphParser = nullptr;

  CustomSrcSink(GraphDiffer *graphParser, vector<Function *> peerFuncs,
                InputNode *inputNode, OutputNode *outputNode, bool fast_mode) {
    this->graphParser = graphParser;
    this->peerFuncs = peerFuncs;
    this->inputNode = inputNode;
    this->outputNode = outputNode;
    this->fast_mode = fast_mode;
  }

  // check isDriverSEGNodeMatched
  bool isSource(SEGNodeBase *Node, SEGSiteBase *Site) const {
    if (fast_mode) {
      if (peerFuncs.empty()) {
        return false;
      }
      bool isPeerCallee = false;
      for (auto peer : peerFuncs) {
        if (graphParser->SEGWrapper->isTransitiveCallee(
                peer, Node->getParentGraph()->getBaseFunc())) {
          isPeerCallee = true;
        }
      }
      if (!isPeerCallee) {
        return false;
      }
    }
    if (inputNode->type == IndirectArg && isa<SEGArgumentNode>(Node)) {
      SEGArgumentNode *argumentNode = dyn_cast<SEGArgumentNode>(Node);
      IndirectArgNode *indirectArgNode = (IndirectArgNode *)inputNode;
      return graphParser->isPeerFunc(Node->getParentFunction()->getName(),
                                     indirectArgNode->funcName);
    }

    if (inputNode->type == ArgRetOfAPI &&
        isa<SEGCallSiteCommonOutputNode>(Node)) {
      ArgRetOfAPINode *returnOfApiNode = (ArgRetOfAPINode *)inputNode;
      SEGCallSiteCommonOutputNode *segCSOutputNode =
          dyn_cast<SEGCallSiteCommonOutputNode>(Node);

      if (segCSOutputNode->getCallSite()->getCalledFunction()) {
        if (segCSOutputNode->getCallSite()->getCalledFunction()->hasName()) {
          if (segCSOutputNode->getCallSite()
                  ->getCalledFunction()
                  ->getName()
                  .equals(returnOfApiNode->apiName)) {
            return true;
          }
        }
      }
    }

    if (Node->getLLVMDbgValue()) {
      if (inputNode->type == IndirectArg &&
          isa<Argument>(Node->getLLVMDbgValue())) {
        // pseudo arg with offset
        Argument *arg = dyn_cast<Argument>(Node->getLLVMDbgValue());
        IndirectArgNode *indirectArgNode = (IndirectArgNode *)inputNode;
        return graphParser->isPeerFunc(Node->getParentFunction()->getName(),
                                       indirectArgNode->funcName);
      } else if (inputNode->type == ErrorCode &&
                 isa<ConstantInt>(Node->getLLVMDbgValue())) {
        ConstantInt *constInt = dyn_cast<ConstantInt>(Node->getLLVMDbgValue());
        if (!constInt->isNegative()) {
          return false;
        }
        // todo: match target API
      } else if (inputNode->type == GlobalVarIn && Node->getLLVMDbgValue() &&
                 isa<GlobalVariable>(Node->getLLVMDbgValue())) {
        GlobalVarInNode *globalVarInNode = (GlobalVarInNode *)inputNode;
        GlobalVariable *globalVariable =
            dyn_cast<GlobalVariable>(Node->getLLVMDbgValue());
        if (globalVariable->hasName() &&
            globalVariable->getName() == globalVarInNode->globalName) {
          return true;
        }
      }
    }

    return false;
  }
  // check isTwoDriverSEGSiteMatch
  bool isSink(SEGNodeBase *Node, SEGSiteBase *Site) const {
    if (fast_mode) {
      if (peerFuncs.empty()) {
        return false;
      }
      bool isPeerCallee = false;
      for (auto peer : peerFuncs) {
        if (graphParser->SEGWrapper->isTransitiveCallee(
                peer, Node->getParentGraph()->getBaseFunc())) {
          isPeerCallee = true;
        }
      }
      if (!isPeerCallee) {
        return false;
      }
    }
    // match return value
    if (outputNode->type == IndirectRet && isa<SEGReturnNode>(Node)) {
      IndirectRetNode *indirectRetNode = (IndirectRetNode *)outputNode;
      return graphParser->isPeerFunc(indirectRetNode->funcName,
                                     Node->getParentFunction()->getName());
    }
    // match customized API
    if (outputNode->type == CustmoizedAPI && isa<SEGCallSite>(Site)) {
      SEGCallSite *callSite = dyn_cast<SEGCallSite>(Site);
      CustomizedAPINode *customizedApiNode = (CustomizedAPINode *)outputNode;
      if (callSite->getCalledFunction() &&
          callSite->getCalledFunction()->hasName()) {
        if (callSite->getCalledFunction()->getName() ==
            customizedApiNode->apiName) {
          if (callSite->isCommonInput(Node) &&
              callSite->getInputIndex(Node) == customizedApiNode->argIdx) {
            return true;
          }
        }
      }
    }
    if (outputNode->type == GlobalVarOut && Node->getLLVMDbgValue() &&
        isa<GlobalVariable>(Node->getLLVMDbgValue())) {
      GlobalVarOutNode *globalVarOutNode = (GlobalVarOutNode *)outputNode;
      GlobalVariable *globalVariable =
          dyn_cast<GlobalVariable>(Node->getLLVMDbgValue());
      if (globalVariable->hasName() &&
          globalVariable->getName() == globalVarOutNode->globalName) {
        return true;
      }
    }
    // match sensitive API
    if (outputNode->type == SensitiveAPI && isa<SEGCallSite>(Site)) {
      SEGCallSite *callSite = dyn_cast<SEGCallSite>(Site);
      SensitiveAPINode *sensitiveApiNode = (SensitiveAPINode *)outputNode;
      if (callSite->getCalledFunction() &&
          callSite->getCalledFunction()->hasName()) {
        if (callSite->getCalledFunction()->getName() ==
            sensitiveApiNode->apiName) {
          if (callSite->isCommonInput(Node) &&
              callSite->getInputIndex(Node) == sensitiveApiNode->argIdx) {
            return true;
          }
        }
      }
    }
    if (outputNode->type == SensitiveOp) {
      SensitiveOpNode *sensitiveOpNode = (SensitiveOpNode *)outputNode;
      if (sensitiveOpNode->opCode == "deref") {
        if (isNullPtrDerefSite(Node, Site) || isOutOfBoundarySite(Node, Site)) {
          return true;
        }
      } else if (sensitiveOpNode->opCode == "div") {
        if (isDivideByZeroSite(Node, Site)) {
          return true;
        }
      }
    }
    // todo: match API and sensitive api
    return false;
  }

  bool checkTrace(shared_ptr<VulnerabilityTrace> &Trace) {
    auto srcNode = (SEGNodeBase *)Trace->at(0);
    auto sinkNode = (SEGNodeBase *)Trace->at(Trace->get_length() - 2);

    if (peerFuncs.empty()) {
      return false;
    }
    bool isPeerCalleeSrc = false;
    bool isPeerCalleeSink = false;

    for (auto peer : peerFuncs) {
      if (graphParser->SEGWrapper->isTransitiveCallee(
              peer, srcNode->getParentGraph()->getBaseFunc())) {
        isPeerCalleeSrc = true;
      }
      if (graphParser->SEGWrapper->isTransitiveCallee(
              peer, sinkNode->getParentGraph()->getBaseFunc())) {
        isPeerCalleeSink = true;
      }
    }

    if (isPeerCalleeSrc && isPeerCalleeSink) {
      return true;
    } else {
      return false;
    }
  }
};

class SingleSrcSingleSink : public SrcMustNotReachSinkVulnerability {

  SMTExprVec *bugConstraint;

public:
  CustomSrcSink *customSrcSink;

  SingleSrcSingleSink(const char *checkerName, GraphDiffer *graphParser,
                      bool fastMode, vector<Function *> peerFuncs,
                      InputNode *inputNode, OutputNode *outputNode,
                      SMTExprVec *bugConstraint)
      : SrcMustNotReachSinkVulnerability(checkerName),
        bugConstraint(bugConstraint) {
    customSrcSink = new CustomSrcSink(graphParser, peerFuncs, inputNode,
                                      outputNode, fastMode);
  }

  virtual void
  transfer(const SEGSiteBase *Site, const SEGNodeBase *Arg,
           std::vector<const SEGNodeBase *> &TransferDsts) override {
    Instruction *SiteInst = Site->getInstruction();
    auto *SEG = Site->getParentGraph();
    if (isa<BinaryOperator>(SiteInst)) {
      TransferDsts.push_back(SEG->findNode(SiteInst));
      return;
    }
  }

  virtual void setPrerequisites(SymbolicExprGraphSolver *Solver,
                                const SEGSiteBase *CurrSite,
                                const VulnerabilityTraceBuilder &TraceHistory,
                                SMTExprVec &Prerequisites) override {
    if (isSource((SEGNodeBase *)TraceHistory.sourceNode(),
                 (SEGSiteBase *)TraceHistory.sourceSite()) &&
        !bugConstraint->empty()) {

      DEBUG_WITH_TYPE("checker", dbgs() << "\nSet prerequisite\n");
      SEGNodeBase *source = (SEGNodeBase *)TraceHistory.sourceNode();
      //      Prerequisites.push_back(
      //          Solver->getOrInsertExpr(customSrcSink->startNode) ==
      //          Solver->getOrInsertExpr(source));
      Prerequisites.mergeWithAnd(*bugConstraint);
    }
  }

  virtual bool isSource(SEGNodeBase *Node, SEGSiteBase *Site) override {
    return customSrcSink->isSource(Node, Site);
  }

  virtual bool isSink(SEGNodeBase *Node, SEGSiteBase *Site) override {
    return customSrcSink->isSink(Node, Site);
  }

  virtual bool checkTrace(shared_ptr<VulnerabilityTrace> &Trace) {
    return customSrcSink->checkTrace(Trace);
  }
};

class SingleSrcSingleSinkReach : public SrcMustReachSinkVulnerability {

  SMTExprVec *bugConstraint;

public:
  CustomSrcSink *customSrcSink;

  SingleSrcSingleSinkReach(const char *checkerName, GraphDiffer *graphParser,
                           bool fastMode, vector<Function *> peerFuncs,
                           InputNode *inputNode, OutputNode *outputNode,
                           SMTExprVec *bugConstraint)
      : SrcMustReachSinkVulnerability(checkerName),
        bugConstraint(bugConstraint) {
    customSrcSink = new CustomSrcSink(graphParser, peerFuncs, inputNode,
                                      outputNode, fastMode);
  }

  virtual void setPrerequisites(SymbolicExprGraphSolver *Solver,
                                const SEGSiteBase *CurrSite,
                                const VulnerabilityTraceBuilder &TraceHistory,
                                SMTExprVec &Prerequisites) override {
    if (isSource((SEGNodeBase *)TraceHistory.sourceNode(),
                 (SEGSiteBase *)TraceHistory.sourceSite()) &&
        !bugConstraint->empty()) {

      DEBUG_WITH_TYPE("checker", dbgs() << "\nSet prerequisite\n");
      SEGNodeBase *source = (SEGNodeBase *)TraceHistory.sourceNode();
      // todo: handle condition for me
      //      Prerequisites.push_back(
      //          Solver->getOrInsertExpr(customSrcSink->startNode) ==
      //          Solver->getOrInsertExpr(source));
      Prerequisites.mergeWithAnd(*bugConstraint);
    }
  }

  virtual bool isSource(SEGNodeBase *Node, SEGSiteBase *Site) override {
    return customSrcSink->isSource(Node, Site);
  }

  virtual bool isSink(SEGNodeBase *Node, SEGSiteBase *Site) override {
    return customSrcSink->isSink(Node, Site);
  }

  virtual bool checkTrace(shared_ptr<VulnerabilityTrace> &Trace) {
    return customSrcSink->checkTrace(Trace);
  }
};

class SingleSrcMultiSink : public SrcMustNotReachSinkVulnerability {

public:
  vector<CustomSrcSink *> customSrcSinkVec;
  vector<int> traceOrder;

  SingleSrcMultiSink(const char *checkerName, GraphDiffer *graphParser,
                     bool fastMode, vector<Function *> peerFuncs,
                     InputNode *inputNode, vector<OutputNode *> outputNodes)
      : SrcMustNotReachSinkVulnerability(checkerName) {
    for (int i = 0; i < outputNodes.size(); i++) {
      auto customSrcSink = new CustomSrcSink(graphParser, peerFuncs, inputNode,
                                             outputNodes[i], fastMode);
      customSrcSinkVec.push_back(customSrcSink);
    }
  }

  virtual bool isSource(SEGNodeBase *Node, SEGSiteBase *Site) override {
    for (auto &checker : customSrcSinkVec) {
      if (checker->isSource(Node, Site)) {
        return true;
      }
    }
    return false;
  }

  virtual bool isSink(SEGNodeBase *Node, SEGSiteBase *Site) override {
    for (auto &checker : customSrcSinkVec) {
      if (checker->isSink(Node, Site)) {
        return true;
      }
    }
    return false;
  }

  virtual bool checkTrace(shared_ptr<VulnerabilityTrace> &Trace) {
    auto srcNode = (SEGNodeBase *)Trace->at(0);
    auto srcSite = (SEGSiteBase *)Trace->at(1);

    auto sinkNode = (SEGNodeBase *)Trace->at(Trace->get_length() - 2);
    auto sinkSite = (SEGSiteBase *)Trace->at(Trace->get_length() - 1);

    for (auto &checker : customSrcSinkVec) {
      if (checker->isSource(srcNode, srcSite) &&
          checker->isSink(sinkNode, sinkSite) && checker->checkTrace(Trace)) {
        return true;
      }
    }
    return false;
  }
};

#endif // CLEARBLUE_SINGLESRCSINGLESINK_H
