#include "include/SpecParser.h"

static cl::opt<bool>
    FastMode("fast-mode", cl::desc("Detect bugs using patch specifications."),
             cl::init(false), cl::Hidden);

SpecParser::SpecParser(EnhancedSEGWrapper *SEGWrapper,
                       GraphDiffer *graphParser) {
  this->SEGWrapper = SEGWrapper;
  this->graphParser = graphParser;
}

static string getSrcFile(Function *F) {
  for (auto &BB : *F) {
    for (auto &Inst : BB) {
      MDNode *N = Inst.getMetadata("dbg");
      if (N) {
        DILocation Loc(N);
        return Loc.getFilename();
      }
    }
  }
  return "";
}

string normalizePathFalcon(string path) {
  std::vector<std::string> components;
  std::stringstream ss(path);
  std::string component;

  // Split the path into components
  while (std::getline(ss, component, '/')) {
    if (component.empty() || component == ".") {
      continue;
    } else if (component == "..") {
      if (!components.empty()) {
        components.pop_back();
      }
    } else {
      components.push_back(component);
    }
  }

  // Join the components back into a normalized path
  std::string normalized;
  for (const std::string &comp : components) {
    normalized += "/" + comp;
  }
  if (!normalized.empty()) {
    normalized = normalized.substr(1);
  }
  return normalized.empty() ? "" : normalized;
}

static Function *getFuncByName(Module *M, string path_and_name) {
  // transform source file path and name to bc function name
  auto file_path =
      normalizePathFalcon(path_and_name.substr(0, path_and_name.find(':')));
  auto source_func_name = path_and_name.substr(path_and_name.find(':') + 1);

  //  for (auto &F : *M) {
  //    string cur_file_path = normalizePathFalcon(getSrcFile(&F));
  //
  //    if (file_path != cur_file_path) {
  //      continue;
  //    }
  //    auto func_name = F.getName().str();
  //
  //    if (func_name.find(source_func_name) == 0) {
  //      return &F;
  //    }
  //  }
  return M->getFunction(source_func_name);
}
void SpecParser::loadSpecFromFile(string fileName) {
  std::ifstream inFile(fileName);
  std::vector<std::unordered_map<std::string, std::string>> spec_data;

  if (!inFile.is_open()) {
    std::cerr << "Unable to open file " << fileName << std::endl;
  } else {
    string line;
    string column;
    vector<string> columnNames;
    bool isFirstLine = true;

    while (getline(inFile, line)) {
      unordered_map<string, string> row;
      istringstream iss(line);
      size_t columnIdx = 0;

      while (std::getline(iss, column, ',')) {
        if (isFirstLine) {
          columnNames.push_back(column);
        } else {
          row[columnNames[columnIdx]] = column;
          columnIdx++;
        }
      }
      if (!isFirstLine) {
        spec_data.push_back(row);
      }
      isFirstLine = false;
    }

    inFile.close();
  }

  for (auto &spec_info : spec_data) {
    Function *indirectFunc = nullptr;
    string indirectName = spec_info["Indirect Call"];
    indirectFunc = getFuncByName(graphParser->SEGWrapper->M, indirectName);
    graphParser->loadPeerFuncLines(spec_info["Peers"]);

    bool isBuggy = true;
    if (spec_info["Spec Type"] == "Add") {
      isBuggy = false;
    }

    if (spec_info["Order"] == "") {
      InputNode *inputNode = nullptr;
      OutputNode *outputNode = nullptr;

      if (spec_info["Input Node"].find("Indirect call") == 0) {
        inputNode = new IndirectArgNode(spec_info["Input Node"]);
      } else if (spec_info["Input Node"].find("Return") == 0) {
        inputNode = new ArgRetOfAPINode(spec_info["Input Node"]);
      } else if (spec_info["Input Node"].find("Error code") == 0) {
        inputNode = new ErrorCodeNode(spec_info["Input Node"]);
      } else if (spec_info["Input Node"].find("Global") == 0) {
        inputNode = new GlobalVarInNode(spec_info["Input Node"]);
      } else {
      }

      if (spec_info["Output Node"].find("Return") == 0) {
        outputNode = new IndirectRetNode(spec_info["Output Node"]);
      } else if (spec_info["Output Node"].find("Used in sensitive opcode") ==
                 0) {
        outputNode = new SensitiveOpNode(spec_info["Output Node"]);
      } else if (spec_info["Output Node"].find("Used in sensitive API") == 0) {
        outputNode = new SensitiveAPINode(spec_info["Output Node"]);
      } else if (spec_info["Output Node"].find("Used in customized API") == 0) {
        outputNode = new CustomizedAPINode(spec_info["Output Node"]);
      } else if (spec_info["Output Node"].find("Global") == 0) {
        outputNode = new GlobalVarOutNode(spec_info["Output Node"], "");
      } else {
      }

      if (inputNode && outputNode) {

        vector<Function *> peerFuncs;
        if (indirectFunc) {
          graphParser->getPeerFuncs(indirectFunc, peerFuncs);
        }
        if (FastMode.getValue()) {
          for (auto peer : peerFuncs) {
            this->peerFuncs.insert(peer);
          }
        }

        auto spec = new SingleSrcSingleSinkSpec(
            inputNode, outputNode, peerFuncs, isBuggy, FastMode.getValue());
        if (spec_info["Constraint"] != "") {
          // TODO: to be changed
          spec->constExpr = nullptr;
        }
        driverBugSpecs.insert(spec);
      } else {
        dbgs()  << "Invalid Spec " << spec_info["Directory"] << "\n";
      }
    } else {
      // TODO: to be changed
      InputNode *inputNode = nullptr;
      vector<OutputNode *> outputNodes;

      inputNode = new InputNode(spec_info["Input Node"]);

      vector<string> outputInfo;
      vector<int> outputOrder;
      std::stringstream ss(spec_info["Output Node"]);
      std::string substring;

      while (std::getline(ss, substring, '$')) {
        outputInfo.push_back(substring);
      }

      std::stringstream order_ss(spec_info["Order"]);
      while (std::getline(order_ss, substring, '$')) {
        outputOrder.push_back(std::stoi(substring));
      }

      for (int i = 0; i < outputInfo.size(); i++) {
        auto outputNode = new OutputNode(outputInfo[i]);
        if (outputNode) {
          outputNodes.push_back(outputNode);
        }
      }

      if (inputNode && !outputNodes.empty()) {
        vector<Function *> peerFuncs;
        if (indirectFunc) {
          graphParser->getPeerFuncs(indirectFunc, peerFuncs);
        }
        if (FastMode.getValue()) {
          for (auto peer : peerFuncs) {
            this->peerFuncs.insert(peer);
          }
        }
        auto spec = new SingleSrcMultiSinkSpec(inputNode, outputNodes,
                                               peerFuncs, FastMode.getValue());
        for (int i = 0; i < outputNodes.size(); i++) {
          size_t underscorePos = outputInfo[i].find('_');

          // Extract the first number
          std::string firstNumber = outputInfo[i].substr(0, underscorePos);

          // Extract the second number
          std::string secondNumber = outputInfo[i].substr(underscorePos + 1);

          // Convert the extracted numbers to integers
          int first = std::stoi(firstNumber);
          int second = std::stoi(secondNumber);
          spec->output2Order[outputNodes[i]] = {first, second};
        }
        driverBugSpecs.insert(spec);
      }
    }
  }
}

bool SpecParser::isTransitiveCallee(Function *func) {
  if (peerFuncs.empty()) {
    return true;
  }
  for (auto peer : peerFuncs) {
    if (SEGWrapper->isTransitiveCallee(peer, func)) {
      return true;
    }
  }
  return false;
}

void SpecParser::abstractBugSpec() {

  for (auto added : graphParser->addedInterTraces) {
    added->trace.dump();
    auto *inputNode = added->input_node;
    auto *outputNode = added->output_node;
    if (!SEGWrapper->ifInOutputMatch(inputNode, outputNode)) {
      continue;
    }
    bool find_same = false;
    for (auto pair : addedPairs) {
      if (isTwoInputNodeEq(pair->inputNode, inputNode) &&
          isTwoOutputNodeEq(pair->outputNode, outputNode)) {
        find_same = true;
        break;
      }
    }
    if (find_same) {
      continue;
    }
    DEBUG_WITH_TYPE(
        "spec", dbgs() << "\n=======Added Single Src Single Sink Spec Start #"
                       << addedPairs.size() << "======\n");
    added->trace.dump();

    dbgs() << "[Add Start "
           << added->trace.getFirstNode()
                  ->getParentGraph()
                  ->getBaseFunc()
                  ->getName()
           << "]\n   [InputNode]: " << *inputNode << "\n";

    dbgs() << "[Add End " << outputNode->nodeFuncName
           << "]\n   [OutputNode]: " << *outputNode << "\n";

    // we can enable it or not
    //      filterInvalidCond(added->trace, added->conditions);
    dbgs() << "[Add Expr Start]\n"
           << added->conditions->dump() << "\n[Add Expr End]\n";

    addedPairs.insert(
        new SingleSrcSingleSinkSpec(inputNode, outputNode, false));

    dbgs() << "\n=======Added Single Src Single Sink Spec End #"
           << addedPairs.size() << "======\n";
  }

  for (auto removed : graphParser->removedInterTraces) {
    auto *inputNode = removed->input_node;
    auto *outputNode = removed->output_node;
    if (!SEGWrapper->ifInOutputMatch(inputNode, outputNode)) {
      continue;
    }
    bool find_same = false;
    for (auto pair : removedPairs) {
      if (isTwoInputNodeEq(pair->inputNode, inputNode) &&
          isTwoOutputNodeEq(pair->outputNode, outputNode)) {
        find_same = true;
        break;
      }
    }
    if (find_same) {
      continue;
    }

    DEBUG_WITH_TYPE(
        "spec", dbgs() << "\n=======Removed Single Src Single Sink Spec Start #"
                       << removedPairs.size() << "======\n");
    removed->trace.dump();

    dbgs() << "[Remove Start "
           << removed->trace.getFirstNode()
                  ->getParentGraph()
                  ->getBaseFunc()
                  ->getName()
           << "]\n   [InputNode]: " << *inputNode << "\n";

    DEBUG_WITH_TYPE(
        "spec", dbgs() << "[Remove End " << outputNode->nodeFuncName
                       << "]\n   [OutputNode]: " << *outputNode << "\n";
        //      filterInvalidCond(removed->trace, removed->conditions);
        dbgs() << "[Removed Expr Start]\n"
               << removed->conditions->dump() << "\n[Removed Expr End]\n");

    removedPairs.insert(
        new SingleSrcSingleSinkSpec(inputNode, outputNode, true));

    DEBUG_WITH_TYPE(
        "spec", dbgs() << "\n=======Removed Single Src Single Sink Spec End #"
                       << removedPairs.size() << "======\n");
  }

  handleDiffCondition();
  groupSingleSrcMultiSink();

  dbgs() << "\n=======Added Spec:  #" << addedPairs.size() << "========\n";
  dbgs() << "\n=======Remove Spec: #" << removedPairs.size() << "========\n";
  dbgs() << "\n=======Cond Spec:   #" << condPairs.size() << "========\n";
  dbgs() << "\n=======Order Spec:  #" << orderPairs.size() << "========\n";
}

void SpecParser::handleDiffCondition() {
  for (const auto &it : graphParser->changedCondInterTraces) {
    auto before = it.first, after = it.second;

    auto beforefuncName = before->trace.getFirstNode()
                              ->getParentGraph()
                              ->getBaseFunc()
                              ->getName();
    auto afterfuncName =
        after->trace.getFirstNode()->getParentGraph()->getBaseFunc()->getName();

    if (afterfuncName.startswith("after.patch.") &&
        beforefuncName.startswith("before.patch.")) {

      auto inputNodeAfter = after->input_node;
      auto outputNodeAfter = after->output_node;
      if (!SEGWrapper->ifInOutputMatch(inputNodeAfter, outputNodeAfter)) {
        continue;
      }
      // todo: time consuming
      ConditionNode *diff =
          graphParser->diffTwoConditions(before->conditions, after->conditions);
      if (!diff) {
        continue;
      }
      bool find_same = false;
      for (auto pair : condPairs) {
        if (isTwoInputNodeEq(pair->inputNode, inputNodeAfter) &&
            isTwoOutputNodeEq(pair->outputNode, outputNodeAfter) &&
            pair->conditions->isEqual(diff)) {
          find_same = true;
          break;
        }
      }

      if (find_same) {
        continue;
      }

      DEBUG_WITH_TYPE(
          "statistics",
          dbgs() << "\n=======Condition Single Src Single Sink Spec Start #"
                 << condPairs.size() << "======\n");
      // diff condition and generate bug spec;

      dbgs() << "\n[Cond Start " << afterfuncName
             << "]\n   [InputNode]: " << *inputNodeAfter << "\n";

      dbgs() << "[Cond End " << outputNodeAfter->nodeFuncName
             << "]\n   [OutputNode]: " << *outputNodeAfter << "\n";
      dbgs() << "[Cond Node Start]\n" << diff->dump() << "\n[Cond Node End]\n";
      printDiffCondition(diff);
      SEGWrapper->SEGSolver->push();
      SEGWrapper->SEGSolver->add(SEGWrapper->condNode2SMTExprInter(diff));
      SEGWrapper->SEGSolver->add(diff->toSMTExpr(SEGWrapper->SEGSolver));
      dbgs() << "[Cond Expr Start]\n"
             << SEGWrapper->SEGSolver->to_smt2() << "\n[Cond Expr End]\n";
      SEGWrapper->SEGSolver->pop();

      auto newCondPair =
          new SingleSrcSingleSinkSpec(inputNodeAfter, outputNodeAfter, false);
      newCondPair->conditions = diff;
      condPairs.insert(newCondPair);

      DEBUG_WITH_TYPE(
          "spec", dbgs() << "=======Condition Single Src Single Sink Spec End #"
                         << condPairs.size() << "======\n");
    }
  }
}

void SpecParser::groupSingleSrcMultiSink() {
  map<InputNode *, map<OutputNode *, int>> input2OrdersBefore;
  map<InputNode *, map<OutputNode *, int>> input2OrdersAfter;

  // todo: handle equal input
  for (const auto &it : graphParser->changedOrderInterTraces) {
    auto before = it.first;
    auto after = it.second;

    auto beforeName = before->trace.getFirstNode()
                          ->getParentGraph()
                          ->getBaseFunc()
                          ->getName();
    auto afterName =
        after->trace.getFirstNode()->getParentGraph()->getBaseFunc()->getName();

    if (afterName.empty() || beforeName.empty()) {
      dbgs() << "!!!Empty parent name:\n";
      after->trace.dump();
      dbgs() << after->trace.getFirstNode()
                    ->getParentGraph()
                    ->getBaseFunc()
                    ->getName()
             << "\n";
      dbgs() << after->trace.getLastNode()
                    ->getParentGraph()
                    ->getBaseFunc()
                    ->getName()
             << "\n";
    }

    if (!afterName.startswith("after.patch.") ||
        !beforeName.startswith("before.patch.")) {
      continue;
    }

    auto inputAfter = after->input_node;

    InputNode *exist_input = nullptr;
    for (const auto &item : input2OrdersAfter) {
      if (*inputAfter == *item.first) {
        exist_input = item.first;
        break;
      }
    }

    if (!exist_input) {
      exist_input = inputAfter;

      input2OrdersBefore[exist_input].insert(
          {after->output_node, before->output_order});
      input2OrdersAfter[exist_input].insert(
          {after->output_node, after->output_order});

    } else {

      for (auto exist_output : input2OrdersAfter[exist_input]) {
        if (*after->output_node == *exist_output.first) {
          continue;
        }
        input2OrdersBefore[exist_input].insert(
            {after->output_node, before->output_order});
        input2OrdersAfter[exist_input].insert(
            {after->output_node, after->output_order});
      }
    }
  }

  for (auto [inputAfter, outputs] : input2OrdersAfter) {
    vector<OutputNode *> beforeOutputs, afterOutputs;

    vector<pair<OutputNode *, int>> vecBefore(
        input2OrdersBefore[inputAfter].begin(),
        input2OrdersBefore[inputAfter].end());
    sort(vecBefore.begin(), vecBefore.end(),
         [](const pair<OutputNode *, int> &a,
            const pair<OutputNode *, int> &b) { return a.second < b.second; });

    for (const auto &pair : vecBefore) {
      beforeOutputs.push_back(pair.first);
    }

    vector<pair<OutputNode *, int>> vecAfter(outputs.begin(), outputs.end());
    sort(vecAfter.begin(), vecAfter.end(),
         [](const pair<OutputNode *, int> &a,
            const pair<OutputNode *, int> &b) { return a.second < b.second; });

    for (const auto &pair : vecAfter) {
      afterOutputs.push_back(pair.first);
    }

    if (beforeOutputs == afterOutputs) {
      continue;
    }

    dbgs() << "\n=======Order Single Src Multiple Sink Spec Start #"
           << orderPairs.size() << "======\n";

    dbgs() << "\n[Ord Start "
           << inputAfter->usedNode->getParentGraph()->getBaseFunc()->getName()
           << "]\n   " << "[InputNode]: " << *inputAfter << "\n";

    map<OutputNode *, pair<int, int>> output2Orders;
    for (auto [outputNodeAfter, order_num] : outputs) {
      output2Orders[outputNodeAfter] = {
          input2OrdersBefore[inputAfter][outputNodeAfter], order_num};

      "spec", dbgs() << "\n[Ord End " << outputNodeAfter->nodeFuncName
                     << "]\n   [OutputNode]: " << *outputNodeAfter << "\n";
      dbgs() << "   [OutputSite]: " << *outputNodeAfter->usedSite << "\n";

      dbgs() << "    [Ord Num Before]: "
             << input2OrdersBefore[inputAfter][outputNodeAfter]
             << ", [Order Num After]: " << order_num << "\n";
    }
    dbgs() << "\n";

    auto newOrderPair =
        new SingleSrcMultiSinkSpec(inputAfter, afterOutputs, output2Orders);
    orderPairs.insert(newOrderPair);
  }
}


void SpecParser::transformToCheckers() {
  for (auto spec : driverBugSpecs) {
    Vulnerability *vulnerability = nullptr;
    if (spec->type == BugSpecification::BS_SingleSrcSingleSink) {
      auto ssSpec = (SingleSrcSingleSinkSpec *)spec;
      if (ssSpec->isBuggy) {
        vulnerability = new SingleSrcSingleSink(
            "Checker", graphParser, ssSpec->fastMode, ssSpec->indirects,
            ssSpec->inputNode, ssSpec->outputNode, ssSpec->constExpr);
      } else {
        vulnerability = new SingleSrcSingleSinkReach(
            "Checker", graphParser, ssSpec->fastMode, ssSpec->indirects,
            ssSpec->inputNode, ssSpec->outputNode, ssSpec->constExpr);
      }
    } else if (spec->type == BugSpecification::BS_SingleSrcMultiSink) {
      auto smSpec = (SingleSrcMultiSinkSpec *)spec;
      vulnerability = new SingleSrcMultiSink(
          "Checker", graphParser, smSpec->fastMode, smSpec->indirects,
          smSpec->inputNode, smSpec->outputNodes);
    } else {
    }

    if (vulnerability) {
      shared_ptr<Vulnerability> sharedPtr(vulnerability);
      sharedPtr->setParasitical(false);
      customizedCheckers.push_back(sharedPtr);
    }
  }
  dbgs()  << "Loading # Spec " << customizedCheckers.size() << "\n";
}

bool SpecParser::isTwoInputNodeEq(InputNode *node1, InputNode *node2) {
  if (node1->type != node2->type) {
    return false;
  }
  if (node1 == node2 || *node1 == *node2) {
    return true;
  }

  switch (node1->type) {
  case IndirectArg: {
    auto *indirectArgNode1 = (IndirectArgNode *)node1;
    auto *indirectArgNode2 = (IndirectArgNode *)node2;

    if ((graphParser->isPeerFunc(indirectArgNode1->funcName,
                                 indirectArgNode2->funcName) ||
         indirectArgNode1->funcName == indirectArgNode2->funcName) &&
        indirectArgNode1->argName == indirectArgNode2->argName) {
      return true;
    }
    return false;
  }

  case ErrorCode: {
    auto *errorCodeNode1 = (ErrorCodeNode *)node1;
    auto *errorCodeNode2 = (ErrorCodeNode *)node2;
    if (isTwoInputNodeEq(errorCodeNode1->inputNode,
                         errorCodeNode2->inputNode) &&
        errorCodeNode1->errorCode == errorCodeNode2->errorCode) {
      return true;
    }
  }
  }
  return false;
}

bool SpecParser::isTwoOutputNodeEq(OutputNode *node1, OutputNode *node2) {
  if (node1 == node2 || *node1 == *node2) {
    return true;
  }
  // TODO: equivalence between APIs and API and sensitive operations
  if (node1->type != SensitiveAPI && node1->type != SensitiveOp &&
      node2->type != SensitiveAPI && node2->type != SensitiveOp) {
    if (node1->type != node2->type) {
      return false;
    }
  }
  switch (node1->type) {
  case IndirectRet: {
    auto *indirectRetNode1 = (IndirectRetNode *)node1;
    auto *indirectRetNode2 = (IndirectRetNode *)node2;

    if (graphParser->isPeerFunc(indirectRetNode1->funcName,
                                indirectRetNode2->funcName)) {
      return true;
    }
    return false;
  }
  case SensitiveOp: {
    auto *sensitiveOpNode1 = (SensitiveOpNode *)node1;
    if (node2->type == SensitiveAPI) {
      auto *sensiAPINode2 = (SensitiveAPINode *)node2;
      // todo: handle api <=> ops
    }
    return false;
  }
  }
  return false;
}

void SpecParser::filterInvalidCond(
    vector<SEGObject *> &guardedTrace,
    ConditionNode* condNode) {
  auto vf_start = chrono::high_resolution_clock::now();

  set<SEGNodeBase *> invalidCondNode;
  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardTraces;
  SEGWrapper->condNode2FlowInter(condNode->obtainNodes(), backwardTraces);

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
      // guess the relation between guard trace and icmp node to filter out as many icmp as possible
      bool hasIntersection = false;
      for (auto node : trace) {
        auto it = find_if(
            guardedTrace.begin(), guardedTrace.end(),
            [&node](const SEGObject *cur) {
              if (isa<SEGPseudoArgumentNode>(node) &&
                  isa<SEGPseudoArgumentNode>(cur)) {
                auto *pseudoArg1 = dyn_cast<SEGPseudoArgumentNode>(node);
                auto *pseudoArg2 = dyn_cast<SEGPseudoArgumentNode>(cur);
                dbgs() << pseudoArg1->getParentGraph()->getBaseFunc()->getName()
                       << " " << *pseudoArg1 << "\n";
                dbgs() << pseudoArg2->getParentGraph()->getBaseFunc()->getName()
                       << " " << *pseudoArg2 << "\n";
                return pseudoArg1->getAccessPath().get_base_ptr() ==
                       pseudoArg2->getAccessPath().get_base_ptr();
              }
              if (isa<SEGCallSiteCommonOutputNode>(node) &&
                  isa<SEGCallSiteCommonOutputNode>(cur)) {
                return true;
              }
              return cur == node;
            });
        if (it != guardedTrace.end()) {
          hasIntersection = true;
          dbgs() << "====Checking Have Intersection: " << *icmpNode << "\n";
          ;
          break;
        }
      }
      if (!hasIntersection) {
        invalidTraces.insert(trace);
      }
    }
    if (invalidTraces.size() == traces.size()) {
      invalidCondNode.insert(icmpNode);
      dbgs() << "Irrelevant iCmp: ";
      printSourceCodeInfoWithValue(icmpNode->getLLVMDbgValue());
      dbgs() << *icmpNode << "\n";
    }
  }
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  filter_invalid_time += vf_duration.count();
  DEBUG_WITH_TYPE("time", dbgs() << "Time for Valid checking: "
                                 << filter_invalid_time / 1000 << "ms\n");

  dbgs() << "\n===Before Remove Invalid Cond:\n " << condNode->dump() << "\n";

  vf_start = chrono::high_resolution_clock::now();
  for (auto node : invalidCondNode) {
    dbgs() << "[Invalid Cond Node] " << *node << "\n";
    condNode->eliminateCond(node);
  }
  condNode->simplifyConst();
  dbgs() << "===After Remove Invalid Cond:\n " << condNode->dump() << "\n";
  vf_stop = chrono::high_resolution_clock::now();
  vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  simplify_cond += vf_duration.count();
  DEBUG_WITH_TYPE("statistics", dbgs() << "Simplify condition time: "
                                       << simplify_cond / 1000 << "ms\n");
}