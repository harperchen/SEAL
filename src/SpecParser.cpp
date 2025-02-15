#include "SpecParser.h"

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
    if (spec_info["Spec Type"] == "Src Must Not Reach Sink") {
      isBuggy = true;
    } else if (spec_info["Spec Type"] == "Src Must Reach Sink") {
      isBuggy = false;
    }

    if (spec_info["Order"].empty()) {
      InputNode *inputNode = nullptr;
      OutputNode *outputNode = nullptr;

      if (spec_info["Spec Input"].find("Indirect call") == 0) {
        inputNode = new IndirectArgNode(spec_info["Spec Input"]);
      } else if (spec_info["Spec Input"].find("Return") == 0) {
        inputNode = new ArgRetOfAPINode(spec_info["Spec Input"]);
      } else if (spec_info["Spec Input"].find("Error code") == 0) {
        inputNode = new ErrorCodeNode(spec_info["Spec Input"]);
      } else if (spec_info["Spec Input"].find("Global") == 0) {
        inputNode = new GlobalVarInNode(spec_info["Spec Input"]);
      } else {
      }

      if (spec_info["Spec Output"].find("Return") == 0) {
        outputNode = new IndirectRetNode(spec_info["Spec Output"]);
      } else if (spec_info["Spec Output"].find("Used in sensitive opcode") ==
                 0) {
        outputNode = new SensitiveOpNode(spec_info["Spec Output"]);
      } else if (spec_info["Spec Output"].find("Used in sensitive API") == 0) {
        outputNode = new SensitiveAPINode(spec_info["Spec Output"]);
      } else if (spec_info["Spec Output"].find("Used in customized API") == 0) {
        outputNode = new CustomizedAPINode(spec_info["Spec Output"]);
      } else if (spec_info["Spec Output"].find("Global") == 0) {
        outputNode = new GlobalVarOutNode(spec_info["Spec Output"], "");
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
        if (spec_info["Spec Cond SMT"] != "") {
          auto preExprVec = graphParser->SEGSolver->from_file(
              spec_info["Spec Cond SMT"].c_str());
          spec->condExprVec = &preExprVec;
        }
        driverBugSpecs.insert(spec);
      }
    } else {
      InputNode *inputNode = nullptr;
      vector<OutputNode *> outputNodes;

      inputNode = new InputNode(spec_info["Spec Input"]);

      vector<string> outputInfo;
      vector<string> outputOrder;
      std::stringstream ss(spec_info["Spec Output"]);
      std::string substring;

      while (std::getline(ss, substring, '$')) {
        outputInfo.push_back(substring);
      }

      std::stringstream order_ss(spec_info["Spec Orders"]);
      while (std::getline(order_ss, substring, '$')) {
        outputOrder.push_back(substring);
      }

      for (const auto &i : outputInfo) {
        auto outputNode = new OutputNode(i);
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
        for (int i = 0; i < outputOrder.size(); i++) {
          size_t underscorePos = outputOrder[i].find('_');
          std::string firstNumber = outputOrder[i].substr(0, underscorePos);
          std::string secondNumber = outputOrder[i].substr(underscorePos + 1);
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

void SpecParser::abstractBugSpec(string outputFile) {
  for (auto added : graphParser->addedInterTraces) {
    dbgs() << "\n3.1 [Add       Path]:\n";
    SEGWrapper->dumpEnhancedTraceCond(added);
    auto *inputNode = added->input_node;
    auto *outputNode = added->output_node;

    set<OutputNode *> outputNodes;
    SEGWrapper->canFindOutput(added->trace.trace, outputNodes, true, false);

    bool is_output_valid = false;
    for (auto output : outputNodes) {
      if (*output == *outputNode) {
        is_output_valid = true;
        break;
      }
    }
    if (!is_output_valid) {
      continue;
    }

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

    dbgs() << "\n[Spec Type] Src Must Reach Sink\n";
    dbgs() << "[Start "
           << added->trace.getFirstNode()
                  ->getParentGraph()
                  ->getBaseFunc()
                  ->getName()
           << "]\n   [InputNode]: " << *inputNode << "\n";

    dbgs() << "[End " << outputNode->nodeFuncName
           << "]\n   [OutputNode]: " << *outputNode << "\n";

    // we can enable it or not
    filterInvalidCond(added->trace.trace, added->conditions);
    dbgs() << "[Spec Cond]\n" << added->conditions->dump() << "\n";
    auto newSpec = new SingleSrcSingleSinkSpec(inputNode, outputNode, false);
    newSpec->conditions = added->conditions;
    addedPairs.insert(newSpec);

    dbgs() << "\n=======Added Single Src Single Sink Spec End #"
           << addedPairs.size() << "======\n";
  }

  for (auto removed : graphParser->removedInterTraces) {
    dbgs() << "\n3.1 [Removed         Path]:\n";
    SEGWrapper->dumpEnhancedTraceCond(removed);

    auto *inputNode = removed->input_node;
    auto *outputNode = removed->output_node;

    set<OutputNode *> outputNodes;
    SEGWrapper->canFindOutput(removed->trace.trace, outputNodes, false, false);

    bool is_output_valid = false;
    for (auto output : outputNodes) {
      if (*output == *outputNode) {
        is_output_valid = true;
        break;
      }
    }
    if (!is_output_valid) {
      continue;
    }

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
    dbgs() << "\n[Spec Type] Src Must Not Reach Sink\n";
    dbgs() << "[Start "
           << removed->trace.getFirstNode()
                  ->getParentGraph()
                  ->getBaseFunc()
                  ->getName()
           << "]\n   [InputNode]: " << *inputNode << "\n";

    DEBUG_WITH_TYPE(
        "spec", dbgs() << "[End " << outputNode->nodeFuncName
                       << "]\n   [OutputNode]: " << *outputNode << "\n";
        filterInvalidCond(removed->trace.trace, removed->conditions);
        dbgs() << "[Spec Cond]\n"
               << removed->conditions->dump() << "\n");
    auto newSpec = new SingleSrcSingleSinkSpec(inputNode, outputNode, true);
    newSpec->conditions = removed->conditions;
    removedPairs.insert(newSpec);

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
  specToOutput(outputFile);
}

void SpecParser::specToOutput(string outputFile) {
  dbgs() << "Spec in CSV: " << outputFile << "\n";
  std::ofstream csvFile(outputFile);

  if (!csvFile.is_open()) {
    std::cerr << "Failed to open the file." << std::endl;
    return;
  }
  csvFile << "Spec Type,Indirect Call,Spec Input,Spec Output,Spec Cond "
             "SMT,Spec Orders\n";

  int num_spec = 0;
  for (const auto &item : addedPairs) {
    csvFile << "Src Must Reach Sink";
    if (item->inputNode->type == IndirectArg) {
      csvFile << item->inputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else if (item->outputNode->type == IndirectRet) {
      csvFile << item->outputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else {
      csvFile << ",";
    }

    csvFile << item->inputNode->to_string() << ","
            << item->outputNode->to_string() << ",";

    size_t pos = outputFile.find_last_of("/\\");
    string baseDir =
        (pos == std::string::npos) ? "" : outputFile.substr(0, pos);
    string smtFilePath = baseDir + "/spec_smt_" + to_string(num_spec) + ".smt";
    std::ofstream smtFile(smtFilePath);

    // Write the string to the smtFile
    if (smtFile.is_open()) {
      string smt_string = "";
      SEGWrapper->SEGSolver->push();

      SEGWrapper->SEGSolver->add(
          SEGWrapper->condNode2SMTExprInter(item->conditions));
      SEGWrapper->SEGSolver->add(
          item->conditions->toSMTExpr(SEGWrapper->SEGSolver));
      smt_string = SEGWrapper->SEGSolver->to_smt2();
      SEGWrapper->SEGSolver->pop();

      smtFile << smt_string;
      smtFile.close();
    }
    csvFile << smtFilePath << ",,\n";
    num_spec += 1;
  }

  for (const auto &item : removedPairs) {
    csvFile << "Src Must Not Reach Sink,";
    if (item->inputNode->type == IndirectArg) {
      csvFile << item->inputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else if (item->outputNode->type == IndirectRet) {
      csvFile << item->outputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else {
      csvFile << ",";
    }
    csvFile << item->inputNode->to_string() << ","
            << item->outputNode->to_string() << ",";

    size_t pos = outputFile.find_last_of("/\\");
    string baseDir =
        (pos == std::string::npos) ? "" : outputFile.substr(0, pos);
    string smtFilePath = baseDir + "/spec_smt_" + to_string(num_spec) + ".smt";
    std::ofstream smtFile(smtFilePath);

    // Write the string to the smtFile
    if (smtFile.is_open()) {
      string smt_string = "";
      SEGWrapper->SEGSolver->push();
      SEGWrapper->SEGSolver->add(
          SEGWrapper->condNode2SMTExprInter(item->conditions));
      SEGWrapper->SEGSolver->add(
          item->conditions->toSMTExpr(SEGWrapper->SEGSolver));
      smt_string = SEGWrapper->SEGSolver->to_smt2();
      SEGWrapper->SEGSolver->pop();

      smtFile << smt_string;
      smtFile.close();
    }
    csvFile << smtFilePath << ",,\n";
    num_spec += 1;
  }

  for (const auto &item : condPairs) {
    csvFile << "Src Must Not Reach Sink,";
    if (item->inputNode->type == IndirectArg) {
      csvFile << item->inputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else if (item->outputNode->type == IndirectRet) {
      csvFile << item->outputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else {
      csvFile << ",";
    }
    csvFile << item->inputNode->to_string() << ","
            << item->outputNode->to_string() << ",";

    size_t pos = outputFile.find_last_of("/\\");
    string baseDir =
        (pos == std::string::npos) ? "" : outputFile.substr(0, pos);
    string smtFilePath = baseDir + "/spec_smt_" + to_string(num_spec) + ".smt";
    std::ofstream smtFile(smtFilePath);

    // Write the string to the smtFile
    if (smtFile.is_open()) {
      string smt_string = "";
      SEGWrapper->SEGSolver->push();
      SEGWrapper->SEGSolver->add(
          SEGWrapper->condNode2SMTExprInter(item->conditions));
      SEGWrapper->SEGSolver->add(
          item->conditions->toSMTExpr(SEGWrapper->SEGSolver));
      smt_string = SEGWrapper->SEGSolver->to_smt2();
      SEGWrapper->SEGSolver->pop();

      smtFile << smt_string;
      smtFile.close();
    }
    csvFile << smtFilePath << ",,\n";
    num_spec += 1;
  }

  for (const auto &item : orderPairs) {
    csvFile << "Src Must Not Reach Sink,";
    if (item->inputNode->type == IndirectArg) {
      csvFile << item->inputNode->usedNode->getParentGraph()
                     ->getBaseFunc()
                     ->getName()
                     .str()
              << ",";
    } else {
      csvFile << ",";
    }
    csvFile << item->inputNode->to_string() << ",";

    string order_info = "";
    for (int i = 0; i < item->outputNodes.size(); i++) {
      csvFile << item->outputNodes[i]->to_string();
      auto orders = item->output2Order[item->outputNodes[i]];
      order_info += to_string(orders.first) + "_" + to_string(orders.second);
      if (i != item->outputNodes.size() - 1) {
        csvFile << "$";
        order_info += "$";
      }
    }

    csvFile << ",,";
    csvFile << order_info << "\n";

    num_spec += 1;
  }

  csvFile.close();
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
      set<SEGNodeBase *> diffCondSEGNodes, diffValidCondSEGNodes;
      graphParser->diffTwoConditionSEGNodes(
          before->conditions, after->conditions, diffCondSEGNodes);
      if (diffCondSEGNodes.empty()) {
        continue;
      }

      filterInvalidCondNodes(after->trace.trace, diffCondSEGNodes,
                             diffValidCondSEGNodes);
      if (diffValidCondSEGNodes.empty()) {
        continue;
      }

      set<OutputNode *> outputNodes;
      SEGWrapper->canFindOutput(after->trace.trace, outputNodes, false, false);

      bool is_output_valid = false;
      for (auto output : outputNodes) {
        if (*output == *outputNodeAfter) {
          is_output_valid = true;
          break;
        }
      }
      if (!is_output_valid) {
        continue;
      }

      dbgs() << "\n3.2 [Conditional Changed Path]:\n";
      SEGWrapper->dumpEnhancedTraceCond(after);

      dbgs() << "[Condition Changed & Valid Nodes:]\n";
      printDiffConditionNodes(diffCondSEGNodes);

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
      auto notDiff = new ConditionNode(diff->SEGWrapper, NODE_NOT);
      notDiff->addChild(diff);
      dbgs() << "\n[Spec Type] Src Must Not Reach Sink\n";
      dbgs() << "[Start " << afterfuncName
             << "]\n   [InputNode]: " << *inputNodeAfter << "\n";

      dbgs() << "[End " << outputNodeAfter->nodeFuncName
             << "]\n   [OutputNode]: " << *outputNodeAfter << "\n";
      dbgs() << "[Spec Cond]\n" << notDiff->dump() << "\n";

      auto newCondPair =
          new SingleSrcSingleSinkSpec(inputNodeAfter, outputNodeAfter, false);
      newCondPair->conditions = notDiff;
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

    dbgs() << "\n[Start "
           << inputAfter->usedNode->getParentGraph()->getBaseFunc()->getName()
           << "]\n   "
           << "[InputNode]: " << *inputAfter << "\n";

    map<OutputNode *, pair<int, int>> output2Orders;
    for (auto [outputNodeAfter, order_num] : outputs) {
      output2Orders[outputNodeAfter] = {
          input2OrdersBefore[inputAfter][outputNodeAfter], order_num};

      "spec", dbgs() << "\n[End " << outputNodeAfter->nodeFuncName
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
            ssSpec->inputNode, ssSpec->outputNode, ssSpec->condExprVec);
      } else {
        vulnerability = new SingleSrcSingleSinkReach(
            "Checker", graphParser, ssSpec->fastMode, ssSpec->indirects,
            ssSpec->inputNode, ssSpec->outputNode, ssSpec->condExprVec);
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
  dbgs() << "Loading # Spec " << customizedCheckers.size() << "\n";
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
void SpecParser::filterInvalidCondNodes(
    vector<SEGObject *> &guardedTrace, set<SEGNodeBase *> &diffCondNodes,
    set<SEGNodeBase *> &diffValidCondNodes) {
  set<SEGNodeBase *> invalidCondNode;
  map<SEGNodeBase *, set<vector<SEGObject *>>> backwardTraces;
  SEGWrapper->condNode2FlowInter(diffCondNodes, backwardTraces);

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
      // guess the relation between guard trace and icmp node to filter out as
      // many icmp as possible
      bool hasIntersection = false;
      for (auto node : trace) {
        auto it =
            find_if(guardedTrace.begin(), guardedTrace.end(),
                    [&node](const SEGObject *cur) {
                      if (isa<SEGPseudoArgumentNode>(node) &&
                          isa<SEGPseudoArgumentNode>(cur)) {
                        auto *pseudoArg1 =
                            dyn_cast<SEGPseudoArgumentNode>(node);
                        auto *pseudoArg2 = dyn_cast<SEGPseudoArgumentNode>(cur);
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
          break;
        }
      }
      if (!hasIntersection) {
        invalidTraces.insert(trace);
      }
    }
    if (invalidTraces.size() == traces.size()) {
      invalidCondNode.insert(icmpNode);
    }
  }

  for (auto node : diffCondNodes) {
    if (invalidCondNode.count(node)) {
      continue;
    }
    diffValidCondNodes.insert(node);
  }
}

void SpecParser::filterInvalidCond(vector<SEGObject *> &guardedTrace,
                                   ConditionNode *condNode) {
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
      // guess the relation between guard trace and icmp node to filter out as
      // many icmp as possible
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
          break;
        }
      }
      if (!hasIntersection) {
        invalidTraces.insert(trace);
      }
    }
    if (invalidTraces.size() == traces.size()) {
      invalidCondNode.insert(icmpNode);
    }
  }
  auto vf_stop = chrono::high_resolution_clock::now();
  auto vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  filter_invalid_time += vf_duration.count();
  DEBUG_WITH_TYPE("time", dbgs() << "Time for Valid checking: "
                                 << filter_invalid_time / 1000 << "ms\n");

  //  dbgs() << "\n===Before Remove Invalid Cond:\n " << condNode->dump() <<
  //  "\n";

  vf_start = chrono::high_resolution_clock::now();
  for (auto node : invalidCondNode) {
    //    dbgs() << "[Invalid Cond Node] " << *node << "\n";
    condNode->eliminateCond(node);
  }
  condNode->simplify();
  //  dbgs() << "===After Remove Invalid Cond:\n " << condNode->dump() << "\n";
  vf_stop = chrono::high_resolution_clock::now();
  vf_duration =
      chrono::duration_cast<std::chrono::microseconds>(vf_stop - vf_start);
  simplify_cond += vf_duration.count();
  DEBUG_WITH_TYPE("statistics", dbgs() << "Simplify condition time: "
                                       << simplify_cond / 1000 << "ms\n");
}