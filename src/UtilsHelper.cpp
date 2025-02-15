#include "UtilsHelper.h"
#include "ConditionNode.h"

string getSrcFileName(Instruction *I) {
  string buffer;
  raw_string_ostream rso(buffer);
  I->getDebugLoc().print(rso);
  rso.flush();

  if (buffer.empty()) {
    return "";
  }

  string token;
  vector<std::string> tokens;
  istringstream tokenStream(buffer);

  while (getline(tokenStream, token, ':')) {
    tokens.push_back(token);
  }

  string source_file = tokens[0];
  if (source_file.empty()) {
    return "";
  }
  if (source_file.find("src/") != string::npos) {
    return "";
  }
  // TODO: extend here to support whole kernel
  if (source_file.find("drivers/") != string::npos) {
    source_file = source_file.substr(source_file.find("drivers/"));
  } else if (source_file.find("sound/") != string::npos) {
    source_file = source_file.substr(source_file.find("sound/"));
  }

  return source_file;
}

DILocation *getSourceLocation(Instruction *I) {
  if (!I)
    return NULL;

  MDNode *N = I->getMetadata("dbg");
  if (!N)
    return NULL;

  DILocation *Loc = new DILocation(N);
  if (!Loc || Loc->getLineNumber() < 1)
    return NULL;

  return Loc;
}

string getFileName(DILocation *Loc, DISubprogram *SP) {
  string FN;
  if (Loc) {
    FN = Loc->getDirectory().str() + "/" + Loc->getFilename().str();
  } else if (SP) {
    FN = SP->getDirectory().str() + "/" + SP->getFilename().str();
  } else {
    return "";
  }

  return FN;
}

/// Get the source code line
string getSourceLine(string fn_str, unsigned lineno) {
  ifstream sourcefile(fn_str);
  string line;
  sourcefile.seekg(ios::beg);

  for (int n = 0; n < lineno - 1; ++n) {
    sourcefile.ignore(std::numeric_limits<streamsize>::max(), '\n');
  }
  getline(sourcefile, line);

  return line;
}

string printSourceCodeInfo(Value *V) {
  Instruction *I = dyn_cast<Instruction>(V);
  if (!I) {
    return "";
  }

  DILocation *Loc = getSourceLocation(I);
  if (!Loc)
    return "";

  unsigned LineNo = Loc->getLineNumber();
  string FN = getFileName(Loc);
  string line = getSourceLine(FN, LineNo);

  if (FN.find("drivers/") != string::npos) {
    FN = FN.substr(FN.find("drivers/"));
  } else if (FN.find("sound/") != string::npos) {
    FN = FN.substr(FN.find("sound/"));
  } else if (FN.find("") != string::npos) {
    FN = FN.substr(FN.find(""));
  } else {
  }

  while (line[0] == ' ' || line[0] == '\t')
    line.erase(line.begin());
  return line;
}

void printDiffCondition(ConditionNode *diffs) {
  for (auto node : diffs->obtainNodes()) {
    printSourceCodeInfoWithValue(node->getLLVMDbgValue());
    DEBUG_WITH_TYPE("condition", dbgs() << *node->getLLVMDbgValue() << "\n");
  }
}

void printDiffConditionNodes(set<SEGNodeBase *> &diffNodes) {
  for (auto node : diffNodes) {
    printSourceCodeInfoWithValue(node->getLLVMDbgValue());
    dbgs() << *node->getLLVMDbgValue() << "\n";
  }
}

void printSourceCodeInfoWithValue(Value *V) {
  if (!V) {
    return;
  }
  Instruction *I = dyn_cast<Instruction>(V);
  if (!I) {
    if (auto *F = dyn_cast<Function>(V)) {
      DEBUG_WITH_TYPE("statistics", dbgs() << "[Code] " << F->getName());
    } else {
      DEBUG_WITH_TYPE("statistics", dbgs() << "[Code] " << *V);
    }
    return;
  }

  DILocation *Loc = getSourceLocation(I);
  if (!Loc)
    return;

  unsigned LineNo = Loc->getLineNumber();
  string FN = getFileName(Loc);
  string line = getSourceLine(FN, LineNo);

  if (FN.find("drivers/") != string::npos) {
    FN = FN.substr(FN.find("drivers/"));
  } else if (FN.find("sound/") != string::npos) {
    FN = FN.substr(FN.find("sound/"));
  } else if (FN.find("") != string::npos) {
    FN = FN.substr(FN.find(""));
  } else {
  }

  while (line[0] == ' ' || line[0] == '\t')
    line.erase(line.begin());
  DEBUG_WITH_TYPE("statistics",
                  dbgs() << "[Code] " << FN << " +" << LineNo << ": " << line);
}

void dumpVector(const vector<SEGObject *> &trace) {
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
        printSourceCodeInfoWithValue(inputNode->getCallSite().getInstruction());
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

void dumpVectorDbg(const vector<SEGObject *> &trace) {
  for (int i = 0; i < trace.size(); i++) {
    if (isa<SEGStoreMemNode>(trace[i])) {
      auto *storeNode = dyn_cast<SEGStoreMemNode>(trace[i]);
      if (storeNode->getStoreSiteAsStoreInst()) {
        printSourceCodeInfoWithValue(storeNode->getStoreSiteAsStoreInst());
      }
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else if (isa<SEGCallSitePseudoInputNode>(trace[i])) {
      auto *inputNode = dyn_cast<SEGCallSitePseudoInputNode>(trace[i]);
      if (inputNode->getCallSite().getInstruction()) {
        printSourceCodeInfoWithValue(inputNode->getCallSite().getInstruction());
      }
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else if (isa<SEGCallSiteOutputNode>(trace[i])) {
      auto *outputNode = dyn_cast<SEGCallSiteOutputNode>(trace[i]);
      if (outputNode->getCallSite()->getInstruction()) {
        printSourceCodeInfoWithValue(
            outputNode->getCallSite()->getInstruction());
      }
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else if (isa<SEGArgumentNode>(trace[i])) {
      auto *argNode = dyn_cast<SEGArgumentNode>(trace[i]);
      printSourceCodeInfoWithValue(&argNode->getParentGraph()
                                        ->getBaseFunc()
                                        ->getEntryBlock()
                                        .getInstList()
                                        .front());
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else if (isa<SEGPhiNode>(trace[i])) {
      auto *phiNode = dyn_cast<SEGPhiNode>(trace[i]);
      printSourceCodeInfoWithValue(phiNode->getLLVMDbgValue());
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else if (trace[i]->getLLVMDbgValue()) {
      printSourceCodeInfoWithValue(trace[i]->getLLVMDbgValue());
      dbgs() << "[Node] " << *trace[i] << "\n";
    } else {
      dbgs() << "[Node] " << *trace[i] << "\n";
    }
  }
  dbgs() << "\n";
}

string findABMatchFunc(string funcName) {
  if (funcName.find("after.patch.") != string::npos) {
    return funcName.replace(funcName.find("after."), strlen("after."),
                            "before.");
  }
  if (funcName.find("before.patch.") != string::npos) {
    return funcName.replace(funcName.find("before."), strlen("before."),
                            "after.");
  }
  return funcName;
}

void cleanStringPatch(string &str) {
  smatch match;
  // process string
  // remove c++ class type added by compiler
  size_t pos = str.find("(%class.");
  if (pos != string::npos) {
    // regex pattern1("\\(\\%class\\.[_A-Za-z0-9]+\\*,?");
    regex pattern("^[_A-Za-z0-9]+\\*,?");

    string str_sub = str.substr(pos + 8);
    if (regex_search(str_sub, match, pattern)) {
      str.replace(pos + 1, 7 + match[0].length(), "");
    }
  }
  regex pattern(R"(\.\d+)");
  // Remove all matching substrings
  str = regex_replace(str, pattern, "");
  string::iterator end_pos = remove(str.begin(), str.end(), ' ');
  str.erase(end_pos, str.end());
}

void cleanString(string &str) {
  smatch match;
  // process string
  // remove c++ class type added by compiler
  size_t pos = str.find("(%class.");
  if (pos != string::npos) {
    // regex pattern1("\\(\\%class\\.[_A-Za-z0-9]+\\*,?");
    regex pattern("^[_A-Za-z0-9]+\\*,?");

    string str_sub = str.substr(pos + 8);
    if (regex_search(str_sub, match, pattern)) {
      str.replace(pos + 1, 7 + match[0].length(), "");
    }
  }
  //  regex pattern(R"(\.\d+)");
  //  // Remove all matching substrings
  //  str = regex_replace(str, pattern, "");
  //  string::iterator end_pos = remove(str.begin(), str.end(), ' ');
  //  str.erase(end_pos, str.end());

  if (str.find("before.patch.") != string::npos) {
    str.erase(str.find("before.patch."), strlen("before.patch."));
  }
  if (str.find("after.patch.") != string::npos) {
    str.erase(str.find("after.patch."), strlen("after.patch."));
  }
}

string type2String(Type *Ty) {
  string sig;
  string ty_str;
  if (StructType *STy = dyn_cast<StructType>(Ty)) {
    if (STy->hasName()) {
      ty_str = STy->getName().str();
    }
  } else if (ArrayType *ATy = dyn_cast<ArrayType>(Ty)) {
    raw_string_ostream rso(sig);
    Ty->print(rso);
    ty_str = rso.str() + "[array]";
    string::iterator end_pos = remove(ty_str.begin(), ty_str.end(), ' ');
    ty_str.erase(end_pos, ty_str.end());
  } else {
    raw_string_ostream rso(sig);
    Ty->print(rso);
    ty_str = rso.str();
    if (isa<FunctionType>(Ty)) {
      cleanString(ty_str);
    }
    string::iterator end_pos = remove(ty_str.begin(), ty_str.end(), ' ');
    ty_str.erase(end_pos, ty_str.end());
  }

  cleanString(ty_str);
  return ty_str;
}

vector<SEGNodeBase *> getConstraintElement(SymbolicExprGraphSolver *SEGSolver,
                                           SMTExpr expr) {
  vector<SMTExpr> exprQueue;
  vector<SEGNodeBase *> exprElems;
  exprQueue.push_back(expr);

  while (!exprQueue.empty()) {
    SMTExpr curExpr = exprQueue.front();
    exprQueue.erase(exprQueue.begin());

    if (curExpr.numArgs() == 0) {
      string name = curExpr.getSymbol();
      if ('|' == name[0]) {
        name = name.substr(1, name.length() - 2);
      }
      if (!SEGSolver->getNodeFromSymbol(name)) {
        continue;
      }
      exprElems.push_back((SEGNodeBase *)SEGSolver->getNodeFromSymbol(name));
    }
    for (int i = 0; i < curExpr.numArgs(); i++) {
      exprQueue.push_back(curExpr.getArg(i));
    }
  }
  return exprElems;
}

ConstExpr *consToExprItem(SMTExpr constraint) {
  vector<ConstExpr *> itemQueue;
  vector<SMTExpr> constraintQueue;

  ConstExpr *root = new ConstExpr(constraint);
  itemQueue.push_back(root);

  constraintQueue.push_back(constraint);

  map<string, ConstExpr *> symbol2Node;
  symbol2Node[constraint.getSymbol()] = root;

  while (!constraintQueue.empty()) {
    SMTExpr curConst = constraintQueue.front();
    constraintQueue.erase(constraintQueue.begin());

    ConstExpr *curNode = itemQueue.front();
    itemQueue.erase(itemQueue.begin());

    if (!curConst.isLogicAnd() && !curConst.isLogicOr() &&
        curConst.numArgs() == 2) { // not compositional logic formula
      continue;
    }

    for (int i = 0; i < curConst.numArgs(); i++) {
      ConstExpr *childNode;
      if (symbol2Node.find(curConst.getArg(i).getSymbol()) !=
          symbol2Node.end()) {
        childNode = symbol2Node[curConst.getArg(i).getSymbol()];
      } else {
        childNode = new ConstExpr(curConst.getArg(i));
        childNode->is_removed = false;
        symbol2Node[curConst.getArg(i).getSymbol()] = childNode;
      }

      curNode->childItems.push_back(childNode);
      curNode->childExprs.push_back(curConst.getArg(i));

      itemQueue.push_back(childNode);
      constraintQueue.push_back(curConst.getArg(i));
    }
  }
  return root;
}

ConstExpr *filterConstraint(SymbolicExprGraphSolver *SEGSolver,
                            SMTExpr constraint,
                            vector<SEGNodeBase *> statistics) {
  vector<ConstExpr *> itemQueue;
  vector<SMTExpr> constraintQueue;

  ConstExpr *root = new ConstExpr(constraint);
  itemQueue.push_back(root);

  constraintQueue.push_back(constraint);

  map<string, ConstExpr *> symbol2Node;
  symbol2Node[constraint.getSymbol()] = root;

  vector<ConstExpr *> tobePropagted;
  vector<SEGNodeBase *> isRelevant = statistics;

  while (!constraintQueue.empty()) {
    SMTExpr curConst = constraintQueue.front();
    constraintQueue.erase(constraintQueue.begin());

    ConstExpr *curNode = itemQueue.front();
    itemQueue.erase(itemQueue.begin());

    if (!curConst.isLogicAnd() && !curConst.isLogicOr() &&
        !curConst.isLogicNot()) { // not compositional logic formula
      vector<SEGNodeBase *> elements =
          getConstraintElement(SEGSolver, curConst);
      if (elements.size() <= 2) {
        tobePropagted.push_back(curNode);
      }
      if (elements.size() == 1) {
        auto elem = elements[0];
        if (std::find(isRelevant.begin(), isRelevant.end(), elem) !=
            isRelevant.end()) {
          curNode->is_removed = false;
          DEBUG_WITH_TYPE("condition", dbgs() << "Add relevant "
                                              << curConst.getSymbol() << "\n");
        }
        continue;
      }
    }

    for (int i = 0; i < curConst.numArgs(); i++) {
      ConstExpr *childNode;
      if (symbol2Node.find(curConst.getArg(i).getSymbol()) !=
          symbol2Node.end()) {
        childNode = symbol2Node[curConst.getArg(i).getSymbol()];
      } else {
        childNode = new ConstExpr(curConst.getArg(i));
        symbol2Node[curConst.getArg(i).getSymbol()] = childNode;
      }

      curNode->childItems.push_back(childNode);
      curNode->childExprs.push_back(curConst.getArg(i));

      itemQueue.push_back(childNode);
      constraintQueue.push_back(curConst.getArg(i));
    }
  }

  // propagate to sibling
  while (true) {
    int changedSize = 0;
    for (auto curConst : tobePropagted) {

      bool has_relavent = false;
      for (int i = 0; i < curConst->childItems.size(); i++) {
        if (!curConst->childItems[i]->is_removed) {
          has_relavent = true;
        }
      }

      if (has_relavent) {
        for (int i = 0; i < curConst->childItems.size(); i++) {
          if (curConst->childItems[i]->is_removed) {
            curConst->childItems[i]->is_removed = false;
            changedSize += 1;
            DEBUG_WITH_TYPE(
                "condition",
                dbgs() << "Add into relavent "
                       << curConst->childItems[i]->curExpr.getSymbol() << "\n");
            if (SEGSolver->getNodeFromSymbol(
                    curConst->childItems[i]->curExpr.getSymbol())) {
              isRelevant.push_back((SEGNodeBase *)SEGSolver->getNodeFromSymbol(
                  curConst->childItems[i]->curExpr.getSymbol()));
            }
          }
        }
      }

      if (curConst->is_removed) {
        vector<SEGNodeBase *> elements =
            getConstraintElement(SEGSolver, curConst->curExpr);
        if (elements.size() == 1) {
          auto elem = elements[0];
          if (std::find(isRelevant.begin(), isRelevant.end(), elem) !=
              isRelevant.end()) {
            curConst->is_removed = false;
            changedSize += 1;
            DEBUG_WITH_TYPE("condition", dbgs() << "Add relevant "
                                                << curConst->curExpr.getSymbol()
                                                << "\n");
          }
        }
      }
    }

    if (!changedSize) {
      break;
    }
  }

  // populate parent expr
  while (true) {
    int changedSize = 0;
    for (auto pair : symbol2Node) {
      auto node = pair.second;
      bool has_relavent = false;

      for (int i = 0; i < node->childItems.size(); i++) {
        if (!node->childItems[i]->is_removed) {
          has_relavent = true;
        }
      }

      if (has_relavent && node->is_removed) {
        node->is_removed = false;
        changedSize += 1;
      }
    }
    if (!changedSize) {
      break;
    }
  }
  //  reconstruct expr from tree
  return root;
}

ConstExpr *negateConstraint(SMTExpr constraint) {
  vector<ConstExpr *> itemQueue;
  vector<SMTExpr> constraintQueue;

  ConstExpr *root = new ConstExpr(constraint);
  itemQueue.push_back(root);

  constraintQueue.push_back(constraint);

  map<string, ConstExpr *> symbol2Node;
  symbol2Node[constraint.getSymbol()] = root;

  while (!constraintQueue.empty()) {
    SMTExpr curConst = constraintQueue.front();
    constraintQueue.erase(constraintQueue.begin());

    ConstExpr *curNode = itemQueue.front();
    itemQueue.erase(itemQueue.begin());

    if (!curConst.isLogicAnd() && !curConst.isLogicOr() &&
        curConst.numArgs() == 2) { // not compositional logic formula
      for (int i = 0; i < curConst.numArgs(); i++) {
        if (curConst.getArg(i).isNumeral()) {
          curNode->is_negated = true;
          break;
        }
      }
      continue;
    }

    for (int i = 0; i < curConst.numArgs(); i++) {
      ConstExpr *childNode;
      if (symbol2Node.find(curConst.getArg(i).getSymbol()) !=
          symbol2Node.end()) {
        childNode = symbol2Node[curConst.getArg(i).getSymbol()];
      } else {
        childNode = new ConstExpr(curConst.getArg(i));
        childNode->is_removed = false;
        symbol2Node[curConst.getArg(i).getSymbol()] = childNode;
      }

      curNode->childItems.push_back(childNode);
      curNode->childExprs.push_back(curConst.getArg(i));

      itemQueue.push_back(childNode);
      constraintQueue.push_back(curConst.getArg(i));
    }
  }
  return root;
}

ConstExpr *negateAndFilterCons(SymbolicExprGraphSolver *SEGSolver,
                               SMTExpr bugConstraint,
                               vector<SEGNodeBase *> trace) {

  DEBUG_WITH_TYPE("condition",
                  dbgs() << "Origined " << bugConstraint.getSymbol() << "\n");
  // step 1.2: filter out irrelevant nodes in constraints
  ConstExpr *filtered = filterConstraint(SEGSolver, bugConstraint, trace);
  DEBUG_WITH_TYPE("condition",
                  dbgs() << "Filtered "
                         << filtered
                                ->toExpr(SEGSolver, &SEGSolver->ExprStr2Operand,
                                         &SEGSolver->ExprStr2Opcode)
                                .toAndExpr()
                                .getSymbol()
                         << "\n");
  //  step 2: negate the constraint, forms the bug constraint
  ConstExpr *negated =
      negateConstraint(filtered
                           ->toExpr(SEGSolver, &SEGSolver->ExprStr2Operand,
                                    &SEGSolver->ExprStr2Opcode)
                           .toAndExpr());
  DEBUG_WITH_TYPE("condition",
                  dbgs() << "Negated "
                         << negated
                                ->toExpr(SEGSolver, &SEGSolver->ExprStr2Operand,
                                         &SEGSolver->ExprStr2Opcode)
                                .toAndExpr()
                                .getSymbol()
                         << "\n");

  //  step 3: align the constraint with the peer function
  //  step 4: check whether the constraint sat or not
}

string get_excopy_name(Value *value) {
  string name = "";
  if (!value) {
    return name;
  }

  if (value->hasName()) {
    name = value->getName().str();
  } else if (auto *loadInst = dyn_cast<LoadInst>(value)) {
    name = get_excopy_name(loadInst->getPointerOperand());
  } else if (auto *callInst = dyn_cast<CallInst>(value)) {
    name = get_excopy_name(callInst->getCalledValue());
  } else if (auto *castInst = dyn_cast<BitCastInst>(value)) {
    name = get_excopy_name(castInst->stripPointerCasts());
  } else if (auto *storeInst = dyn_cast<StoreInst>(value)) {
    name = get_excopy_name(storeInst->getPointerOperand());
  } else if (auto *gepOp = dyn_cast<GEPOperator>(value)) {
    name = get_excopy_name(gepOp->getPointerOperand());
  } else {
  }
  return name;
}
bool is_excopy_val(Value *value) {
  auto name = get_excopy_name(value);
  if (name.find(".ex_copy") != string::npos) {
    return true;
  }
  if (name.find(".loop_copy") != string::npos) {
    return true;
  }
  return false;
}
