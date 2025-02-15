#pragma once

#include "IR/SEG/SymbolicExprGraphSolver.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>

class EnhancedSEGWrapper;

using namespace std;
using namespace llvm;

enum NodeType {
  NODE_AND,
  NODE_OR,
  NODE_NOT,
  NODE_CONST,
  NODE_VAR,
};

class ConditionNode {
public:
  NodeType type;
  LLVMContext context;
  SEGNodeBase *value = nullptr;
  vector<ConditionNode *> children;

  EnhancedSEGWrapper *SEGWrapper;

  ConditionNode(EnhancedSEGWrapper *SEGWrapper, NodeType t)
      : type(t), SEGWrapper(SEGWrapper) {}

  ConditionNode(EnhancedSEGWrapper *SEGWrapper, SEGNodeBase *value)
      : type(NODE_VAR), value(value), SEGWrapper(SEGWrapper) {}

  ConditionNode(EnhancedSEGWrapper *SEGWrapper, NodeType t, SEGNodeBase *value)
      : type(t), value(value), SEGWrapper(SEGWrapper) {}

  void clear() {
    this->type = NODE_CONST;
    this->value = nullptr;
    this->children.clear();
  }

  bool isEqual(ConditionNode *other);

  // Add child node
  void addChild(ConditionNode *child) { children.push_back(child); }

  SMTExpr toSMTExpr(SymbolicExprGraphSolver *SEGSolver) {
    SMTExprVec exprVec = SEGSolver->getSMTFactory().createEmptySMTExprVec();
    for (auto child : children) {
      exprVec.push_back(child->toSMTExpr(SEGSolver));
    }

    if (this->type == NODE_AND) {
      return exprVec.toAndExpr();
    } else if (this->type == NODE_OR) {
      return exprVec.toOrExpr();
    } else if (this->type == NODE_NOT) {
      return !exprVec[0];
    } else if (this->type == NODE_VAR) {
      return SEGSolver->getOrInsertExpr(value) == 1;
    } else if (this->type == NODE_CONST) {
      return exprVec.toAndExpr();
    }
  }

  set<SEGNodeBase *> obtainNodes() {
    set<SEGNodeBase *> allSEGNodes;
    if (this->value) {
      allSEGNodes.insert(this->value);
    }
    for (auto child : children) {
      set<SEGNodeBase *> childSEGNodes = child->obtainNodes();
      allSEGNodes.insert(childSEGNodes.begin(), childSEGNodes.end());
    }
    return allSEGNodes;
  }

  static string myValueToString(const Value *value) {
    std::string str;
    llvm::raw_string_ostream rso(str);
    value->print(rso);
    return rso.str();
  }

  // Function to dump the tree
  string dump(int level = 0) const {
    // Print indentation for current level
    ostringstream ss;
    string indent(level * 2, ' ');

    // Print the type of the node
    ss << indent;
    switch (type) {
    case NODE_AND:
      ss << "AND";
      break;
    case NODE_OR:
      ss << "OR";
      break;
    case NODE_NOT:
      ss << "NOT";
      break;
    case NODE_VAR:
      ss << "VALUE";
      break;
    }

    // If the node has a value, print it
    if (value != nullptr) {
      string valueStr = "(" + myValueToString(value->getLLVMDbgValue()) + ")";
      ss << valueStr;
    }

    if (type == NODE_OR || type == NODE_AND) {
      ss << "\n";
    }

    // Recursively dump children
    for (auto child : children) {
      ss << child->dump(level + 1);
      if (type == NODE_OR) {
        ss << "\n";
      }
    }
    return ss.str();
  }

  ConditionNode *processNode(ConditionNode *node);

  ConditionNode *distribute(ConditionNode *node, int depth, bool &changed);
  ConditionNode *distributeORoverAND(ConditionNode *node, size_t index,
                                     int depth, bool &changed);
  ConditionNode *distributeANDoverOR(ConditionNode *node, size_t index,
                                     int depth, bool &changed);

  void simplify();
  void simplifyConst();
  void simplifyAnd();
  void simplifyOr();
  void simplifyNot();

  void eliminateCond(SEGNodeBase *node);

  bool isAbsorptionLaw(ConditionNode *a, vector<ConditionNode *> &b);

  bool isEqual(ConditionNode *a, ConditionNode *b);
  bool isNegation(ConditionNode *a, ConditionNode *b);
  void addUnique(vector<ConditionNode *> &list, ConditionNode *node);
};

class ConditionTree {

public:
  static ConditionNode *parseFromString(string str,
                                        EnhancedSEGWrapper *SEGWrapper,
                                        set<SEGNodeBase *> nodeSet);
  static ConditionNode *simplifyCondition(EnhancedSEGWrapper *SEGWrapper,
                                          ConditionNode *node);
  static ConditionNode *diffCondition(ConditionNode *node1,
                                      ConditionNode *node2);
};
