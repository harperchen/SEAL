
#ifndef CLEARBLUE_UTILSHELPER_H
#define CLEARBLUE_UTILSHELPER_H

#include "Analysis/Graph/ControlDependenceGraph.h"
#include "IR/SEG/SEGCallSite.h"
#include "IR/SEG/SEGCallSiteOutputNode.h"
#include "IR/SEG/SEGCallSitePseudoInputNode.h"
#include "IR/SEG/SEGPhiNode.h"
#include "IR/SEG/SEGReturnSite.h"
#include "IR/SEG/SymbolicExprGraph.h"
#include "IR/SEG/SymbolicExprGraphSolver.h"
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Casting.h>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "ConditionNode.h"

using namespace std;
using namespace llvm;

struct ConstExpr {
  SMTExpr curExpr;

  bool is_removed, is_negated;
  bool islogicOr, islogicAnd, islogicNot;

  vector<SMTExpr> childExprs;
  vector<ConstExpr *> childItems;
  string expr_str;

  ConstExpr(SMTExpr curExpr) : curExpr(curExpr) {
    is_removed = true;
    is_negated = false;

    islogicAnd = curExpr.isLogicAnd();
    islogicOr = curExpr.isLogicOr();
    islogicNot = curExpr.isLogicNot();

    expr_str = curExpr.getSymbol();
  };

  string remove_newlines(string s) {
    size_t pos;
    while (
        (pos = s.find('\n')) !=
        std::string::npos) { // find the position of the next newline character
      s.erase(pos, 1);       // erase the newline character
    }
    return s;
  }

  int get_number(string s) {
    bool is_hex = *s.begin() == 'x';
    s = s.substr(1, s.length() - 1);
    size_t pos;
    if (is_hex) {
      int n = stoi(s, &pos,
                   16); // try to convert the string to a hexadecimal integer
      return n;
    } else {
      int n = stoi(s, &pos,
                   2); // try to convert the string to a hexadecimal integer
      return n;
    }
  }

  SMTExpr
  newExpr(std::string tobeCopied, SymbolicExprGraphSolver *segSolver,
          std::unordered_map<std::string, const SEGNodeBase *> *expr2Operand,
          std::unordered_map<std::string, const SEGOpcodeNode *> *expr2Opcode) {
    SMTExpr Ret = segSolver->getSMTFactory().createEmptySMTExpr();

    if (!expr2Opcode->count(tobeCopied)) {

      if (tobeCopied.front() == '#') { // if number
        tobeCopied = tobeCopied.substr(1, tobeCopied.length() - 1);
        if (tobeCopied.front() == 'x') {
          return segSolver->getSMTFactory().createBitVecVal(
              get_number(tobeCopied), 64);
        }
        if (tobeCopied.front() == 'b') {
          return segSolver->getSMTFactory().createBitVecVal(
              get_number(tobeCopied), 1);
        }
      }

      tobeCopied = remove_newlines(tobeCopied);
      if (tobeCopied.front() == '(' && tobeCopied.back() == ')') {
        tobeCopied = tobeCopied.substr(1, tobeCopied.size() - 2);
      }
      string token;
      vector<string> tokens;
      vector<SMTExpr> exprs;
      stringstream ss(tobeCopied);
      while (ss >> token) {
        tokens.push_back(token);
      }
      if (tokens.size() == 1) {

      } else {
        string opcode = tokens[0];
        for (int i = 1; i < tokens.size(); i++) {
          string name = tokens[i];
          if ('|' == name[0]) {
            name = name.substr(1, name.length() - 2);
          }
          if (!expr2Operand->count(name)) {
            exprs.push_back(
                newExpr(tokens[i], segSolver, expr2Operand, expr2Opcode));
          } else {
            exprs.push_back(
                segSolver->getOrInsertExpr(expr2Operand->find(name)->second));
          }
        }
        if (opcode == "=") {
          Ret = (exprs[0] == exprs[1]);
        } else if (opcode == "bvadd") {
          Ret = exprs[0].array_add(exprs[1], 1);
        } else if (opcode == "bvugt") {
          Ret = exprs[0].array_ugt(exprs[1], 1);
        }
      }
    } else {
      auto OpcodeNode = expr2Opcode->find(tobeCopied)->second;
      if (OpcodeNode->isBinaryNode()) {
        Ret = segSolver->encodeBinaryOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isCastNode()) {
        Ret = segSolver->encodeCastOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isSelectNode()) {
        Ret = segSolver->encodeSelectOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isExtractElmtNode()) {
        Ret = segSolver->encodeExtractElementOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isInsertElmtNode()) {
        Ret = segSolver->encodeInsertElementOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isCmpNode()) {
        Ret = segSolver->encodeCompareOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isGEPNode()) {
        Ret = segSolver->encodeGEPOpcodeNode(OpcodeNode);
      } else if (OpcodeNode->isConcatNode()) {
        Ret = segSolver->encodeConcatOpcodeNode(OpcodeNode);
      } else {
        llvm_unreachable("Unsupported opcode!");
      }
    }
    return Ret;
  }

  SMTExprVec
  toExpr(SymbolicExprGraphSolver *segSolver,
         std::unordered_map<std::string, const SEGNodeBase *> *expr2Operand,
         std::unordered_map<std::string, const SEGOpcodeNode *> *expr2Opcode) {
    SMTExprVec exprVec = segSolver->Factory->createEmptySMTExprVec();
    if (!islogicAnd and !islogicOr and !islogicNot) {
      if (is_negated) {
        exprVec.push_back(
            !newExpr(expr_str, segSolver, expr2Operand, expr2Opcode));
      } else {
        exprVec.push_back(
            newExpr(expr_str, segSolver, expr2Operand, expr2Opcode));
      }
      return exprVec;
    }
    for (int i = 0; i < childItems.size(); i++) {
      if (!childItems[i]->is_removed) {
        if (islogicNot xor is_negated) {
          exprVec.push_back(!childItems[i]
                                 ->toExpr(segSolver, expr2Operand, expr2Opcode)
                                 .toAndExpr());
        } else {
          if (islogicAnd or islogicNot) {
            exprVec.mergeWithAnd(
                childItems[i]->toExpr(segSolver, expr2Operand, expr2Opcode));
          } else if (islogicOr) {
            exprVec.mergeWithOr(
                childItems[i]->toExpr(segSolver, expr2Operand, expr2Opcode));
          } else {
            //            dbgs() << "Error\n";
          }
        }
      }
    }
    return exprVec;
  }
};

vector<SEGNodeBase *> getConstraintElement(SymbolicExprGraphSolver *SEGSolver,
                                           SMTExpr expr);

ConstExpr *filterConstraint(SymbolicExprGraphSolver *SEGSolver,
                            SMTExpr constraint, vector<SEGNodeBase *> segTrace);

ConstExpr *negateConstraint(SMTExpr constraint);

ConstExpr *negateAndFilterCons(SymbolicExprGraphSolver *SEGSolver,
                               SMTExpr bugConstraint,
                               vector<SEGNodeBase *> trace);

ConstExpr *consToExprItem(SMTExpr constraint);
string myValueToString(Value *value);
string type2String(Type *Ty);
void cleanString(string &str);
void cleanStringPatch(string &str);

string findABMatchFunc(string funcName);

DILocation *getSourceLocation(Instruction *I);
string getSrcFileName(Instruction *I);
string printSourceCodeInfo(Value *V);
void printSourceCodeInfoWithValue(Value *V);

string getFileName(DILocation *Loc, DISubprogram *SP = NULL);
string getSourceLine(string fn_str, unsigned lineno);
string getFileName(DILocation *Loc, DISubprogram *SP);

void dumpVector(const vector<SEGObject *> &trace);
void dumpVectorDbg(const vector<SEGObject *> &trace);
void printDiffCondition(ConditionNode *diffs);
void printDiffConditionNodes(set<SEGNodeBase *> &diffNodes);

bool is_excopy_val(Value *value);
string get_excopy_name(Value *value);

#endif // CLEARBLUE_UTILSHELPER_H
