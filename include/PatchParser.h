#ifndef CLEARBLUE_PATCHPARSER_H
#define CLEARBLUE_PATCHPARSER_H

#include "bits/stdc++.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "Analysis/Bitcode/DebugInfoAnalysis.h"
#include "IR/ConstantsContext.h"
#include "Transform/ValueComparator.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Instruction.h"

using namespace std;
using namespace llvm;

struct ChangedLine {
  string sourceFile;
  unsigned line;
  Function *func;
  bool is_add;

  ChangedLine(StringRef str) {
    if (str[0] == '+') {
      is_add = true;
    } else if (str[0] == '-') {
      is_add = false;
    }
    str = str.drop_front();
    sourceFile = str.split(":").first.str();
    line = stoi(str.split(":").second.str());
  }

  friend raw_ostream &operator<<(raw_ostream &out, const ChangedLine &item) {
    out << item.sourceFile << ":" << item.line;
    return out;
  }

  bool operator<(const ChangedLine &item) const {
    return (sourceFile < item.sourceFile) && (line < item.line);
  }
};

class PatchParser {

  vector<ChangedLine> addedLines;
  vector<ChangedLine> removedLines;

  // cache of functions to the source line scopes
  map<Function *, pair<int, int>> funcLineScope;
  // cache of basic blocks to the source line scopes
  map<BasicBlock *, pair<int, int>> blockLineScope;

  map<Function *, string> funcSourceFile;

  Module *M;
  DebugInfoAnalysis *DIA;

  unsigned int guessInstructionLineNum(Instruction *inst);

  set<Function *> findEnclosedFunc(string srcFile, int line, bool isAdded);
  void getLineNumInsts(Function *func, int line, vector<Instruction *> &inst);

  void cacheFuncBBScope();
  void matchBBByLine();
  void matchUnChangedIRs();
  void matchAndDiffChangedIRs();
  void computeBeforeAfterLineMap();

  void parsePatchFile(string patchFile);

  bool isLineAdded(const string &srcfile, int lineNum);
  bool isLineRemoved(const string &srffile, int lineNum);

public:
  set<Value *> addedValues;
  set<Value *> removedValues;

  PatchParser(Module *M, DebugInfoAnalysis *pDIA, string patchFile);
  void parseIRChanges();
};

#endif // CLEARBLUE_PATCHPARSER_H
