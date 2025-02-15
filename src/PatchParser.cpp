
#include "PatchParser.h"
#include "UtilsHelper.h"
#include "ValueHelper.h"

static cl::opt<bool, false>
    DumpDiffProcess("dump-ir-diff",
                    cl::desc("Dump the process of IR difference."),
                    cl::init(false), cl::Hidden);

PatchParser::PatchParser(Module *M, DebugInfoAnalysis *pDIA, string patchFile) {
  this->M = M;
  DIA = pDIA;
  cacheFuncBBScope();

  parsePatchFile(patchFile);
  computeBeforeAfterLineMap();
}

void PatchParser::parseIRChanges() {
  //  for (auto func : changedFuncs) {
  //    outs() << *func << "\n";
  //  }

  matchBBByLine();
  matchUnChangedIRs();
  matchAndDiffChangedIRs();

  dbgs() << "\n=========1 [Print PatchParser Statistics] =======\n";
  dbgs() << "[# Added   LLVM Values]: " << addedValues.size() << "\n";
  dbgs() << "[# Removed LLVM Values]: " << removedValues.size() << "\n";
  dbgs() << "[# Matched IRs Before]: " << matchedIRsBefore.size() << "\n";
  dbgs() << "[# Matched IRs After]: " << matchedIRsAfter.size() << "\n";

  for (auto [beforeIR, afterIR] : matchedIRsBefore) {
    if (auto *bb = dyn_cast<BasicBlock>(beforeIR)) {
      if (!changedFuncs.count(bb->getParent())) {
        continue;
      }
      DEBUG_WITH_TYPE("statistics", dbgs() << "1.0 Matched BB Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");

    } else if (auto *inst = dyn_cast<Instruction>(beforeIR)) {
      if (!changedFuncs.count(inst->getParent()->getParent())) {
        continue;
      }
      DEBUG_WITH_TYPE("statistics", dbgs() << "1.0 Matched IR Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");
    } else {
      DEBUG_WITH_TYPE("statistics", dbgs() << "1.0 Matched Value Before\n"
                                           << *beforeIR << "\n"
                                           << *afterIR << "\n");
    }
  }
  // make sure matchedIRsBefore and matchedIRAfter have the same number of
  // mappings
  for (auto [beforeIR, afterIR] : matchedIRsBefore) {
    if (matchedIRsAfter.count(afterIR) == 0) {
      dbgs() << "!!!Incorrect in matched IR after: " << *afterIR << "\n";
    }
  }
}

// for each function in module, compute their start and end source code line
// number
void PatchParser::cacheFuncBBScope() {
  for (Function &F : *M) {
    if (F.getName().find("clearblue") != string::npos) {
      continue;
    }
    if (F.empty()) {
      continue;
    }

    string final_source_file;
    int start_line = -1, end_line;

    for (BasicBlock &B : F) {
      auto bb_name = B.getName();
      if (bb_name.find("ex_copy") != string::npos) {
        continue;
      }
      if (bb_name.find("loop_copy") != string::npos) {
        continue;
      }
      int start_bb_line = -1;
      int end_bb_line;
      for (Instruction &I : B) {
        if (auto *callInst = dyn_cast<CallInst>(&I)) {
          if (callInst->getCalledFunction() &&
              callInst->getCalledFunction()->hasName() &&
              callInst->getCalledFunction()->getName().startswith("llvm.dbg")) {
            continue;
          }
        }

        auto line = I.getDebugLoc().getLine();
        if (getSrcFileName(&I) == "") {
          continue;
        }
        final_source_file = getSrcFileName(&I);
        if (start_line == -1) {
          start_line = line;
          end_line = start_line;
        }

        if (start_bb_line == -1) {
          start_bb_line = line;
          end_bb_line = start_bb_line;
        }
        if (line >= start_bb_line) {
          end_bb_line = line;
        }
      }

      if (start_bb_line != -1) {
        pair<int, int> startEndPair(start_bb_line, end_bb_line);
        blockLineScope.insert({&B, startEndPair});
        if (end_bb_line > end_line) {
          end_line = end_bb_line;
        }
      }
    }

    if (!final_source_file.empty() && start_line != -1) {
      pair<int, int> startEndPair(start_line, end_line);
      funcLineScope.insert({&F, startEndPair});
      funcSourceFile.insert({&F, final_source_file.c_str()});
    }
  }
}

// Given diff file, identify changed functions and lines
void PatchParser::parsePatchFile(string patchFile) {
  ifstream file(patchFile);

  if (file.fail()) {
    return;
  }
  if (file.is_open()) {
    string line, curFunc;
    while (getline(file, line)) {
      if (line[0] == '+') {
        auto addLine = ChangedLine(line);
        auto add_funcs =
            findEnclosedFunc(addLine.sourceFile, addLine.line, true);
        for (auto func : add_funcs) {
          addLine.func = func;
          changedFuncs.insert(addLine.func);
          changedFuncs.insert(
              M->getFunction(findABMatchFunc(addLine.func->getName())));
          addedLines.push_back(addLine);
        }
      } else if (line[0] == '-') {
        auto removedLine = ChangedLine(line);
        auto removed_funcs =
            findEnclosedFunc(removedLine.sourceFile, removedLine.line, false);
        for (auto func : removed_funcs) {
          removedLine.func = func;
          changedFuncs.insert(removedLine.func);
          changedFuncs.insert(
              M->getFunction(findABMatchFunc(removedLine.func->getName())));
          removedLines.push_back(removedLine);
        }
      }
    }
    file.close();
  }

  for (auto F : changedFuncs) {
    DEBUG_WITH_TYPE("statistics", dbgs() << *F << "\n");
  }
}

// Establish the line number mapping between pre- and post- patch codes
void PatchParser::computeBeforeAfterLineMap() {
  // handle changed function
  for (auto before_func : changedFuncs) {
    if (before_func->getName().startswith("after.patch.")) {
      continue;
    }
    auto after_func = M->getFunction(findABMatchFunc(before_func->getName()));

    map<int, int> codeUnChangedInFunc;
    map<int, int> codeChangedInFunc;

    string srcfile = funcSourceFile[before_func];
    int before_line = funcLineScope[before_func].first; // before line
    int after_line = funcLineScope[after_func].first;   // after line

    while (before_line <= funcLineScope[before_func].second) {
      bool isAdded = isLineAdded(srcfile, after_line);
      bool isRemoved = isLineRemoved(srcfile, before_line);
      if (!isAdded && !isRemoved) {
        codeUnChangedInFunc.insert({before_line, after_line});
        before_line++;
        after_line++;
      } else if (isAdded && !isRemoved) {
        after_line++;
      } else if (!isAdded) {
        before_line++;
      } else { // all changed, do not map
        codeChangedInFunc.insert({before_line, after_line});
        before_line++;
        after_line++;
      }
    }

    if (after_line <= funcLineScope[after_func].second) {
      codeUnChangedInFunc.insert({before_line, after_line});
      before_line++;
      after_line++;
    }

    if (unChangedMapping.find(srcfile) == unChangedMapping.end()) {
      unChangedMapping[srcfile];
    }

    if (changedMapping.find(srcfile) == changedMapping.end()) {
      changedMapping[srcfile];
    }

    unChangedMapping[srcfile].insert(codeUnChangedInFunc.begin(),
                                     codeUnChangedInFunc.end());
    changedMapping[srcfile].insert(codeChangedInFunc.begin(),
                                   codeChangedInFunc.end());
  }

  // handle unchanged functions
  for (auto it : funcLineScope) {
    if (changedFuncs.find(it.first) != changedFuncs.end()) {
      continue;
    }
    if (it.first->getName().startswith("after.patch.")) {
      continue;
    }
    map<int, int> codeUnChangedInFunc;

    auto before_func = it.first;
    auto after_func = M->getFunction(findABMatchFunc(before_func->getName()));

    string srcfile = funcSourceFile[before_func];
    int before_line = funcLineScope[before_func].first;
    int after_line = funcLineScope[after_func].first;

    while (before_line <= funcLineScope[before_func].second) {
      codeUnChangedInFunc.insert({before_line, after_line});
      before_line++;
      after_line++;
    }
    unChangedMapping[srcfile].insert(codeUnChangedInFunc.begin(),
                                     codeUnChangedInFunc.end());
  }
}

void PatchParser::matchBBByLine() {
  map<string, map<pair<int, int>, vector<BasicBlock *>>> valueToBlocks;

  for (const auto &entry : blockLineScope) {
    auto *block = entry.first;
    auto src_file = funcSourceFile[block->getParent()];
    if (!valueToBlocks.count(src_file)) {
      valueToBlocks[src_file];
    }

    std::pair<int, int> value;
    if (block->getParent()->getName().startswith("after.patch")) {
      value.first = entry.second.first;
      value.second = entry.second.second;
      //       if (changedFuncs.count(block->getParent())) {
      //         dbgs() << "\nSrc file: " << src_file << "\n";
      //         dbgs() << "Range of original after bb " << block->getName() <<
      //         " in "
      //                << block->getParent()->getName() << " is from "
      //                << entry.second.first << " to " << entry.second.second
      //                << "\n";
      //       }
    } else {
      //       if (changedFuncs.count(block->getParent())) {
      //         dbgs() << "\nSrc file: " << src_file << "\n";
      //         dbgs() << "Range of before bb " << block->getName() << " in "
      //                << block->getParent()->getName() << " is from "
      //                << entry.second.first << " to " << entry.second.second
      //                << "\n";
      //       }
      if (unChangedMapping.count(src_file)) {
        if (unChangedMapping[src_file].count(entry.second.first) &&
            unChangedMapping[src_file].count(entry.second.second)) {
          value.first = unChangedMapping[src_file][entry.second.first];
          value.second = unChangedMapping[src_file][entry.second.second];
          //           if (changedFuncs.count(block->getParent())) {
          //             dbgs() << "Range of mapped after bb " <<
          //             block->getName() << " in "
          //                    << block->getParent()->getName() << " is from "
          //                    << value.first << " to " << value.second <<
          //                    "\n";
          //           }
        } else {
          //          dbgs() << "!!!Warn: not matched\n");
          continue;
        }
      }
    }
    valueToBlocks[src_file][value].push_back(block);
  }

  for (auto &[srcfile, bbMap] : valueToBlocks) {
    for (auto item : bbMap) {
      set<BasicBlock *> beforeBBs, afterBBs;
      auto pairedBlocks = item.second;
      if (pairedBlocks.empty()) {
        continue;
      }
      //      if (changedFuncs.count(pairedBlocks.front()->getParent())) {
      //        DEBUG_WITH_TYPE("statistics", dbgs() << "Range of mapped from "
      //        << item.first.first << " to "
      //               << item.first.second << ": " << pairedBlocks.size()
      //               << "\nbb name:");
      //        for (auto block : pairedBlocks) {
      //          DEBUG_WITH_TYPE("statistics", dbgs() << " " <<
      //          block->getName());
      //        }
      //        DEBUG_WITH_TYPE("statistics", dbgs() << "\n");
      //      }
      if (pairedBlocks.size() >= 2) {
        for (auto bb : pairedBlocks) {
          if (bb->getParent()->getName().startswith("before.patch")) {
            beforeBBs.insert(bb);
          }
          if (bb->getParent()->getName().startswith("after.patch")) {
            afterBBs.insert(bb);
          }
        }
      } else {
        for (auto bbBefore : pairedBlocks) {
          if (changedFuncs.count(bbBefore->getParent())) {
            DEBUG_WITH_TYPE("statistics",
                            dbgs() << "Line Scope UnMatched Before BB:"
                                   << bbBefore->getName() << "\n");
          }
        }
        unMatchedBBs.insert(pairedBlocks.begin(), pairedBlocks.end());
        continue;
      }

      for (auto bbBefore : beforeBBs) {
        for (auto bbAfter : afterBBs) {
          if (matchedIRsAfter.count(bbAfter)) {
            continue;
          }
          if (isTwoValueMatchedHelper(bbBefore, bbAfter)) {
            if (changedFuncs.count(bbBefore->getParent())) {
              DEBUG_WITH_TYPE("statistics", dbgs()
                                                << "Line Scope Matched BB:"
                                                << bbBefore->getName() << ", "
                                                << bbAfter->getName() << "\n");
            }
            matchedIRsBefore.insert({bbBefore, bbAfter});
            matchedIRsAfter.insert({bbAfter, bbBefore});
            break;
          }
        }
        if (!matchedIRsBefore.count(bbBefore)) {
          if (changedFuncs.count(bbBefore->getParent())) {
            DEBUG_WITH_TYPE("statistics",
                            dbgs() << "Line Scope UnMatched Before BB:"
                                   << bbBefore->getName() << "\n");
          }
          unMatchedBBs.insert(bbBefore);
        }
      }

      for (auto bbAfter : afterBBs) {
        if (!matchedIRsAfter.count(bbAfter)) {
          if (changedFuncs.count(bbAfter->getParent())) {
            DEBUG_WITH_TYPE("statistics",
                            dbgs() << "Line Scope UnMatched After BB:"
                                   << bbAfter->getName() << "\n");
          }
          unMatchedBBs.insert(bbAfter);
        }
      }
    }
  }
}

void PatchParser::matchUnChangedIRs() {
  dbgs() << "\n=======1.1 Same Line But Different IRs========\n";
  for (auto [srcfile, lineNumMap] : unChangedMapping) {
    for (auto [beforeLine, afterLine] : lineNumMap) {
      vector<Instruction *> beforeIRs, afterIRs;

      auto before_funcs = findEnclosedFunc(srcfile, beforeLine, false);
      for (auto func : before_funcs) {
        getLineNumInsts(func, beforeLine, beforeIRs);
      }

      auto after_funcs = findEnclosedFunc(srcfile, afterLine, true);
      for (auto func : after_funcs) {
        getLineNumInsts(func, afterLine, afterIRs);
      }

      bool is_print = false;
      for (auto beforeIR : beforeIRs) {
        if (isCurrentIRSkipMatch(beforeIR)) {
          continue;
        }
        bool find_match = false;
        if (matchedIRsBefore.count(beforeIR)) {
          find_match = true;
        } else {
          for (auto afterIR : afterIRs) {
            if (isCurrentIRSkipMatch(afterIR)) {
              continue;
            }
            if (matchedIRsAfter.find(afterIR) != matchedIRsAfter.end()) {
              continue;
            }
            if (!isTwoIRMatched(beforeIR, afterIR, true)) {
              continue;
            }
            find_match = true;
            break;
          }
        }

        if (!find_match) {
          if (!is_print) {
            dbgs() << "\n===============Line: " << srcfile << " +" << beforeLine
                   << ": " << printSourceCodeInfo(beforeIR) << "\n";
            is_print = true;
          }
          dbgs() << "[" << beforeIR->getParent()->getParent()->getName()
                 << "]: Removed IR " << *beforeIR << "\n";
          removedValues.insert(beforeIR);
          if (DumpDiffProcess.getValue()) {
            for (auto afterIR : afterIRs) {
              dbgs() << "\tCompare with candidate IR: " << *afterIR << "\n";
              if (matchedIRsAfter.find(afterIR) != matchedIRsAfter.end() &&
                  isTwoIRMatched(beforeIR, afterIR, true)) {

                dbgs() << "\tCompare with candidate IR: "
                       << *matchedIRsAfter[afterIR] << "\n";
              }
            }
          }
        }
      }

      is_print = false;
      for (auto afterIR : afterIRs) {
        if (matchedIRsAfter.find(afterIR) == matchedIRsAfter.end() &&
            !isCurrentIRSkipMatch(afterIR)) {
          if (!is_print) {
            dbgs() << "\n===============Line: " << srcfile << " +" << afterLine
                   << ": " << printSourceCodeInfo(afterIR) << "\n";
            is_print = true;
          }
          dbgs() << "[" << afterIR->getParent()->getParent()->getName()
                 << "]: Added IR " << *afterIR << "\n";
          addedValues.insert(afterIR);
          if (DumpDiffProcess.getValue()) {
            for (auto beforeIR : beforeIRs) {
              if (matchedIRsBefore.find(beforeIR) == matchedIRsBefore.end()) {
                dbgs() << "\tCompare with candidate IR: " << *beforeIR << "\n";
                dbgs() << "\t" << isTwoIRMatched(beforeIR, afterIR) << "\n";
              }
            }
          }
        }
      }
    }
  }
}

void PatchParser::matchAndDiffChangedIRs() {
  dbgs() << "\n=======1.2 Different Line And Different IRs========\n";
  // add instructions in changed mapping into addedValues/removedValues,
  // since we cannot determine their equivalence so far
  for (auto [srcfile, lineNumMap] : changedMapping) {
    for (auto [beforeLine, afterLine] : lineNumMap) {

      // necessary for later printing
      int pos = -1;
      for (int i = 0; i < addedLines.size(); i++) {
        if (addedLines[i].line == afterLine &&
            addedLines[i].sourceFile == srcfile) {
          pos = i;
          break;
        }
      }
      addedLines.erase(addedLines.begin() + pos);

      for (int i = 0; i < removedLines.size(); i++) {
        if (removedLines[i].line == beforeLine &&
            removedLines[i].sourceFile == srcfile) {
          pos = i;
          break;
        }
      }
      removedLines.erase(removedLines.begin() + pos);

      vector<Instruction *> beforeIRs, afterIRs;

      auto before_funcs = findEnclosedFunc(srcfile, beforeLine, false);
      for (auto func : before_funcs) {
        getLineNumInsts(func, beforeLine, beforeIRs);
      }

      auto after_funcs = findEnclosedFunc(srcfile, afterLine, true);
      for (auto func : after_funcs) {
        getLineNumInsts(func, afterLine, afterIRs);
      }
      if (!beforeIRs.empty() || !afterIRs.empty()) {
        if (!beforeIRs.empty()) {
          dbgs() << "\n===============Line: " << srcfile << " +" << beforeLine
                 << ": " << printSourceCodeInfo(beforeIRs.front()) << " <-> "
                 << "+" << printSourceCodeInfo(beforeIRs.front()) << afterLine
                 << "\n";
        } else {
          dbgs() << "\n===============Line: " << srcfile << " +" << beforeLine
                 << ": " << printSourceCodeInfo(afterIRs.front()) << " <-> "
                 << "+" << printSourceCodeInfo(afterIRs.front()) << afterLine
                 << "\n";
        }
      }

      for (auto beforeIR : beforeIRs) {
        dbgs() << "[" << beforeIR->getParent()->getParent()->getName()
               << "]: Removed IR " << *beforeIR << "\n";
        removedValues.insert(beforeIR);
      }

      for (auto afterIR : afterIRs) {
        dbgs() << "[" << afterIR->getParent()->getParent()->getName()
               << "]: Added IR " << *afterIR << "\n";
        addedValues.insert(afterIR);
      }
    }
  }

  // add instructions in removed lines into removedValues
  dbgs() << "\n=======1.3 IRs for Removed Lines========\n";
  for (const auto &removed : removedLines) {
    vector<Instruction *> removedIRs;
    getLineNumInsts(removed.func, removed.line, removedIRs);

    if (!removedIRs.empty()) {
      dbgs() << "\n===============Line: " << removed.sourceFile << " +"
             << removed.line << ": " << printSourceCodeInfo(removedIRs.front())
             << "\n";
    }
    for (auto removedIR : removedIRs) {
      dbgs() << "[" << removed.func->getName() << "]: Removed IR " << *removedIR
             << "\n";
      removedValues.insert(removedIR);
    }
  }

  // add instructions in added lines into addedValues
  dbgs() << "\n=======1.4 IRs for Added Lines========\n";
  for (const auto &added : addedLines) {
    vector<Instruction *> addedIRs;
    getLineNumInsts(added.func, added.line, addedIRs);
    if (!addedIRs.empty()) {
      dbgs() << "\n===============Line: " << added.sourceFile << " +"
             << added.line << ": " << printSourceCodeInfo(addedIRs.front())
             << "\n";
    }
    for (auto addedIR : addedIRs) {
      dbgs() << "[" << added.func->getName() << "]: Added IR " << *addedIR
             << "\n";
      addedValues.insert(addedIR);
    }
  }
}

set<Function *> PatchParser::findEnclosedFunc(string srcFile, int line,
                                              bool isAdded) {
  set<Function *> enclosedFuncs;

  for (auto [func, pair] : funcLineScope) {
    if (isAdded && !func->getName().startswith("after.patch.")) {
      continue;
    }
    if (!isAdded && !func->getName().startswith("before.patch.")) {
      continue;
    }

    if (funcSourceFile[func] == srcFile && line >= pair.first &&
        line <= pair.second) {
      enclosedFuncs.insert(func);
    }
  }
  return enclosedFuncs;
}

bool PatchParser::isLineAdded(const std::string &srcfile, int lineNum) {
  return std::any_of(addedLines.begin(), addedLines.end(),
                     [lineNum, &srcfile](const ChangedLine &added) {
                       return added.line == lineNum &&
                              added.sourceFile == srcfile;
                     });
}

bool PatchParser::isLineRemoved(const std::string &srcfile, int lineNum) {
  return std::any_of(removedLines.begin(), removedLines.end(),
                     [lineNum, &srcfile](const ChangedLine &removed) {
                       return removed.line == lineNum &&
                              removed.sourceFile == srcfile;
                     });
}

// give the line number and function, return all instructions in the function
// that at specific line number
void PatchParser::getLineNumInsts(Function *func, int line,
                                  vector<Instruction *> &insts) {

  for (BasicBlock &bb : *func) {
    int bb_start_line = blockLineScope[&bb].first;
    int bb_end_line = blockLineScope[&bb].second;

    if (bb_start_line > line || bb_end_line < line) {
      continue;
    }

    vector<pair<Instruction *, int>> inst2Line;
    for (Instruction &i : bb) {
      if (isa<ReturnInst>(&i)) {
        continue;
      }
      if (auto *br_inst = dyn_cast<BranchInst>(&i)) {
        if (!br_inst->isConditional()) {
          continue;
        }
      }
      auto ir_line = guessInstructionLineNum(&i);
      if (!ir_line) {
        continue;
      }
      if (is_excopy_val(&i)) {
        continue;
      }
      if (auto *callInst = dyn_cast<CallInst>(&i)) {
        if (callInst->getCalledFunction() &&
            callInst->getCalledFunction()->hasName() &&
            callInst->getCalledFunction()->getName().startswith("llvm.")) {
          continue;
        }
      }
      // if (changedFuncs.count(func)) {
      //   dbgs() << "Line: " << ir_line << ", Site: " << i << "\n";
      // }
      inst2Line.emplace_back(&i, ir_line);
    }

    // below are some heuristics to filter out the invalid line number,
    // for instance, the number of current instruction maybe larger than the
    // next inst
    int last_line = -1;
    for (auto it1 = inst2Line.begin(); it1 != inst2Line.end(); it1++) {
      if (last_line == -1) {
        last_line = it1->second;
        continue;
      }
      if (it1->second < last_line) {
        for (auto it2 = it1; it2 != inst2Line.begin(); it2--) {
          if (it2->second > it1->second) {
            it2->second = it1->second;
          }
        }
      }
      last_line = it1->second;
    }

    for (auto &it : inst2Line) {
      if (it.second == line) {
        insts.push_back(it.first);
      }
    }
  }
}

unsigned int PatchParser::guessInstructionLineNum(Instruction *inst) {
  auto ir_line = inst->getDebugLoc().getLine();
  auto cur_bb = inst->getParent();
  auto bb_scope = blockLineScope[cur_bb];
  if (ir_line) {
    return ir_line;
  }
  // if ir_line is 0, here are some heuristics
  if (isa<PHINode>(inst)) {
    auto next_inst = inst->getNextNode();
    auto next_ir_line = next_inst->getDebugLoc().getLine();
    while (!next_ir_line) {
      next_inst = next_inst->getNextNode();
      next_ir_line = next_inst->getDebugLoc().getLine();
    }
    return next_ir_line;
  }
  if (auto *icmpInst = dyn_cast<ICmpInst>(inst)) {
    for (auto use_it = icmpInst->user_begin(); use_it != icmpInst->user_end();
         use_it++) {
      if (!isa<Instruction>(*use_it)) {
        continue;
      }
      auto *next_inst = dyn_cast<Instruction>(*use_it);
      if (isa<BranchInst>(next_inst) || isa<BinaryOperator>(next_inst)) {
        auto next_ir_line = guessInstructionLineNum(next_inst);
        if (next_ir_line) {
          //          dbgs() << "\nOriginal icmp: " << *icmpInst << "\n";
          //          dbgs() << "Branch inst: " << next_ir_line << ", " <<
          //          *next_inst << "\n";
          return next_ir_line;
        }
      }
    }
  }
  if (isa<AllocaInst>(inst)) {
    return bb_scope.first;
  }
  if (isa<BranchInst>(inst)) {
    return bb_scope.second;
  }
  if (bb_scope.first == bb_scope.second) {
    return bb_scope.first;
  }

  // todo: refine guess
  return 0;
}
