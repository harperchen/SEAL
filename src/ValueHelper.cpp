#include "ValueHelper.h"
#include "UtilsHelper.h"

set<Function *> changedFuncs;

map<Value *, Value *, llvm_cmp> matchedIRsBefore;
map<Value *, Value *, llvm_cmp> matchedIRsAfter;

set<BasicBlock *> unMatchedBBs;

map<string, map<int, int>> changedMapping;
map<string, map<int, int>> unChangedMapping;

bool isTwoValueMatchedHelper(Value *value1, Value *value2, bool matchBB) {
  if (matchedIRsBefore.count(value1)) {
    return matchedIRsBefore[value1] == value2;
  }

  if (value1 == value2) {
    return true;
  }

  if (!isCurrentValueSkipMatch(value1) && !isCurrentValueSkipMatch(value2) &&
      type2String(value1->getType()) != type2String(value2->getType())) {
    return false;
  }
  // verify class ID
  if (value1->getValueID() != value2->getValueID()) {
    return false;
  }

  // global variables can be directly checked via name
  if (isa<GlobalVariable>(value1)) {
    if (value1->hasName() && value2->hasName()) {
      string valueName1 = value1->getName().str();
      string valueName2 = value2->getName().str();

      cleanString(valueName1);
      cleanString(valueName2);

      if (valueName1 == valueName2) {
        return true;
      }
    }
  }

  else if (isa<Function>(value1)) {
    auto *func1 = dyn_cast<Function>(value1);
    auto *func2 = dyn_cast<Function>(value2);

    if (func1->arg_size() != func2->arg_size()) {
      return false;
    }
    if (func1->hasName() xor func2->hasName()) {
      return false;
    }

    if (func1->hasName() && func2->hasName()) {
      string callName1 = func1->getName().str();
      string callName2 = func2->getName().str();

      cleanString(callName1);
      cleanString(callName2);

      if (callName1 != callName2) {
        return false;
      }
    }
  } else if (isa<MetadataAsValue>(value1)) {
    auto *meta1 = dyn_cast<MetadataAsValue>(value1);
    auto *meta2 = dyn_cast<MetadataAsValue>(value2);
    if (isa<ValueAsMetadata>(meta1->getMetadata()) &&
        isa<ValueAsMetadata>(meta2->getMetadata())) {
      Value *metaValue1 =
          dyn_cast<ValueAsMetadata>(meta1->getMetadata())->getValue();
      Value *metaValue2 =
          dyn_cast<ValueAsMetadata>(meta2->getMetadata())->getValue();
      if (isa<Instruction>(metaValue1) && isa<Instruction>(metaValue2)) {
        return true;
      }
      if (!isTwoValueMatchedHelper(metaValue1, metaValue2, matchBB)) {
        return false;
      }
    }
  } else if (isa<Argument>(value1)) {
    auto *arg1 = dyn_cast<Argument>(value1);
    auto *arg2 = dyn_cast<Argument>(value2);
    if (arg1->getParent() && arg2->getParent()) {
      if (!isTwoValueMatchedHelper(arg1->getParent(), arg2->getParent())) {
        return false;
      }
      if (arg1->getArgNo() != arg2->getArgNo()) {
        return false;
      }
    }
    string arg1Name = arg1->getName().str();
    string arg2Name = arg2->getName().str();

    cleanString(arg1Name);
    cleanString(arg2Name);

    if (arg1Name != arg2Name) {
      return false;
    }
  } else if (isa<ConstantInt>(value1)) {
    auto *const1 = dyn_cast<ConstantInt>(value1);
    auto *const2 = dyn_cast<ConstantInt>(value2);
    if (const1->getType() != const2->getType()) {
      return false;
    }
    if (!const1->equalsInt(const2->getSExtValue())) {
      return false;
    }
  } else if (isa<ConstantExpr>(value1)) {
    auto *constExpr1 = dyn_cast<ConstantExpr>(value1);
    auto *constExpr2 = dyn_cast<ConstantExpr>(value2);

    if (constExpr1->getOpcode() != constExpr2->getOpcode()) {
      return false;
    }
    if (constExpr1->getNumOperands() != constExpr2->getNumOperands()) {
      return false;
    }

    for (auto i = 0; i < constExpr1->getNumOperands(); i++) {
      if (!isTwoValueMatchedHelper(constExpr1->getOperand(i),
                                   constExpr2->getOperand(i))) {
        return false;
      }
    }
  } else if (isa<GetElementPtrConstantExpr>(value1)) {
    return true;
  } else if (isa<BasicBlock>(value1)) {
    auto *bb1 = dyn_cast<BasicBlock>(value1);
    auto *bb2 = dyn_cast<BasicBlock>(value2);

    if (!isTwoValueMatchedHelper(bb1->getParent(), bb2->getParent())) {
      return false;
    }

    if (!changedFuncs.count(bb1->getParent())) {
      return bb1->getName() == bb2->getName();
    }

    if (unMatchedBBs.count(bb1) || unMatchedBBs.count(bb2)) {
      return false;
    }
    if (bb1->getInstList().size() != bb2->getInstList().size()) {
      return false;
    }

    bool found_common = false, found1 = false, found2 = false;
    vector<string> substr_list = {"entry", ".else", ".then", ".end",
                                  ".cond", ".body", "return"};

    for (const auto &substr : substr_list) {
      size_t pos1 = bb1->getName().find(substr);
      size_t pos2 = bb2->getName().find(substr);
      if (pos1 != string::npos) {
        found1 = true;
      }
      if (pos2 != string::npos) {
        found2 = true;
      }
      if (pos1 != string::npos && pos2 != string::npos) {
        found_common = true;
      }
    }

    if (!found_common and (found1 or found2)) {
      return false;
    }

    for (int i = 0; i < bb1->getInstList().size(); i++) {
      auto it1 = bb1->begin();
      auto it2 = bb2->begin();
      for (int j = 0; j < i; j++) {
        it1++;
        it2++;
      }
      Instruction *inst1 = it1;
      Instruction *inst2 = it2;
      if (inst1->getOpcode() != inst2->getOpcode()) {
        return false;
      }
      if (type2String(inst1->getType()) != type2String(inst2->getType())) {
        return false;
      }
    }
    matchedIRsBefore.insert({value1, value2});
    matchedIRsAfter.insert({value2, value1});
    return true;
  } else if (isa<Instruction>(value1)) {
    return isTwoIRMatched(dyn_cast<Instruction>(value1),
                          dyn_cast<Instruction>(value2), matchBB);
  } else {
    dbgs() << "\n!!!UnHandled value " << value1->getValueName() << "\n";
    dbgs() << *value1 << "\n";
    dbgs() << *value2 << "\n\n";
  }

  return true;
}

bool isCurrentIRSkipMatch(Instruction *inst) {
  if (isa<AllocaInst>(inst)) {
    return true;
  } else if (isa<CallInst>(inst)) {
    auto *callInst = dyn_cast<CallInst>(inst);
    if (callInst->isInlineAsm()) {
      return true;
    }
  }
  return false;
}

bool isCurrentValueSkipMatch(Value *value) {
  if (auto *global_var = dyn_cast<GlobalVariable>(value)) {
    if (global_var->getName().count(".str.")) {
      return true;
    }
  }
  if (auto *inst = dyn_cast<Instruction>(value)) {
    return isCurrentIRSkipMatch(inst);
  }
  return false;
}

// used for pre-patch and post-patch comparison
bool isTwoIRMatched(Instruction *inst1, Instruction *inst2, bool matchBB) {
  if (matchedIRsBefore.find(inst1) != matchedIRsBefore.end()) {
    if (matchedIRsBefore[inst1] == inst2) {
      return true;
    }
  }

  if (inst1->getOpcode() != inst2->getOpcode()) {
    return false;
  }

  if (type2String(inst1->getType()) != type2String(inst2->getType())) {
    return false;
  }

  if (inst1->getNumOperands() != inst2->getNumOperands()) {
    return false;
  }

  auto src_line1 = inst1->getDebugLoc().getLine();
  auto src_line2 = inst2->getDebugLoc().getLine();

  string src_file1 = getSrcFileName(inst1);
  string src_file2 = getSrcFileName(inst2);

  if (!src_file1.empty() && !src_file2.empty()) {
    if (src_file1 != src_file2) {
      return false;
    }

    if (unChangedMapping.count(src_file1)) {
      if (unChangedMapping[src_file1].count(src_line1)) {
        if (unChangedMapping[src_file1][src_line1] != src_line2) {
          return false;
        }
      }
    }
  }

  if (isa<PHINode>(inst1) && isa<PHINode>(inst2)) {
    set<int> matchedOperandIdxs;
    for (int i = 0; i < inst1->getNumOperands(); i++) {
      bool has_matched = false;
      for (int j = 0; j < inst2->getNumOperands(); j++) {
        if (matchedOperandIdxs.find(j) != matchedOperandIdxs.end()) {
          continue;
        }
        auto op1 = inst1->getOperand(i);
        auto op2 = inst2->getOperand(j);
        if (isa<Instruction>(op1) && isa<Instruction>(op2)) {
          auto *nextInst1 = dyn_cast<Instruction>(op1);
          auto *nextInst2 = dyn_cast<Instruction>(op2);
          if (isTwoIRMatched(nextInst1, nextInst2, matchBB)) {
            matchedOperandIdxs.insert(j);
            has_matched = true;
            break;
          }
        } else {
          if (isTwoValueMatchedHelper(inst1->getOperand(i),
                                      inst2->getOperand(j))) {
            matchedOperandIdxs.insert(j);
            has_matched = true;
            break;
          }
        }
      }
      if (!has_matched) {
        return false;
      }
    }
  } else if (isa<ReturnInst>(inst1) && isa<ReturnInst>(inst2)) {
    return true;
  } else {
    if (isa<ICmpInst>(inst1) && isa<ICmpInst>(inst2)) {
      auto *icmpInst1 = dyn_cast<ICmpInst>(inst1);
      auto *icmpInst2 = dyn_cast<ICmpInst>(inst2);
      if (icmpInst1->getPredicate() != icmpInst2->getPredicate()) {
        return false;
      }
    }
    for (int i = 0; i < inst1->getNumOperands(); i++) {
      auto op1 = inst1->getOperand(i);
      auto op2 = inst2->getOperand(i);
      if (isa<Instruction>(op1) && isa<Instruction>(op2)) {
        auto *nextInst1 = dyn_cast<Instruction>(op1);
        auto *nextInst2 = dyn_cast<Instruction>(op2);
        if (!isTwoIRMatched(nextInst1, nextInst2, matchBB)) {
          return false;
        }
      } else if (isa<BasicBlock>(op1) && isa<BasicBlock>(op2)) {
      } else {
        if (!isTwoValueMatchedHelper(inst1->getOperand(i),
                                     inst2->getOperand(i))) {
          return false;
        }
      }
    }
  }

  if (matchBB &&
      !isTwoValueMatchedHelper(inst1->getParent(), inst2->getParent())) {
    return false;
  }
  matchedIRsBefore.insert({inst1, inst2});
  matchedIRsAfter.insert({inst2, inst1});
  return true;
}

void findValueEnClosedFunc(Value *value, set<Function *> &funcs) {
  vector<Value *> worklist;
  set<Value *> checkedlist;
  worklist.push_back(value);

  while (!worklist.empty()) {
    auto curValue = worklist.front();
    worklist.erase(worklist.begin());
    checkedlist.insert(curValue);

    if (curValue->getNumUses() == 0) {
      continue;
    }

    for (auto it = curValue->use_begin(); it != curValue->use_end(); it++) {
      if (auto *inst = dyn_cast<Instruction>(it->getUser())) {
        funcs.insert(inst->getParent()->getParent());
      } else {
        if (checkedlist.find(it->getUser()) == checkedlist.end()) {
          worklist.push_back(it->getUser());
        }
      }
    }
  }
}