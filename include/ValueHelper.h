#ifndef CLEARBLUE_VALUEHELPER_H
#define CLEARBLUE_VALUEHELPER_H
#include "Analysis/Bitcode/DebugInfoAnalysis.h"
#include "IR/ConstantsContext.h"
#include "Transform/ValueComparator.h"
#include "UtilsHelper.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Instruction.h"
#include <string>

using namespace std;
using namespace llvm;

extern set<Function *> changedFuncs;

extern map<Value *, Value *, llvm_cmp> matchedIRsBefore;
extern map<Value *, Value *, llvm_cmp> matchedIRsAfter;

extern set<BasicBlock *> unMatchedBBs;

extern map<string, map<int, int>> changedMapping;
extern map<string, map<int, int>> unChangedMapping;

bool isCurrentIRSkipMatch(Instruction *inst);

bool isCurrentValueSkipMatch(Value *value);

bool isTwoValueMatchedHelper(Value *value1, Value *value2,
                             bool matchBB = false);

bool isTwoIRMatched(Instruction *inst1, Instruction *inst2,
                    bool matchBB = false);

void findValueEnClosedFunc(Value *value, set<Function *> &funcs);

#endif // CLEARBLUE_VALUEHELPER_H
