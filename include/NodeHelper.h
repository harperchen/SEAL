#ifndef CLEARBLUE_NODEHELPER_H
#define CLEARBLUE_NODEHELPER_H

#include "Analysis/Bitcode/DebugInfoAnalysis.h"
#include "IR/ConstantsContext.h"
#include "UtilsHelper.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Instruction.h"
#include <string>

#include "IR/SEG/SEGCallSiteOutputNode.h"
#include "IR/SEG/SEGCallSitePseudoInputNode.h"
#include "IR/SEG/SEGSimpleOperandNode.h"
#include "IR/SEG/SymbolicExprGraph.h"
#include "IR/SEG/SymbolicExprGraphBuilder.h"

using namespace std;
using namespace llvm;

bool isPatchSEGNodeMatched(SEGNodeBase *node1, SEGNodeBase *node2);

bool isPatchSEGSiteMatched(SEGSiteBase *site1, SEGSiteBase *site2);

bool isDriverSEGNodeMatched(SEGNodeBase *node1, SEGNodeBase *node2);
bool isDriverSEGSiteMatched(SEGNodeBase *node1, SEGNodeBase *node2,
                            SEGSiteBase *site1, SEGSiteBase *site2);

#endif // CLEARBLUE_NODEHELPER_H
