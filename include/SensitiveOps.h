
#ifndef CLEARBLUE_SENSITIVEOPS_H
#define CLEARBLUE_SENSITIVEOPS_H

#include "DriverSpecs.h"
#include <llvm/Support/Casting.h>

#include "IR/SEG/SEGCallSite.h"
#include "IR/SEG/SEGCallSiteOutputNode.h"
#include "IR/SEG/SEGCallSitePseudoInputNode.h"
#include "IR/SEG/SEGSimpleOperandNode.h"
#include "IR/SEG/SEGSimpleSite.h"
#include "IR/SEG/SymbolicExprGraph.h"
#include "IR/SEG/SymbolicExprGraphBuilder.h"
#include <vector>

using namespace llvm;
using namespace std;

// enumerate all sensitive operations
void obtainSensitive(const vector<SEGObject *> &segTrace,
                     set<OutputNode *> &outputs);

OutputNode *isDivideByZeroSite(SEGNodeBase *node, SEGSiteBase *site);
OutputNode *isNullPtrDerefSite(SEGNodeBase *node, SEGSiteBase *site);
OutputNode *isOutOfBoundarySite(SEGNodeBase *node, SEGSiteBase *site);
OutputNode *isShiftOutOfBoundSite(SEGNodeBase *node, SEGSiteBase *site);

#endif // CLEARBLUE_SENSITIVEOPS_H
