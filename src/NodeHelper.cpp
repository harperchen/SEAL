#include "NodeHelper.h"
#include "UtilsHelper.h"
#include "ValueHelper.h"

bool isTwoSEGSiteMatched(SEGSiteBase *site1, SEGSiteBase *site2) {
  if (site1->getKind() != site2->getKind()) {
    return false;
  }
  return true;
}

CBAccessPath *getAccessPatch(SEGNodeBase *node) {
  CBAccessPath *accessPath = nullptr;
  if (auto *pseudoArg = dyn_cast<SEGPseudoArgumentNode>(node)) {
    accessPath = &pseudoArg->getAccessPath();
  } else if (auto *pseudoRet = dyn_cast<SEGPseudoReturnNode>(node)) {
    accessPath = &pseudoRet->getAccessPath();
  } else if (auto *CSOInput = dyn_cast<SEGCallSitePseudoInputNode>(node)) {
    accessPath = &CSOInput->getAccessPath();
  } else if (auto *CSOOutput = dyn_cast<SEGCallSitePseudoOutputNode>(node)) {
    accessPath = &CSOOutput->getAccessPath();
  }
  return accessPath;
}

Instruction *getCallSite(SEGNodeBase *node) {
  Instruction *callSite = nullptr;
  if (auto *CSOInput = dyn_cast<SEGCallSitePseudoInputNode>(node)) {
    callSite = CSOInput->getCallSite().getInstruction();
  } else if (auto *CSOOutput = dyn_cast<SEGCallSitePseudoOutputNode>(node)) {
    callSite = CSOOutput->getCallSite()->getLLVMCallSite().getInstruction();
  }
  return callSite;
}

Function *getCalledFunction(SEGNodeBase *node) {
  if (auto *csoInput = dyn_cast<SEGCallSitePseudoInputNode>(node)) {
    return csoInput->getCallee();
  } else if (auto *csoOutput = dyn_cast<SEGCallSiteOutputNode>(node)) {
    return csoOutput->getCallSite()->getCalledFunction();
  } else {
    return nullptr;
  }
}

bool diffSEGCommonArgument(SEGNodeBase *node1, SEGNodeBase *node2) {
  if (isa<SEGCommonArgumentNode>(node1) && isa<SEGCommonArgumentNode>(node2)) {
    auto *commonArg1 = dyn_cast<SEGCommonArgumentNode>(node1);
    auto *commonArg2 = dyn_cast<SEGCommonArgumentNode>(node2);
    // todo: refine
    if (commonArg1->getIndex() != commonArg2->getIndex()) {
      return false;
    }
  }
  return true;
}

bool diffSEGPseudoIO(SEGNodeBase *node1, SEGNodeBase *node2) {
  auto callSite1 = getCallSite(node1);
  auto callSite2 = getCallSite(node2);
  if (callSite1 && callSite2) {
    if (matchedIRsBefore.count(callSite1)) {
      if (matchedIRsBefore[callSite1] != callSite2) {
        return false;
      }
    }
  }

  auto accessPath1 = getAccessPatch(node1);
  auto accessPath2 = getAccessPatch(node2);
  if (accessPath1 && accessPath2) {
    if (accessPath1->get_depth() != accessPath2->get_depth()) {
      return false;
    }

    for (int j = 0; j < accessPath1->get_depth(); j++) {
      if (accessPath1->get_offset(j) != accessPath2->get_offset(j)) {
        return false;
      }
    }
  }
  return true;
}

// check node properties only
bool isTwoSEGNodeMatched(SEGNodeBase *node1, SEGNodeBase *node2) {
  if (node1 == node2) {
    return true;
  }
  if (node1->getKind() != node2->getKind()) {
    return false;
  }

  if (node1->getLLVMType() && node2->getLLVMType()) {
    if (type2String(node1->getLLVMType()) !=
        type2String(node2->getLLVMType())) {
      return false;
    }
  }

  if (!diffSEGCommonArgument(node1, node2)) {
    return false;
  }

  if (!diffSEGPseudoIO(node1, node2)) {
    return false;
  }
  return true;
}

bool isPatchSEGNodeMatched(SEGNodeBase *node1, SEGNodeBase *node2) {
  if (node1 == node2) {
    return true;
  }
  auto parentFuncName1 =
      node1->getParentGraph()->getBaseFunc()->getName().str();
  auto parentFuncName2 =
      node2->getParentGraph()->getBaseFunc()->getName().str();

  cleanStringPatch(parentFuncName1);
  cleanStringPatch(parentFuncName2);

  if (parentFuncName1 != findABMatchFunc(parentFuncName2) &&
      parentFuncName1 != parentFuncName2) {
    return false;
  }

  if (!isTwoSEGNodeMatched(node1, node2)) {
    return false;
  }

  if (isa<SEGOperandNode>(node1)) {
    if (node1->getLLVMDbgValue() && node2->getLLVMDbgValue()) {
      if (node1->getLLVMDbgValue() == node2->getLLVMDbgValue()) {
        return true;
      }

      auto calledFunc1 = getCalledFunction(node1);
      auto calledFunc2 = getCalledFunction(node2);
      if (calledFunc1 && calledFunc2) {
        // no need to check name of pseudo inputs and outputs
        auto name1 = calledFunc1->getName().str();
        auto name2 = calledFunc2->getName().str();
        cleanStringPatch(name1);
        cleanStringPatch(name2);
        if (name1 != findABMatchFunc(name2) && name1 != name2) {
          return false;
        }
      }
      if (isa<SEGPseudoArgumentNode>(node1) ||
          isa<SEGPseudoReturnNode>(node1) ||
          isa<SEGCallSitePseudoInputNode>(node1) ||
          isa<SEGCallSitePseudoOutputNode>(node1)) {
        return true;
      }
      if (parentFuncName1 != parentFuncName2) {
        if (!isTwoValueMatchedHelper(node1->getLLVMDbgValue(),
                                     node2->getLLVMDbgValue())) {
          return false;
        }
      } else {
        if (node1->getLLVMDbgValue() != node2->getLLVMDbgValue()) {
          return false;
        }
      }
    }
  }
  return true;
}

bool isDriverSEGNodeMatched(SEGNodeBase *node1, SEGNodeBase *node2) {
  if (!isTwoSEGNodeMatched(node1, node2)) {
    return false;
  }
  if (isa<SEGSimpleOperandNode>(node1) && isa<SEGSimpleOperandNode>(node2)) {
    // in case cannot be transformed to pseudo arg, matching offset from name
    if (node1->getLLVMDbgValue() && node2->getLLVMDbgValue()) {
      if (isa<Argument>(node1->getLLVMDbgValue()) &&
          isa<Argument>(node2->getLLVMDbgValue())) {
        auto *argOperandNode = dyn_cast<Argument>(node1->getLLVMDbgValue());
        auto *argSrcNode = dyn_cast<Argument>(node2->getLLVMDbgValue());

        if (!argSrcNode->hasName() || !argOperandNode->hasName()) {
          return false;
        }

        string argSrcName = argSrcNode->getName();
        string argOpeName = argOperandNode->getName();

        if (argSrcName.find("].") != string::npos &&
            argSrcName.find("[S_") != string::npos &&
            argOpeName.find("].") != string::npos &&
            argOpeName.find("[S_") != string::npos) {

          string offsetSrcString = argSrcName.substr(argSrcName.rfind(']') + 2);
          int offsetSrc = stoi(offsetSrcString);

          string numString = argOpeName.substr(argOpeName.rfind(']') + 2);
          int offsetOperand = stoi(numString);

          if (offsetOperand != offsetSrc) {
            return false;
          }
        }
      }
    }
  }
  return true;
}

bool isPatchSEGSiteMatched(SEGSiteBase *site1, SEGSiteBase *site2) {

  if (site1 == site2) {
    return true;
  }
  auto parentFuncName1 =
      site1->getParentGraph()->getBaseFunc()->getName().str();
  auto parentFuncName2 =
      site2->getParentGraph()->getBaseFunc()->getName().str();

  cleanStringPatch(parentFuncName1);
  cleanStringPatch(parentFuncName2);

  if (parentFuncName1 != findABMatchFunc(parentFuncName2) &&
      parentFuncName1 != parentFuncName2) {
    return false;
  }

  if (site1->getKind() != site2->getKind()) {
    return false;
  }

  auto inst1 = site1->getInstruction();
  auto inst2 = site2->getInstruction();

  if (matchedIRsBefore.count(inst1)) {
    if (matchedIRsBefore[inst1] != inst2) {
      return false;
    } else {
      return true;
    }
  }

  if (matchedIRsBefore.count(inst2)) {
    if (matchedIRsBefore[inst2] != inst1) {
      return false;
    } else {
      return true;
    }
  }

  if (matchedIRsAfter.count(inst1)) {
    if (matchedIRsAfter[inst1] != inst2) {
      return false;
    } else {
      return true;
    }
  }

  if (matchedIRsAfter.count(inst2)) {
    if (matchedIRsAfter[inst2] != inst1) {
      return false;
    } else {
      return true;
    }
  }

  if (!isTwoIRMatched(inst1, inst2)) {
    return false;
  }

  return true;
}
