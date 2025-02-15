
#include "SensitiveOps.h"

void obtainSensitive(const vector<SEGObject *> &segTrace,
                     set<OutputNode *> &outputs) {
  for (auto node : segTrace) {
    if (auto *operandNode = dyn_cast<SEGNodeBase>(node)) {
      for (auto uit = operandNode->use_site_begin();
           uit != operandNode->use_site_end(); uit++) {
        auto outputNode = isDivideByZeroSite(operandNode, *uit);
        if (outputNode) {
          outputs.insert(outputNode);
        }
        outputNode = isNullPtrDerefSite(operandNode, *uit);
        if (outputNode) {
          outputs.insert(outputNode);
        }
        outputNode = isOutOfBoundarySite(operandNode, *uit);
        if (outputNode) {
          outputs.insert(outputNode);
        }
      }
    }
  }
}

OutputNode *isNullPtrDerefSite(SEGNodeBase *node, SEGSiteBase *site) {
  // 1. deref pointer or struct
  // 2. access memory with load
  // 3. access memory with store

  if (!isa<SEGOperandNode>(node)) {
    return nullptr;
  }

  auto *operandNode = dyn_cast<SEGOperandNode>(node);
  if (auto *derefSite = dyn_cast<SEGDereferenceSite>(site)) {
    if (derefSite->deref(operandNode)) {
      auto output = new SensitiveOpNode(
          "deref", -1, operandNode->getParentGraph()->getBaseFunc()->getName());
      output->usedNode = node;
      output->usedSite = site;
      return (OutputNode *)output;
    }
  }
  return nullptr;
}

OutputNode *isDivideByZeroSite(SEGNodeBase *node, SEGSiteBase *site) {
  if (!isa<SEGDivSite>(site) || !isa<SEGOperandNode>(node) ||
      !node->getLLVMDbgValue()) {
    return nullptr;
  }
  auto *divSite = dyn_cast<SEGDivSite>(site);
  if (divSite->getSEGValue()->isDivInst() &&
      node->getLLVMDbgValue() ==
          site->getSEGValue()->getInstOperand(1)->getValue()) {
    auto output = new SensitiveOpNode(
        "div", 1, site->getParentGraph()->getBaseFunc()->getName());
    output->usedNode = node;
    output->usedSite = site;
    return (OutputNode *)output;
  }
  return nullptr;
}

OutputNode *isOutOfBoundarySite(SEGNodeBase *node, SEGSiteBase *site) {
  if (!isa<SEGOperandNode>(node) || !node->getLLVMDbgValue()) {
    return nullptr;
  }
  if (auto *CS = dyn_cast<SEGCallSite>(site)) {
    if (CS->getCalledFunction()) {
      Function *F = CS->getCalledFunction();
      if ((F->isIntrinsic() && F->getIntrinsicID() == Intrinsic::memcpy) ||
          (F->hasName() && F->getName().equals("__memcpy"))) {
        int ArgNo = -1;
        for (int j = 0; j < CS->getLLVMCallSite().arg_size(); j++) {
          if (node->getLLVMDbgValue() == CS->getLLVMCallSite().getArgument(j)) {
            ArgNo = j;
            break;
          }
        }
        if (ArgNo == 2) {
          auto output = new SensitiveAPINode(
              F->getName(), ArgNo,
              node->getParentGraph()->getBaseFunc()->getName());
          output->usedNode = node;
          output->usedSite = site;
          return (OutputNode *)output;
        }
      }
    }
  }
  return nullptr;
}
