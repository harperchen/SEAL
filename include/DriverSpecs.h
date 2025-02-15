//
// Created by weichen on 9/22/23.
//

#ifndef CLEARBLUE_DRIVERSPECS_H
#define CLEARBLUE_DRIVERSPECS_H

#include "Analysis/Bitcode/DebugInfoAnalysis.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Instruction.h"

#include <IR/ConstantsContext.h>
#include <IR/SEG/SymbolicExprGraph.h>

#include <iostream>
#include <istream>
#include <ostream>
#include <string>
using namespace std;

enum InputType {
  IndirectArg,
  ArgRetOfAPI,
  ErrorCode,
  GlobalVarIn,
  SensitiveIn,
};

struct InputNode {
  InputType type;
  SEGNodeBase *usedNode = nullptr;
  SEGSiteBase *usedSite = nullptr;

  virtual void print(raw_ostream &out) const {}

  virtual string to_string() const {}

  friend raw_ostream &operator<<(raw_ostream &out, const InputNode &node) {
    node.print(out);
    return out;
  }

  InputNode() {}

  InputNode(string str) {}

  bool operator==(const InputNode &other) const {
    return other.type == type && other.usedNode == usedNode &&
           other.usedSite == usedSite;
  }
};

struct IndirectArgNode : InputNode {
  string funcName;
  string argName;

  IndirectArgNode(string funcName, string argName) {
    this->argName = argName;
    this->funcName = funcName;
    this->type = IndirectArg;
  }

  void print(raw_ostream &out) const override {
    out << "Indirect call: " << funcName << " Arg Name: " << argName;
  }

  string to_string() const override {
    return "Indirect call: " + funcName + " Arg Name: " + argName;
  }

  IndirectArgNode(string str) : InputNode(str) {
    size_t callPos = str.find("Indirect call: ") + 15;
    this->funcName = str.substr(callPos, str.find(" Arg Name") - callPos);

    size_t argIdxPos = str.find("Arg Name: ") + 9;
    this->argName = str.substr(argIdxPos, str.find('\n') - argIdxPos);
    this->type = IndirectArg;
  }

  bool operator==(const IndirectArgNode &other) const {
    if (this == &other)
      return true;
    return InputNode::operator==(other) && argName == other.argName &&
           funcName == other.funcName;
  }
};

struct ArgRetOfAPINode : InputNode {
  string apiName;
  int index;

  ArgRetOfAPINode(string apiName) {
    size_t startPos = apiName.find(": ") + 2;
    this->apiName = apiName.substr(startPos);
    this->type = ArgRetOfAPI;
  }

  ArgRetOfAPINode(string apiName, int index) {
    this->apiName = apiName;
    this->type = ArgRetOfAPI;
    this->index = index;
  }

  void print(raw_ostream &out) const override {
    out << "Return of API: " << apiName << "#" << index;
  }

  string to_string() const override {
    return "Return of API: " + apiName + "#" + std::to_string(index);
  }

  bool operator==(const ArgRetOfAPINode &other) const {
    if (this == &other)
      return true;
    return InputNode::operator==(other) && apiName == other.apiName &&
           index == other.index;
  }
};

struct SensitiveInNode : InputNode {
  enum sensitiveInType {
    NULLValue,
  };

  string valType;
  SensitiveInNode(string valType) {
    this->valType = valType;
    this->type = SensitiveIn;
  }

  void print(raw_ostream &out) const override {
    out << "Sensitive Input Value: " << valType;
  }

  string to_string() const override {
    return "Sensitive Input Value: " + valType;
  }

  bool operator==(const SensitiveInNode &other) const {
    if (this == &other)
      return true;
    return InputNode::operator==(other) && valType == other.valType;
  }
};

struct ErrorCodeNode : InputNode {
  InputNode *inputNode;
  int errorCode;

  ErrorCodeNode(InputNode *inputNode, int errorCode) {
    this->inputNode = inputNode;
    this->errorCode = errorCode;
    this->type = ErrorCode;
  }

  void print(raw_ostream &out) const override {
    out << "Error code: " << errorCode
        << " Caused by Input Node: " << *inputNode;
  }
  string to_string() const override {
    return "Error code: " + std::to_string(errorCode) +
           " Caused by Input Node: " + inputNode->to_string();
  }

  ErrorCodeNode(string str) {
    size_t errorCodePos = str.find("Error code: ") + 12;
    string errorCodeStr =
        str.substr(errorCodePos, str.find(" Caused by API") - errorCodePos);
    this->errorCode = stoi(errorCodeStr);

    size_t apiPos = str.find("Caused by API: ") + 15;
    this->inputNode =
        new InputNode(str.substr(apiPos, str.find('\n') - apiPos));
    this->type = ErrorCode;
  }

  bool operator==(const ErrorCodeNode &other) const {
    // Check for self-comparison
    if (this == &other)
      return true;
    bool inputNodeEqual = (inputNode && other.inputNode)
                              ? (*inputNode == *other.inputNode)
                              : (inputNode == other.inputNode);
    return InputNode::operator==(other) && errorCode == other.errorCode &&
           inputNodeEqual;
  }
};

struct GlobalVarInNode : InputNode {
  string globalName;

  GlobalVarInNode(string globalName) {
    if (globalName.find('Global variable: ') != -1) {
      size_t startPos = globalName.find(": ") + 2;
      this->globalName = globalName.substr(startPos);
      this->type = GlobalVarIn;
    } else {
      this->globalName = globalName;
      this->type = GlobalVarIn;
    }
  }

  void print(raw_ostream &out) const override {
    out << "Global variable: " << globalName;
  }

  string to_string() const override { return "Global variable: " + globalName; }

  bool operator==(const GlobalVarInNode &other) const {
    if (this == &other)
      return true;
    return InputNode::operator==(other) && globalName == other.globalName;
  }
};

enum OutputType {
  IndirectRet,
  SensitiveAPI,
  SensitiveOp,
  CustmoizedAPI,
  GlobalVarOut,
};

struct OutputNode {
  OutputType type;
  string nodeFuncName;
  SEGNodeBase *usedNode;
  SEGSiteBase *usedSite;

  virtual void print(raw_ostream &out) const {}
  virtual string to_string() const {}

  OutputNode() {}
  OutputNode(string str) {}

  friend raw_ostream &operator<<(raw_ostream &out, const OutputNode &node) {
    node.print(out);
    return out;
  }
  bool operator==(const OutputNode &output) const {
    return output.type == type && nodeFuncName == output.nodeFuncName &&
           usedNode == output.usedNode && usedSite == output.usedSite;
  }
};

struct IndirectRetNode : OutputNode {
  string funcName;
  IndirectRetNode(string funcName) {
    if (funcName.find("Return of indirect call: ") != -1) {
      size_t startPos = funcName.find(": ") + 2;
      this->funcName = funcName.substr(startPos);
      this->nodeFuncName = funcName;
      this->type = IndirectRet;
    } else {
      this->funcName = funcName;
      this->nodeFuncName = funcName;
      this->type = IndirectRet;
    }
  }

  void print(raw_ostream &out) const override {
    out << "Return of indirect call: " << funcName;
  }

  string to_string() const { return "Return of indirect call: " + funcName; }

  bool operator==(const IndirectRetNode &other) const {
    return OutputNode::operator==(other) && other.type == type;
  }
};

struct SensitiveOpNode : OutputNode {
  string opCode;
  int opIdx;

  SensitiveOpNode(string opCode, int opIdx, string nodeFuncName) {
    this->opCode = opCode;
    this->opIdx = opIdx;
    this->nodeFuncName = nodeFuncName;
    this->type = SensitiveOp;
  }

  SensitiveOpNode(string str) {
    size_t callPos = str.find("Used in sensitive opcode: ") + 26;
    this->opCode = str.substr(callPos, str.find(" Operand idx") - callPos);

    size_t argIdxPos = str.find("Operand idx: ") + 13;
    string argIdxStr = str.substr(argIdxPos, str.find('\n') - argIdxPos);
    this->opIdx = stoi(argIdxStr);
    this->type = SensitiveOp;
  }

  void print(raw_ostream &out) const override {
    out << "Used in sensitive opcode: " << opCode << " Operand idx: " << opIdx;
  }

  string to_string() const {
    return "Used in sensitive opcode: " + opCode +
           " Operand idx: " + std::to_string(opIdx);
  }

  bool operator==(const SensitiveOpNode &other) const {
    if (this == &other)
      return true;
    return OutputNode::operator==(other) && opCode == other.opCode &&
           opIdx == other.opIdx;
  }
};

struct SensitiveAPINode : OutputNode {
  string apiName;
  unsigned int argIdx;

  SensitiveAPINode(string apiName, unsigned int argIdx, string nodeFuncName) {
    this->apiName = apiName;
    this->argIdx = argIdx;
    this->nodeFuncName = nodeFuncName;
    this->type = SensitiveAPI;
  }

  SensitiveAPINode(string str) {
    size_t callPos = str.find("Used in sensitive API: ") + 23;
    this->apiName = str.substr(callPos, str.find(" Arg idx") - callPos);

    size_t argIdxPos = str.find("Arg idx: ") + 9;
    string argIdxStr = str.substr(argIdxPos, str.find('\n') - argIdxPos);
    this->argIdx = stoi(argIdxStr);
    this->type = SensitiveAPI;
  }

  void print(raw_ostream &out) const override {
    out << "Used in sensitive API: " << apiName << " Arg idx: " << argIdx;
  }

  string to_string() const {
    return "Used in sensitive API: " + apiName +
           " Arg idx: " + std::to_string(argIdx);
  }

  bool operator==(const SensitiveAPINode &other) const {
    if (this == &other)
      return true;
    return OutputNode::operator==(other) && apiName == other.apiName &&
           argIdx == other.argIdx;
  }
};

struct CustomizedAPINode : OutputNode {
  string apiName;
  unsigned int argIdx;

  CustomizedAPINode(string apiName, unsigned int argIdx, string nodeFuncName) {
    this->apiName = apiName;
    this->argIdx = argIdx;
    this->nodeFuncName = nodeFuncName;
    this->type = CustmoizedAPI;
  }

  CustomizedAPINode(string str) {
    size_t callPos = str.find("Used in customized API: ") + 24;
    this->apiName = str.substr(callPos, str.find(" Arg idx") - callPos);

    size_t argIdxPos = str.find("Arg idx: ") + 9;
    string argIdxStr = str.substr(argIdxPos, str.find('\n') - argIdxPos);
    this->argIdx = stoi(argIdxStr);
    this->type = CustmoizedAPI;
  }

  void print(raw_ostream &out) const override {
    out << "Used in customized API: " << apiName << " Arg idx: " << argIdx;
  }

  string to_string() const {
    return "Used in customized API: " + apiName +
           " Arg idx: " + std::to_string(argIdx);
  }

  bool operator==(const CustomizedAPINode &other) const {
    if (this == &other)
      return true;
    return OutputNode::operator==(other) && apiName == other.apiName &&
           argIdx == other.argIdx;
  }
};

struct GlobalVarOutNode : OutputNode {
  string globalName;
  GlobalVarOutNode(string globalName, string nodeFuncName) {
    if (globalName.find("Global variable: ") != -1) {
      size_t startPos = globalName.find(": ") + 2;
      this->globalName = globalName.substr(startPos);
      this->nodeFuncName = nodeFuncName;
      this->type = GlobalVarOut;
    } else {
      this->globalName = globalName;
      this->nodeFuncName = nodeFuncName;
      this->type = GlobalVarOut;
    }
  }

  void print(raw_ostream &out) const override {
    out << "Global variable: " << globalName;
  }

  string to_string() const { return "Global variable: " + globalName; }

  bool operator==(const GlobalVarOutNode &other) const {
    if (this == &other)
      return true;
    return OutputNode::operator==(other) && globalName == other.globalName;
  }
};

#endif // CLEARBLUE_DRIVERSPECS_H
