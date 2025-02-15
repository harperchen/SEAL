
#ifndef CLEARBLUE_SPECPARSER_H
#define CLEARBLUE_SPECPARSER_H

#include <utility>

#include "CustomChecker.h"
#include "DriverSpecs.h"
#include "EnhancedSEG.h"
#include "SensitiveOps.h"

struct BugSpecification {
  enum specType {
    BS_SingleSrcSingleSink,
    BS_SingleSrcMultiSink,
  } type;

  ConditionNode *conditions;
  SMTExprVec *condExprVec;
  vector<Function *> indirects;
  bool fastMode = false;

  BugSpecification(specType type, vector<Function *> indirects, bool fastModes)
      : type(type), indirects(indirects), fastMode(fastModes){};

  BugSpecification(specType type) : type(type){};
};

struct SingleSrcSingleSinkSpec : BugSpecification {
  InputNode *inputNode;
  OutputNode *outputNode;
  bool isBuggy = false;

  SingleSrcSingleSinkSpec(InputNode *inputNode, OutputNode *outputNode,
                          vector<Function *> indirects, bool isBuggy,
                          bool fastMode)
      : BugSpecification(BS_SingleSrcSingleSink, indirects, fastMode),
        inputNode(inputNode), outputNode(outputNode), isBuggy(isBuggy){};

  SingleSrcSingleSinkSpec(InputNode *inputNode, OutputNode *outputNode,
                          bool isBuggy)
      : BugSpecification(BS_SingleSrcSingleSink), inputNode(inputNode),
        outputNode(outputNode), isBuggy(isBuggy){};
};

struct SingleSrcMultiSinkSpec : BugSpecification {
  InputNode *inputNode;
  vector<OutputNode *> outputNodes;
  map<OutputNode *, pair<int, int>> output2Order;

  SingleSrcMultiSinkSpec(InputNode *input, vector<OutputNode *> outputs,
                         vector<Function *> indirects, bool fastMode)
      : BugSpecification(BS_SingleSrcMultiSink, indirects, fastMode),
        inputNode(input), outputNodes(std::move(outputs)){};

  SingleSrcMultiSinkSpec(InputNode *inputNode, vector<OutputNode *> outputs,
                         map<OutputNode *, pair<int, int>> output2Order)
      : BugSpecification(BS_SingleSrcMultiSink), inputNode(inputNode),
        outputNodes(outputs), output2Order(output2Order){};
};

/*
 * 1. Filter out bug irrelvent slicings with the following metrics
 *   a. we cannot find X and Y from the traces, thus cannot be utilized to find
 * bugs in other drivers b. the condition do not contain X and Y, thus cannot be
 * utilized to find bugs in other drivers
 * 2. Create bug specification from remaining slicings
 * */

class SpecParser {
  GraphDiffer *graphParser;
  EnhancedSEGWrapper *SEGWrapper;

  bool isTwoInputNodeEq(InputNode *node1, InputNode *node2);
  bool isTwoOutputNodeEq(OutputNode *node1, OutputNode *node2);

  void handleDiffCondition();
  void groupSingleSrcMultiSink();

  void filterInvalidCond(vector<SEGObject *> &guardedTrace,
                         ConditionNode *condNode);
  void filterInvalidCondNodes(vector<SEGObject *> &guardedTrace,
                              set<SEGNodeBase *> &diffCondNodes,
                              set<SEGNodeBase *> &diffValidCondNodes);

  int filter_invalid_time = 0;
  int eliminate_cond = 0;
  int simplify_cond = 0;

public:
  // output
  set<BugSpecification *> driverBugSpecs;
  vector<shared_ptr<Vulnerability>> customizedCheckers;
  set<Function *> peerFuncs;

  set<SingleSrcSingleSinkSpec *> addedPairs, removedPairs;
  set<SingleSrcSingleSinkSpec *> condPairs;
  set<SingleSrcMultiSinkSpec *> orderPairs;

  SpecParser(EnhancedSEGWrapper *SEGWrapper, GraphDiffer *graphParser);
  bool isTransitiveCallee(Function *func);
  void loadSpecFromFile(string fileName);
  void abstractBugSpec(string outputFile);
  void specToOutput(string outputFile);
  void transformToCheckers();
};

#endif // CLEARBLUE_SPECPARSER_H
