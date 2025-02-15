#include "SEGPatchDiff.h"
#include "Checker/CBCheckerManager.h"
#include "Checker/CBPluginPass.h"
#include "EnhancedSEG.h"
#include "Platform/OS/Profiler.h"
#include <llvm/IR/Module.h>
#include <llvm/Support/Debug.h>
using namespace llvm;
using namespace std;

static cl::opt<bool, false>
    DumpIndirectCall("dump-indirect-call", cl::desc("Dump all indirect calls."),
                     cl::init(false), cl::Hidden);

static cl::opt<bool, false> DumpCallGraph(
    "dump-call-graph",
    cl::desc("Dump call graph without resolving function pointers."),
    cl::init(false), cl::Hidden);

static cl::opt<bool, false>
    InferPatchSpec("infer-patch-spec",
                   cl::desc("Extract patch specific specifications."),
                   cl::init(false), cl::Hidden);

static cl::opt<std::string>
    Patch("patch", cl::desc("The bug related codes are added/deleted"),
          cl::value_desc("file Name"), cl::ReallyHidden, cl::ValueOptional,
          cl::init(""));

static cl::opt<std::string>
    Output("output", cl::desc("Dump generated specifications into output file"),
           cl::init(""), cl::Hidden);

static cl::opt<bool, false>
    DetectPatchBug("detect-patch-bug",
                   cl::desc("Detect bugs using patch specifications."),
                   cl::init(false), cl::Hidden);

static cl::opt<std::string>
    Specs("specs", cl::desc("Input specifications generated from patches"),
          cl::init(""), cl::Hidden);

static cl::opt<std::string> Peers("peer", cl::desc("Peer function information"),
                                  cl::value_desc("file Name"), cl::ReallyHidden,
                                  cl::ValueOptional, cl::init(""));

static CBPluginPassRegistry<SEGPathDiff>
    X("patch-plugin", "Run spec inference and bug detection plugin.");

void SEGPathDiff::getAnalysisUsage(llvm::AnalysisUsage &AU) {
  AU.setPreservesAll();
  AU.addRequired<SymbolicExprGraphBuilder>();
  AU.addRequired<CBCallGraphWrapper>();
  AU.addRequired<DebugInfoAnalysis>();
  AU.addRequired<ControlDependenceAnalysis>();
  AU.addRequired<CFGReachabilityAnalysis>();
  AU.addRequired<DomTreePass>();
  AU.addRequired<TSDataLayout>();
  AU.addRequired<ExternalMemorySpec>();
  AU.addRequired<ExternalIOSpec>();
}

void SEGPathDiff::runOnModule(llvm::Module &M) {
  SEGBuilder = &getAnalysis<SymbolicExprGraphBuilder>();
  pCBCG = &getAnalysis<CBCallGraphWrapper>().getCallGraph();
  pDIA = &getAnalysis<DebugInfoAnalysis>();
  pCDGs = &getAnalysis<ControlDependenceAnalysis>();
  pCRA = &getAnalysis<CFGReachabilityAnalysis>();
  pDT = &getAnalysis<DomTreePass>();

  auto Fctry = new SMTFactory;
  MemSpec = &getAnalysis<ExternalMemorySpec>();
  IOSpec = &getAnalysis<ExternalIOSpec>();
  DL = &getAnalysis<TSDataLayout>();

  pSolver = new SymbolicExprGraphSolver(*Fctry, *DL, MemSpec, IOSpec);

  SEGWrapper = new EnhancedSEGWrapper(&M, SEGBuilder, pSolver, pDIA, pCBCG,
                                      pCDGs, pCRA, pDT);

  outs() << "Starting Checking..";
  if (DumpIndirectCall.getValue()) {
    // output all indirect called functions

    for (Function &func : M) {
      if (SEGWrapper->isIndirectCall(&func)) {
        outs() << "Indirect Call: " << SEGWrapper->getCallSourceFile(&func)
               << ":" << func.getName() << ";\n";
      }
    }
  } else if (DumpCallGraph.getValue()) {
    for (Function &F : M) { // key: caller, value: set of callees
      if (F.getName().find("clearblue") != string::npos) {
        continue;
      }
      if (F.empty()) {
        continue;
      }
      auto node = pCBCG->getOrInsertFunction(&F);
      set<Function *> callees;
      for (auto it = node->begin(); it != node->end(); it++) {
        Function *callee = it->second->getFunction();
        if (callee->isDeclaration() || callee->isIntrinsic() ||
            callee->empty()) {
          continue;
        }
        if (callee->getName().startswith("asan.")) {
          continue;
        }
        callees.insert(callee);
      }

      for (auto callee : callees) {
        if (!SEGWrapper->getCallSourceFile(callee).empty()) {
          string curFuncName = F.getName();
          if (SEGWrapper->isIndirectCall(&F)) {
            curFuncName += " [Indirect]";
          }
          string calleeFuncName = callee->getName();
          if (SEGWrapper->isIndirectCall(callee)) {
            calleeFuncName += " [Indirect]";
          }
          outs() << "Dot Call Graph: \"" << SEGWrapper->getCallSourceFile(&F)
                 << ":" << curFuncName << "\" -> \""
                 << SEGWrapper->getCallSourceFile(callee) << ":"
                 << calleeFuncName << "\";\n";
        }
      }
    }
  } else if (InferPatchSpec.getValue()) {
    Profiler TimeMemProfiler(Profiler::TIME | Profiler::MEMORY);
    Profiler TimeMemProfiler1(Profiler::TIME | Profiler::MEMORY);

    // step 1: changes in code => changes in values
    // input: LLVM IR before and after changes, patch file
    // output: (V-, V+, V=)
    outs() << "\n[Phase 1]: Parsing added/removed LLVM values from patch...\n";
    patchParser = new PatchParser(&M, pDIA, Patch.getValue());
    patchParser->parseIRChanges();

    outs() << "\n";
    TimeMemProfiler1.create_snapshot();
    TimeMemProfiler1.print_snapshot_result("Patch analysis stage 1 done");

    Profiler TimeMemProfiler2(Profiler::TIME | Profiler::MEMORY);
    // step 2: changes in value => changes in graph
    // input: (V-, V+, V=)
    // output: (S-, _), (S+, _), (S-, S+), (S, S)
    outs() << "\n[Phase 2]: Found added/removed value flows from add/removed "
              "LLVM values...\n";
    graphParser = new GraphDiffer(SEGWrapper, pSolver);
    graphParser->parseValueFlowChanges(patchParser->addedValues,
                                       patchParser->removedValues);

    outs() << "\n";
    TimeMemProfiler2.create_snapshot();
    TimeMemProfiler2.print_snapshot_result("Patch analysis stage 2 done");

    Profiler TimeMemProfiler3(Profiler::TIME | Profiler::MEMORY);

    // step 3: bug spec inference
    // input: (S-, _), (S+, _), (S-, S+), (S, S)
    // output: (X, Y) + cond + order
    outs() << "\n[Phase 3]: Summarize bug specifications from add/removed "
              "value flows...\n";
    specParser = new SpecParser(SEGWrapper, graphParser);
    specParser->abstractBugSpec(Output.getValue());
    outs() << "\n";
    TimeMemProfiler3.create_snapshot();
    TimeMemProfiler3.print_snapshot_result("Patch analysis stage 3 done");

    outs() << "\n";
    TimeMemProfiler.create_snapshot();
    TimeMemProfiler.print_snapshot_result("Patch analysis done");
  } else if (DetectPatchBug) {
    graphParser = new GraphDiffer(SEGWrapper, pSolver);
    specParser = new SpecParser(SEGWrapper, graphParser);

    // step 4: bug matching
    // input: (X, Y) + cond + order
    // output: customized bug checkers
    specParser->loadSpecFromFile(Specs.getValue());
    specParser->transformToCheckers();
    customizedCheckers = specParser->customizedCheckers;

    CBCheckerManager *checker_mgr = CBCheckerManager::getCheckerManager();
    checker_mgr->initializeExternalCheckers(&M, customizedCheckers);
  }
}
