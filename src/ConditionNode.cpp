
#include "ConditionNode.h"
#include "EnhancedSEG.h"

ConditionNode *ConditionNode::processNode(ConditionNode *node) {
  bool changed;
  do {
    changed = false;
    auto originNode = node;
    node->simplify();
    DEBUG_WITH_TYPE("condition", dbgs() << "\nAfter Simplify:\n");
    node->dump();
    node = distribute(node, 0, changed);
    changed = changed || !node->isEqual(originNode);
    DEBUG_WITH_TYPE("condition", dbgs()
                                     << "\nAfter Process: " << changed << "\n");
    node->dump();
  } while (changed);
  return node;
}

ConditionNode *ConditionNode::distribute(ConditionNode *node, int depth,
                                         bool &changed) {
  if (node == nullptr)
    return nullptr;

  // Apply recursive distribution to children first
  for (size_t i = 0; i < node->children.size(); ++i) {
    node->children[i] = distribute(node->children[i], depth + 1, changed);
  }

  // Check and apply distribution based on node type
  //  if (node->type == NODE_OR) {
  //    for (size_t i = 0; i < node->children.size(); ++i) {
  //      if (node->children[i]->type == NODE_AND) {
  //        node = distributeORoverAND(node, i, depth + 1, changed);
  //      }
  //    }
  //  }
  if (node->type == NODE_AND) {
    for (size_t i = 0; i < node->children.size(); ++i) {
      if (node->children[i]->type == NODE_AND) {
        node = distributeANDoverOR(node, i, depth + 1, changed);
      }
    }
  }
  return node;
}

ConditionNode *ConditionNode::distributeANDoverOR(ConditionNode *node,
                                                  size_t index, int depth,
                                                  bool &changed) {
  // A and (B or C) = (A and B) or (A and C)
  if (depth > 5) {
    return node;
  }
  ConditionNode *orNode = node->children[index];
  if (orNode == nullptr || orNode->type != NODE_OR)
    return node;

  auto newORNode = new ConditionNode(SEGWrapper, NODE_OR);

  // Distribute AND over each child of OR
  for (ConditionNode *orChild : orNode->children) {
    auto newAndNode = new ConditionNode(SEGWrapper, NODE_AND);
    // Add all other siblings of OR to this new AND node
    for (size_t j = 0; j < node->children.size(); ++j) {
      if (j != index) {
        newAndNode->addChild(
            node->children[j]); // Recursively distribute siblings
      }
    }
    newAndNode->addChild(orChild); // Recursively distribute subchildren of OR
    newORNode->addChild(newAndNode);
  }
  if (!newORNode->isEqual(node)) {
    DEBUG_WITH_TYPE("condition", dbgs() << "\nBefore or distribution\n");
    node->dump();
    DEBUG_WITH_TYPE("condition", dbgs() << "\n");
    DEBUG_WITH_TYPE("condition", dbgs() << "\nAfter or distribution\n");
    newORNode->dump();
    DEBUG_WITH_TYPE("condition", dbgs() << "\n");
    changed = true;
  }
  return newORNode; // Recursively distribute the newly created OR node
}

ConditionNode *ConditionNode::distributeORoverAND(ConditionNode *node,
                                                  size_t index, int depth,
                                                  bool &changed) {
  if (depth > 5) {
    return node;
  }
  // A or (B and C) = (A or B) and (A or C)
  if (node == nullptr || node->type != NODE_OR)
    return node;

  // Get the AND node that needs to be distributed
  ConditionNode *andNode = node->children[index];
  if (andNode == nullptr || andNode->type != NODE_AND)
    return node;

  // Create a new AND node which will replace the original OR node
  auto newANDNode = new ConditionNode(SEGWrapper, NODE_AND);

  // Iterate over each child of the AND node
  // andNode is (B and C)
  for (auto andChild : andNode->children) {
    // andChild is B
    // Create a new OR node for each child of the AND node
    auto newORNode = new ConditionNode(SEGWrapper, NODE_OR);

    // Add the current child of AND to the new OR node
    newORNode->addChild(andChild);

    // Add all other OR siblings (except the AND node) to the new OR node
    for (size_t i = 0; i < node->children.size(); ++i) {
      if (i != index) {
        newORNode->addChild(node->children[i]);
      }
    }

    // Add the newly created OR node to the new AND node
    newANDNode->addChild(newORNode);
  }
  if (!newANDNode->isEqual(node)) {
    DEBUG_WITH_TYPE("condition", dbgs() << "\nBefore and distribution\n");
    node->dump();
    DEBUG_WITH_TYPE("condition", dbgs() << "\n");
    DEBUG_WITH_TYPE("condition", dbgs() << "\nAfter and distribution\n");
    newANDNode->dump();
    DEBUG_WITH_TYPE("condition", dbgs() << "\n");
    changed = true;
  }
  // Return the newly created AND node which has distributed the original AND
  // over OR
  return newANDNode; // Recursively distribute to handle nested structures
}

void ConditionNode::simplify() {
  ConditionNode *newNode = nullptr;
  this->simplifyConst();

  // Recursively simplify children
  for (auto child : children) {
    child->simplify();
  }

  // Apply simplification rules based on node type
  switch (this->type) {
  case NODE_AND:
    simplifyAnd();
    break;
  case NODE_OR:
    simplifyOr();
    break;
  case NODE_NOT:
    simplifyNot();
    break;
  case NODE_CONST:
    break;
  case NODE_VAR:
    break;
  }
}

bool isConstNode(ConditionNode *node) { return node->type == NODE_CONST; }
bool isInvalidNode(ConditionNode *node) {
  return node->children.empty() &&
         (node->type == NODE_AND || node->type == NODE_OR ||
          node->type == NODE_NOT);
}

void ConditionNode::simplifyConst() {
  for (ConditionNode *child : children) {
    child->simplifyConst();
  }
  children.erase(remove_if(children.begin(), children.end(), isConstNode),
                 children.end());
  children.erase(remove_if(children.begin(), children.end(), isInvalidNode),
                 children.end());
  if (isInvalidNode(this)) {
    this->clear();
  }
}

void ConditionNode::simplifyNot() {
  // Check if the current node is a NOT node
  if (this->type == NODE_NOT) {
    int notCount = 0;
    ConditionNode *current = this;

    // Count consecutive NOT nodes
    while (current->type == NODE_NOT && current->children.size() > 0) {
      notCount++;
      current = current->children[0];
    }

    // Check if we reached a variable after consecutive NOTs
    if (current->type == NODE_VAR) {
      if (notCount % 2 == 0) {
        // Even number of NOTs, simplify to just the variable
        this->type = NODE_VAR;
        this->value = current->value;
        this->children.clear();
      } else {
        // Odd number of NOTs, simplify to NOT node above the variable
        this->children[0] =
            current; // Keep the last NOT's child as the current variable
        this->children.resize(1); // Ensure there are no additional children
      }
    }
  }
}

void ConditionNode::simplifyAnd() {
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "\nBefore And Simplify\n");
  //  DEBUG_WITH_TYPE("condition",  dbgs() << this->dump();

  vector<ConditionNode *> simplifiedChildren;

  for (ConditionNode *child : children) {
    // Check for duplicates or negations
    bool containConflict = false, containMerge = false;
    bool containAReduceB = false, containBReduceA = false;

    vector<ConditionNode *> toBeRemoved;
    for (auto item : simplifiedChildren) {
      if (SEGWrapper->isConditionConflict(item, child)) {
        containConflict = true;
      }
      if (SEGWrapper->isConditionMerge(item, child)) {
        containMerge = true;
      }
      if (SEGWrapper->isConditionAReduceB(item, child)) {
        containAReduceB = true;
      }
      if (SEGWrapper->isConditionAReduceB(child, item)) {
        containBReduceA = true;
        toBeRemoved.push_back(item);
      }
    }

    if (!containConflict) {
      if (child->type == NODE_OR) {
        if (isAbsorptionLaw(child, simplifiedChildren)) {
          continue;
        } else {
          addUnique(simplifiedChildren, child);
        }
      } else if (child->type == NODE_AND) {
        simplifiedChildren.insert(simplifiedChildren.end(),
                                  child->children.begin(),
                                  child->children.end());
      } else {
        if (containAReduceB || containMerge) {
          continue;
        }

        if (containBReduceA) {
          for (ConditionNode *sibling : toBeRemoved) {
            simplifiedChildren.erase(find(simplifiedChildren.begin(),
                                          simplifiedChildren.end(), sibling));
          }
        }
        addUnique(simplifiedChildren, child);
      }
    } else {
      // contain conflict conditions, remove all, turn to false;
      simplifiedChildren.clear();
      break;
    }
  }

  if (simplifiedChildren.size() == 1) {
    this->type = simplifiedChildren[0]->type;
    this->value = simplifiedChildren[0]->value;
    this->children = simplifiedChildren[0]->children;
  } else if (simplifiedChildren.empty()) {
    this->clear();
  } else {
    this->children = simplifiedChildren;
  }

  //  DEBUG_WITH_TYPE("condition",  dbgs() << "\nAfter And Simplify\n");
  //  DEBUG_WITH_TYPE("condition",  dbgs() << this->dump();
}

void ConditionNode::simplifyOr() {
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "\nBefore Or Simplify\n");
  //  DEBUG_WITH_TYPE("condition",  dbgs() << this->dump();
  vector<ConditionNode *> simplifiedChildren;

  for (ConditionNode *child : children) {

    // Check for duplicates or negations
    bool containConflict = false, containMerge = false;
    bool containAReduceB = false, containBReduceA = false;

    vector<ConditionNode *> toBeRemoved;
    for (auto item : simplifiedChildren) {
      if (SEGWrapper->isConditionConflict(item, child)) {
        containConflict = true;
      }
      if (SEGWrapper->isConditionMerge(item, child)) {
        containMerge = true;
      }
      if (SEGWrapper->isConditionAReduceB(item, child)) {
        containAReduceB = true;
      }
      if (SEGWrapper->isConditionAReduceB(child, item)) {
        containBReduceA = true;
        toBeRemoved.push_back(item);
      }
    }

    if (!containConflict) {
      if (child->type == NODE_AND) { // xxx or (xxx and xxx)
        if (isAbsorptionLaw(child, simplifiedChildren)) {
          continue;
        } else {
          addUnique(simplifiedChildren, child);
        }
      } else if (child->type == NODE_OR) { // xxx or (xxx or xxx)
        simplifiedChildren.insert(simplifiedChildren.end(),
                                  child->children.begin(),
                                  child->children.end());
      } else {
        if (containBReduceA || containMerge) {
          continue;
        }
        if (containAReduceB) {
          for (ConditionNode *sibling : toBeRemoved) {
            simplifiedChildren.erase(find(simplifiedChildren.begin(),
                                          simplifiedChildren.end(), sibling));
          }
        }

        addUnique(simplifiedChildren, child);
      }
    } else { // xxx or not xxx
      simplifiedChildren.clear();
      break;
    }
  }

  if (simplifiedChildren.size() == 1) {
    this->type = simplifiedChildren[0]->type;
    this->value = simplifiedChildren[0]->value;
    this->children = simplifiedChildren[0]->children;
  } else if (simplifiedChildren.empty()) {
    this->clear();
  } else {
    this->children = simplifiedChildren;
  }
  //  DEBUG_WITH_TYPE("condition",  dbgs() << "\nAfter Or Simplify\n");
  //  DEBUG_WITH_TYPE("condition",  dbgs() << this->dump();
}

// Custom comparison function
bool customEqual(ConditionNode *a, ConditionNode *b) {
  // Example custom condition: consider equal if the difference is less than 3
  return a->isEqual(b);
}

bool isSubVector(const vector<ConditionNode *> &a,
                 const vector<ConditionNode *> &b) {
  // Early exit if 'a' is longer than 'b'
  if (a.size() > b.size())
    return false;

  // Search for the first element of 'a' in 'b'
  auto it = search(b.begin(), b.end(), a.begin(), a.end(), customEqual);

  // If iterator is not at the end, 'a' is a subvector of 'b'
  return it != b.end();
}

bool ConditionNode::isAbsorptionLaw(ConditionNode *a,
                                    vector<ConditionNode *> &b) {
  // a is (A and B)
  // b is [A]
  for (ConditionNode *sibling : b) {
    if (sibling != a) {
      for (auto &it : a->children) {
        if (sibling->isEqual(it)) {
          //          DEBUG_WITH_TYPE("condition",  dbgs() << it->dump() <<
          //          "\n"); DEBUG_WITH_TYPE("condition",  dbgs() <<
          //          sibling->dump() << "\n");
          return true;
        }
      }
    }
  }

  // a is A
  // b is [(A and B), (A and B and C)]
  vector<ConditionNode *> toBeRemoved;
  for (ConditionNode *sibling : b) {
    if (sibling != a) {
      for (auto &it : sibling->children) {
        if (a->isEqual(it)) {
          DEBUG_WITH_TYPE("condition", dbgs() << sibling->dump() << "\n");
          DEBUG_WITH_TYPE("condition", dbgs() << a->dump() << "\n");
          toBeRemoved.push_back(sibling);
          break;
        }
      }
    }
  }

  if (!toBeRemoved.empty()) {
    DEBUG_WITH_TYPE("condition", dbgs() << b.size() << "\n");
    for (ConditionNode *sibling : toBeRemoved) {
      b.erase(find(b.begin(), b.end(), sibling));
    }
    DEBUG_WITH_TYPE("condition", dbgs() << b.size() << "\n");
    return false;
  }

  // a is (A and B and C)
  // b is [(A and B)]
  for (ConditionNode *sibling : b) {
    if (sibling != a) {
      if (a->type != sibling->type) {
        continue;
      }
      // sibling is (A and B)
      // a is (A and B and C)
      if (isSubVector(sibling->children, a->children)) {
        //          DEBUG_WITH_TYPE("condition",  dbgs() << a->dump() << "\n");
        //          DEBUG_WITH_TYPE("condition",  dbgs() << sibling->dump() <<
        //          "\n");
        return true;
      }
    }
  }

  // a is (A, B)
  // b is [(A and B and C), (A and B and D)]
  toBeRemoved.clear();
  for (ConditionNode *sibling : b) {
    if (sibling != a) {
      if (a->type != sibling->type) {
        continue;
      }
      if (isSubVector(a->children, sibling->children)) {
        DEBUG_WITH_TYPE("condition", dbgs() << "isAbsorptionLaw\n"
                                            << sibling->dump() << "\n");
        DEBUG_WITH_TYPE("condition", dbgs() << a->dump() << "\n");
        toBeRemoved.push_back(sibling);
      }
    }
  }

  if (!toBeRemoved.empty()) {
    DEBUG_WITH_TYPE("condition", dbgs() << b.size() << "\n");
    for (ConditionNode *sibling : toBeRemoved) {
      b.erase(find(b.begin(), b.end(), sibling));
    }
    DEBUG_WITH_TYPE("condition", dbgs() << b.size() << "\n");
    return false;
  }
  return false;
}

bool ConditionNode::isEqual(ConditionNode *a, ConditionNode *b) {
  return a->isEqual(b);
}

bool ConditionNode::isEqual(ConditionNode *other) {
  if (other == nullptr)
    return false;

  if (SEGWrapper->isConditionMerge(this, other)) {
    return true;
  }

  if (type != other->type)
    return false;
  if ((value == nullptr) ^ (other->value == nullptr))
    return false;
  if (value && other->value && value != other->value)
    return false;
  if (children.size() != other->children.size())
    return false;
  for (size_t i = 0; i < children.size(); ++i) {
    if (!children[i]->isEqual(other->children[i]))
      return false;
  }
  return true;
}

void ConditionNode::addUnique(vector<ConditionNode *> &list,
                              ConditionNode *node) {
  for (ConditionNode *item : list) {
    if (isEqual(item, node))
      return;
  }
  list.push_back(node);
}

ConditionNode *ConditionTree::parseFromString(string dumped_str,
                                              EnhancedSEGWrapper *SEGWrapper,
                                              set<SEGNodeBase *> nodeSet) {
  istringstream iss(dumped_str);
  string line;
  ConditionNode *root = nullptr;
  stack<ConditionNode *> node_stack;

  while (getline(iss, line)) {
    if (line.empty()) {
      continue;
    }

    int level = 0;
    while (level < line.size() && line[level] == ' ') {
      level++;
    }
    level /= 2; // 2 spaces per level

    auto trimmed = line.substr(level * 2);
    istringstream line_stream(trimmed);
    string node_type_str;
    line_stream >> node_type_str;

    NodeType node_type;
    if (node_type_str == "AND")
      node_type = NODE_AND;
    else if (node_type_str == "OR")
      node_type = NODE_OR;
    else if (node_type_str == "NOT")
      node_type = NODE_NOT;
    else if (node_type_str.substr(0, strlen("VALUE")) == "VALUE")
      node_type = NODE_VAR;
    else
      continue; // Handle unknown types or add error handling

    auto node = new ConditionNode(SEGWrapper, node_type);

    if (node_type == NODE_VAR) {
      string value_str = node_type_str.substr(node_type_str.find("%"),
                                              node_type_str.find(")") -
                                                  node_type_str.find("%"));

      for (auto segNode : nodeSet) {
        if (valueToString(segNode->getLLVMDbgValue()) == value_str) {
          node->value = segNode;
          break;
        }
      }
    }

    if (level == 0) {
      root = node;
    } else {
      while (node_stack.size() > level) {
        node_stack.pop();
      }
      if (!node_stack.empty()) {
        node_stack.top()->addChild(node);
      }
    }

    node_stack.push(node);
  }

  return root;
}

string generateUniqueFilename(const string &content, const string &prefix) {
  auto now = chrono::system_clock::now().time_since_epoch();
  auto now_ms = chrono::duration_cast<chrono::milliseconds>(now).count();

  hash<string> hasher;
  auto content_hash = hasher(content + to_string(now_ms));

  stringstream ss;
  ss << prefix << "_" << hex << content_hash;
  return ss.str();
}

string createArgFile(const string &args) {
  string filename = generateUniqueFilename(args, "/tmp/");
  ofstream out(filename);
  if (!out) {
    throw runtime_error("Failed to create the argument file.");
  }
  out << args;
  out.close();
  return filename;
}

string execCommand(const string &command) {
  array<char, 128> buffer{};
  string result;
  unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
  if (!pipe) {
    throw runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

string readFileContents(string filePath) {
  filePath.erase(filePath.end() - 1);
  ifstream file(filePath);
  if (!file.is_open()) {
    throw runtime_error("Could not open file: " + filePath);
  }

  stringstream buffer;
  buffer << file.rdbuf();
  file.close();
  return buffer.str();
}

ConditionNode *ConditionTree::simplifyCondition(EnhancedSEGWrapper *SEGWrapper,
                                                ConditionNode *node) {
  set<SEGNodeBase *> allSEGNode = node->obtainNodes();

  string command =
      "python3 /Users/harperchen/PycharmProjects/pythonProject9/main.py "
      "simplify " +
      createArgFile(node->dump());
  string outputExpr = readFileContents(execCommand(command));
  return parseFromString(outputExpr, SEGWrapper, allSEGNode);
}

ConditionNode *ConditionTree::diffCondition(ConditionNode *node1,
                                            ConditionNode *node2) {
  set<SEGNodeBase *> allSEGNode1 = node1->obtainNodes();
  set<SEGNodeBase *> allSEGNode2 = node2->obtainNodes();

  string command =
      "python3 /Users/harperchen/PycharmProjects/pythonProject9/main.py diff " +
      createArgFile(node1->dump()) + " " + createArgFile(node2->dump());
  string outputExpr = readFileContents(execCommand(command));

  //  ConditionNode *diffNode = parseFromString(outputExpr, );
}

void ConditionNode::eliminateCond(SEGNodeBase *node) {
  if (this->type == NODE_VAR && this->value == node) {
    this->clear();
    return;
  }
  for (auto child : this->children) {
    child->eliminateCond(node);
  }
  //  this->simplify();
}
