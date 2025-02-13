import copy

import pandas as pd
import networkx as nx

from utils import *
from config import *
from pydriller import *


class IndirectParser:
    def __init__(self):
        self.repo = Git(LINUX_SRC_TEMPLATE)
        self.arch2call_graphs = {}
        for arch in ARCHS.split(", "):
            call_graphs = {}
            self.arch2call_graphs[arch] = call_graphs

    def parse_commit(self, item):
        node2_in_graph, found_arch, reasons1 = self.parse_changed_methods(item['hexsha'])
        if len(node2_in_graph) == 0:
            new_item = copy.deepcopy(item)
            new_item['indirect call'] = ""
            new_item['related files'] = ""
            new_item['arch'] = ""
            new_item['reason'] = ",".join(reasons1)
            return [new_item]

        node2indirects, reasons2 = self.parse_indirect(node2_in_graph, found_arch)
        if len(node2indirects) == 0:
            new_item = copy.deepcopy(item)
            new_item['indirect call'] = ""
            new_item['related files'] = ""
            new_item['arch'] = found_arch
            new_item['reason'] = ",".join(reasons1 + reasons2)
            return [new_item]

        ret = []
        unique_items = set()
        for node, indirects in node2indirects.items():
            for indirect in indirects:
                related_files = self.find_related(indirect, node, found_arch)
                unique_items.add((indirect, ','.join(related_files)))

        for indirect, related_files in unique_items:
            new_item = copy.deepcopy(item)
            new_item['indirect call'] = indirect.replace(' [Indirect]', '')
            new_item['related files'] = related_files
            new_item['arch'] = found_arch
            new_item['reason'] = ",".join(reasons1 + reasons2)
            ret.append(new_item)
        return ret

    def find_graph_node(self, func_name, arch):
        if func_name.startswith('drivers/'):
            driver_sub = func_name.split('/')[1]
        elif func_name.startswith('sound/'):
            driver_sub = 'sound'
        else:
            return ""

        key_name = "/" + driver_sub + "/"
        if key_name not in self.arch2call_graphs[arch]:
            file = CALL_DIR.format("v6.2", arch) + f"/{driver_sub}_36_final.dot"
            if not os.path.exists(file):
                return ""

            print('Loading dot', file)
            self.arch2call_graphs[arch][key_name] = nx.DiGraph(nx.nx_pydot.read_dot(file))

        for node in self.arch2call_graphs[arch][key_name].nodes:
            if ':' not in node:
                continue
            if func_name in node:
                return node
        return ""

    def parse_changed_methods(self, hexsha):
        reasons = []
        nodes_in_graph = set()

        changed_methods = set()
        commit = self.repo.get_commit(hexsha)
        for f in commit.modified_files:
            if f.change_type != ModificationType.MODIFY:
                continue
            for method in f.changed_methods:
                method_before = list(filter(lambda x: x.name == method.name, f.methods_before))
                if not method_before:
                    continue
                method_before = method_before[0]
                if method.name != method_before.name:
                    reasons.append("changed signature " + method_before.name + " -> " + method.name)
                    continue

                func_name = f.new_path + ":" + method.name
                changed_methods.add(func_name)

        found_arch = ""
        not_found_func = set()
        for arch in ARCHS.split(", "):
            found_all = True
            for func_name in changed_methods:
                node = self.find_graph_node(func_name, arch)
                if node == "":
                    found_all = False
                    not_found_func.add((arch, func_name))
                    break
            if not found_all:
                continue

            found_arch = arch
            for func_name in changed_methods:
                nodes_in_graph.add(self.find_graph_node(func_name, arch))
            break

        if found_arch == "":
            reasons.append("unsupported arch for " + str(list(not_found_func)) + "or version incompability")

        return nodes_in_graph, found_arch, reasons

    def parse_indirect(self, nodes_in_graph, node_arch):
        reasons = []
        node2indirects = {}

        for node in nodes_in_graph:
            if node.startswith('drivers/'):
                driver_sub = node.split('/')[1]
            elif node.startswith('sound/'):
                driver_sub = 'sound'
            else:
                continue

            key_name = "/" + driver_sub + "/"
            if key_name not in self.arch2call_graphs[node_arch]:
                file = CALL_DIR.format("v6.2", node_arch) + f"/{driver_sub}_36_final.dot"
                if not os.path.exists(file):
                    continue

                print('Loading dot', file)
                self.arch2call_graphs[node_arch][key_name] = nx.DiGraph(nx.nx_pydot.read_dot(file))

            parent_nodes = set()

            graph = self.arch2call_graphs[node_arch][key_name]
            for parent in nx.ancestors(graph, node):
                paths = nx.all_simple_paths(graph, parent, node, cutoff=6)
                if len(list(paths)) == 0:
                    continue
                if ':' not in parent:
                    continue
                parent_nodes.add(parent)
            parent_nodes.add(node)

            indirect_funcs = set()
            for parent in parent_nodes:
                if '[Indirect]' in parent:
                    indirect_funcs.add(parent)

            if len(indirect_funcs) == 0:
                reasons.append("No indirect call for " + node)
                continue
            if len(indirect_funcs) > 5:
                reasons.append(">5 indirect call for " + node)
                continue

            node2indirects[node] = indirect_funcs

        return node2indirects, reasons

    def find_related(self, indirect, node, node_arch):
        related_node = set()
        related_files = set()

        if node.startswith('drivers/'):
            driver_sub = node.split('/')[1]
        elif node.startswith('sound/'):
            driver_sub = 'sound'
        else:
            return related_files

        key_name = "/" + driver_sub + "/"
        if key_name not in self.arch2call_graphs[node_arch]:
            file = CALL_DIR.format("v6.2", node_arch) + f"/{driver_sub}_36_final.dot"
            if not os.path.exists(file):
                return related_files

            print('Loading dot', file)
            self.arch2call_graphs[node_arch][key_name] = nx.DiGraph(nx.nx_pydot.read_dot(file))

        graph = self.arch2call_graphs[node_arch][key_name]
        related_node.add(node)
        # collect parent
        paths = nx.all_simple_paths(graph, indirect, node, cutoff=6)
        for path in paths:
            for elem in path:
                related_node.add(elem)

        # collect child
        for child in nx.descendants(graph, node):
            paths = nx.all_simple_paths(graph, node, child, cutoff=6)
            if len(list(paths)) == 0:
                continue
            related_node.add(child)

        for item in related_node:
            if ':' not in item:
                continue
            file_path = item.split(':')[0]
            if file_path != "" and file_path.endswith('.c'):
                related_files.add(file_path)

        return related_files


def process_patch(parser, item):
    print('Commit ID ', item['hexsha'])
    return parser.parse_commit(item)


if __name__ == "__main__":
    df = pd.read_csv(INPUT_PATCH)
    df = df.dropna(axis=0, how='any')
    df = df.drop_duplicates(subset=['hexsha'], keep='first')

    if os.path.exists(FILTER_PATCH):
        patch_df = pd.read_csv(FILTER_PATCH)
    else:
        cols = ['hexsha', 'patch', 'summary', 'author', 'indirect call', 'related files', 'arch', 'reason']
        patch_df = pd.DataFrame(columns=cols)
    parser = IndirectParser()

    for idx, item in df.iterrows():
        print(idx, "/", len(df))
        if item['hexsha'] in patch_df['hexsha'].values:
            print('Already processed', item['hexsha'])
            continue
        print('Now processing', item['hexsha'])
        rows = process_patch(parser, item)
        new_df = pd.DataFrame(rows)
        patch_df = pd.concat([patch_df, new_df], ignore_index=True)
        patch_df.to_csv(FILTER_PATCH, index=False)
