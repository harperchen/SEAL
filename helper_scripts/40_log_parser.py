import os
import pandas as pd
from config import *
import re

pattern = r":\s*(\d+)"
data_col_name = [
    "2.2 [# Before SEG Traces Stage 1]",
    "2.2 [# After  SEG Traces Stage 1]",
    "2.2 [# Backward Visited Stage 1]",
    "2.2 [# Forward  Visited Stage 1]",
    "2.2 [# Before SEG Traces Stage 2]",
    "2.2 [# After  SEG Traces Stage 2]",
    "2.2 [# Backward Visited Stage 2]",
    "2.2 [# Forward  Visited Stage 2]",
    "2.2 [# Before SEG Traces Stage 3]",
    "2.2 [# After  SEG Traces Stage 3]",
    "2.2 [# Backward Visited Stage 3]",
    "2.2 [# Forward  Visited Stage 3]",
    "2.2 [# Before SEG Traces Stage 4]",
    "2.2 [# After  SEG Traces Stage 4]",
    "2.2 [# Backward Visited Stage 4]",
    "2.2 [# Forward  Visited Stage 4]",
    "2.2 [# Matched SEG Nodes Before]",
    "2.2 [# Matched SEG Nodes After]",
    "2.3 [Matched   Intra Conditions]",
    "2.3 [Unchanged Intra Slicings]",
    "2.3 [Added     Intra Slicings]",
    "2.3 [Removed   Intra Slicings]",
    "2.3 [Condition Intra Slicings]",
    "2.3 [Order     Intra Slicings]",
    "2.4 [Added   Inter Slicings]",
    "2.4 [Removed Inter Slicings]",
    "2.4 [Cond    Inter Slicings]",
    "2.4 [Order   Inter Slicings]",
]

data_cols = [
    "Directory",
    "Added Spec",
    "Remove Spec",
    "Cond Spec",
    "Order Spec"
] + data_col_name

spec_cols = [
    "Directory",
    "Spec Type",
    "Input Node",
    "Output Node",
    "Constraint",
    "Order",
    "Hexsha",
    "Indirect Call",
    "Peers",
]
data_df = pd.DataFrame(columns=data_cols)
spec_df = pd.DataFrame(columns=spec_cols)


def count_spec(root, patch_file):
    global data_df, spec_df
    info = {}
    spec_infos = []
    with open(os.path.join(root, patch_file), "r") as f:
        iterf = iter(f)
        for line in iterf:
            for d in data_col_name:
                if d in line:
                    match = re.search(pattern, line)
                    if match:
                        # Extract the number from the match
                        number = match.group(1)
                        info[d] = number
                    else:
                        print("No number found in line.")

            if "[After Unmatched Values, Added Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Unmatched Values, Added Intra"] = num

            elif "[After Unmatched Values, Removed Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Unmatched Values, Removed Intra"] = num

            elif "[After Matched Values, Added Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Matched Values, Added Intra"] = num

            elif "[After Matched Values, Removed Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Matched Values, Removed Intra"] = num

            elif "[After Matched Values, Cond Changed Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Matched Values, Cond Changed Intra"] = num

            elif "[After Matched Values, Ord Changed Intra Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Matched Values, Ord Changed Intra"] = num

            elif "[Added Inter Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Added Inter"] = num

            elif "[Removed Inter Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Removed Inter"] = num

            elif "[Cond Changed Inter Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Cond Changed Inter"] = num

            elif "[Ord Changed Inter Slicings]:" in line:
                num = int(line[line.find(": ") + 2 :])
                info["Ord Changed Inter"] = num

            elif "Added Spec:  #" in line:
                num = line[line.find("#") + 1 :]
                num = int(num[: num.find("=")])
                info["Added Spec"] = num
            elif "Remove Spec: #" in line:
                num = line[line.find("#") + 1 :]
                num = int(num[: num.find("=")])
                info["Remove Spec"] = num
            elif "Cond Spec:   #" in line:
                num = line[line.find("#") + 1 :]
                num = int(num[: num.find("=")])
                info["Cond Spec"] = num
            elif "Order Spec:  #" in line:
                num = line[line.find("#") + 1 :]
                num = int(num[: num.find("=")])
                info["Order Spec"] = num
            elif "[Add Start" in line:
                spec_info = {}
                line.strip()
                dirs = root.split("/")[-1]
                spec_info["Directory"] = dirs
                spec_info["Spec Type"] = "Add"
                input_node = line[line.find("[InputNode]: ") + 13 : -1]
                spec_info["Input Node"] = input_node
                next_line = next(iterf)
                next_line.strip()
                if "[OutputNode]:" in next_line:
                    output_node = next_line[next_line.find("[OutputNode]: ") + 14 : -1]
                    spec_info["Output Node"] = output_node
                else:
                    spec_info["Output Node"] = ""

                next_line = next(iterf)
                next_line.strip()
                if "[Add Expr Start]" in next_line:
                    cons_info = ""
                    cons_line = next(iterf)
                    while (
                        "[Add Expr End]" not in cons_line
                        and "Segmentation fault" not in cons_line
                    ):
                        cons_info += cons_line
                        cons_line = next(iterf)
                    if "Segmentation fault" not in cons_line:
                        smt_path = os.path.join(
                            root, "spec" + str(len(spec_infos)) + ".smt2"
                        )
                        with open(smt_path, "w") as smtf:
                            smtf.write(cons_line)
                        spec_info["Constraint"] = smt_path
                    else:
                        spec_info["Constraint"] = ""
                else:
                    spec_info["Constraint"] = ""

                spec_info["Order"] = ""
                spec_info["Hexsha"] = dirs[:12]
                spec_infos.append(spec_info)
            elif "[Remove Start" in line:
                spec_info = {}
                line.strip()
                dirs = root.split("/")[-1]
                spec_info["Directory"] = dirs
                spec_info["Spec Type"] = "Remove"
                input_node = line[line.find("[InputNode]: ") + 13 : -1]
                spec_info["Input Node"] = input_node
                next_line = next(iterf)
                next_line.strip()

                if "[OutputNode]:" in next_line:
                    output_node = next_line[next_line.find("[OutputNode]: ") + 14 : -1]
                    spec_info["Output Node"] = output_node
                else:
                    spec_info["Output Node"] = ""

                next_line = next(iterf)
                next_line.strip()
                if "[Removed Expr Start]" in next_line:
                    cons_info = ""
                    cons_line = next(iterf)
                    while (
                        "[Removed Expr End]" not in cons_line
                        and "Segmentation fault" not in cons_line
                    ):
                        cons_info += cons_line
                        cons_line = next(iterf)
                    if "Segmentation fault" not in cons_line:
                        smt_path = os.path.join(
                            root, "spec" + str(len(spec_infos)) + ".smt2"
                        )
                        with open(smt_path, "w") as smtf:
                            smtf.write(cons_line)
                        spec_info["Constraint"] = smt_path
                    else:
                        spec_info["Constraint"] = ""
                else:
                    spec_info["Constraint"] = ""

                spec_info["Order"] = ""
                spec_info["Hexsha"] = dirs[:12]
                spec_infos.append(spec_info)

            elif "[Cond Start" in line:
                spec_info = {}
                line.strip()
                dirs = root.split("/")[-1]
                spec_info["Directory"] = dirs
                spec_info["Spec Type"] = "Condition"
                input_node = line[line.find("[InputNode]: ") + 13 : -1]
                spec_info["Input Node"] = input_node

                next_line = next(iterf)
                next_line.strip()
                if "[OutputNode]:" in next_line:
                    output_node = next_line[next_line.find("[OutputNode]: ") + 14 : -1]
                    spec_info["Output Node"] = output_node
                else:
                    spec_info["Output Node"] = ""

                next_line = next(iterf)
                next_line.strip()
                if "[Cond Expr Start]" in next_line:
                    cons_info = ""
                    cons_line = next(iterf)
                    while (
                        "[Cond Expr End]" not in cons_line
                        and "Segmentation fault" not in cons_line
                        and "Dumping current bug reports" not in cons_line
                    ):
                        cons_info += cons_line
                        cons_line = next(iterf)
                    if (
                        "Segmentation fault" not in cons_line
                        and "Dumping current bug reports" not in cons_line
                    ):
                        smt_path = os.path.join(
                            root, "spec" + str(len(spec_infos)) + ".smt2"
                        )
                        with open(smt_path, "w") as smtf:
                            smtf.write(cons_line)
                        spec_info["Constraint"] = smt_path
                    else:
                        spec_info["Constraint"] = ""
                else:
                    spec_info["Constraint"] = ""
                spec_info["Order"] = ""
                spec_info["Hexsha"] = dirs[:12]
                spec_infos.append(spec_info)

            elif "[Ord Start" in line:
                line.strip()
                spec_info = {}
                dirs = root.split("/")[-1]
                spec_info["Directory"] = dirs
                spec_info["Spec Type"] = "Order"
                input_node = line[line.find("[InputNode]: ") + 13 : -1]
                spec_info["Input Node"] = input_node
                output_node = ""
                next_line = next(iterf)
                while "[Ord End" in next_line:
                    next_line.strip()
                    output_node += (
                        next_line[next_line.find("[OutputNode]: ") + 14 : -1] + "$"
                    )
                    next_line = next(iterf)

                if output_node != "":
                    spec_info["Output Node"] = output_node[:-1]
                else:
                    spec_info["Output Node"] = ""
                spec_info["Constraint"] = ""

                if "[Ord Info]:" in next_line:
                    spec_info["Order"] = next_line[
                        next_line.find("[Ord Info]: ") + 12 : -2
                    ]
                else:
                    spec_info["Order"] = ""
                spec_info["Hexsha"] = dirs[:12]
                spec_infos.append(spec_info)

    info["Directory"] = root
    df2 = pd.DataFrame(info, index=[0])
    data_df = pd.concat([df2, data_df.loc[:]], ignore_index=True)
    return spec_infos


if __name__ == "__main__":
    indirect_df = pd.read_csv(
        "/home/seal/filter_calls.csv"
    )
    indirect_df = indirect_df.fillna("")
    indirect_df = indirect_df[indirect_df["indirect call"] != ""]

    num = 0
    for root, dirs, files in os.walk(
        "/home/seal/Patches_Bc"
    ):
        found_log = False
        cur_call = ""
        peer_files = ""
        spec_infos = []
        for file in files:
            if file.endswith("patch.log"):
                dirname = os.path.basename(root)
                indirect_call = indirect_df[indirect_df["hexsha"] == dirname[:12]]
                for idx, item in indirect_call.iterrows():
                    call = item["indirect call"]
                    if call[call.find(":") + 1 :] == dirname[13:]:
                        cur_call = call
                        break
                spec_infos = count_spec(root, file)
                print(os.path.join(root, file), num, len(spec_infos))
                num += 1
                found_log = True
            if file.endswith("peer.txt"):
                peer_files = os.path.join(root, file)

        if found_log and peer_files != "" and cur_call != "":
            if len(spec_infos) > 10:
                continue
            for spec_info in spec_infos:
                spec_info["Indirect Call"] = cur_call
                spec_info["Peers"] = peer_files
                df2 = pd.DataFrame(spec_info, index=[0])
                spec_df = pd.concat([df2, spec_df.loc[:]], ignore_index=True)

    data_df.to_csv(DATA_PATCH, index=False)
    spec_df.to_csv(SPEC_PATCH, index=False)
