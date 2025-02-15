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
    "Indirect Call",
    "Spec Type",
    "Spec Input",
    "Spec Output",
    "Spec Cond SMT ",
    "Spec Orders",
]
data_df = pd.DataFrame(columns=data_cols)
spec_df = pd.DataFrame(columns=spec_cols)


def count_spec(root, patch_file):
    global data_df
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

    info["Directory"] = root
    df2 = pd.DataFrame(info, index=[0])
    data_df = pd.concat([df2, data_df.loc[:]], ignore_index=True)
    return spec_infos

def merge_spec_csvs(spec_files):
    global spec_df
    
    for file in spec_files:
        df = pd.read_csv(file)
        df['Directory'] = os.path.dirname(file)
        for col in spec_cols:
            if col not in df.columns:
                df[col] = None 
        spec_df = spec_df.append(df[spec_cols], ignore_index=True)
    
    
if __name__ == "__main__":
    indirect_df = pd.read_csv(FILTER_PATCH)
    indirect_df = indirect_df.fillna("")
    indirect_df = indirect_df[indirect_df["indirect call"] != ""]

    num = 0
    spec_files = []
    for root, dirs, files in os.walk(PATCH_DIR):
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
            if file.endswith('specs.csv'):
                spec_files.append(os.path.join(root, file))
                
    merge_spec_csvs(spec_files=spec_files)
    data_df.to_csv(DATA_PATCH, index=False)
    spec_df.to_csv(SPEC_PATCH, index=False)
