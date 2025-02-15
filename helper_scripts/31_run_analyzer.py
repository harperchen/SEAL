import os.path
import threading
import time
import re
import glob
import requests

import pandas as pd
from tqdm import tqdm
from git import Repo

from utils import *
from pydriller import *
from pandarallel import pandarallel
from multiprocessing import Pool
from multiprocessing import Lock
from multiprocessing import Event

# pandarallel.initialize(progress_bar=True,
#                        nb_workers=20,
#                        use_memory_fs=False,
#                        verbose=0)

lock = Lock()
data_list = multiprocessing.Manager().list()

if os.path.exists(CMD_OUTPUT_PATCH):
    output_df = pd.read_csv(CMD_OUTPUT_PATCH)
    if "version" not in output_df.columns:
        output_df.loc[:, "version"] = ""
    condition = (output_df["is failed"] == "Succeed") & (output_df["version"] == "")
    output_df.loc[condition, "version"] = "v6.2"
else:
    cols = ['hexsha', 'workdir', 'diff file', 'before bc', 'after bc', 'version', 'merge bc', 'extract patch',
            '# peer functions', 'bug_report', 'command', 'is failed', 'reason', 'arch']
    output_df = pd.DataFrame(columns=cols)


class PatchParser:
    def __init__(self):
        self.repo = Git(LINUX_SRC_TEMPLATE)

    def parse_commit(self, workdir, item, is_failed):
        hexsha = item['hexsha']
        if not os.path.exists(workdir):
            os.makedirs(workdir)

        reason1, reason2, reason3, reason4 = [], [], [], []
        if item['related files'] == '':
            return {
                'hexsha': hexsha,
                'workdir': workdir,
                'diff file': True,
                'before bc': False,
                'after bc': False,
                'version': '',
                'merge bc': False,
                'extract patch': False,
                '# peer functions': 0,
                'bug_report': '',
                'command': '',
                'is failed': 'No related files',
                'reason': ' '.join(reason1)
            }

        if (not os.path.exists(os.path.join(workdir, 'before.bc'))
                or is_failed == "Before BC Failed" or is_failed == "After BC Failed"):
            return {
                'hexsha': hexsha,
                'workdir': workdir,
                'diff file': True,
                'before bc': False,
                'after bc': False,
                'version': '',
                'merge bc': False,
                'extract patch': False,
                '# peer functions': 0,
                'bug_report': '',
                'command': '',
                'is failed': 'Before BC Failed',
                'reason': ' '.join(reason1)
            }

        if not os.path.exists(os.path.join(workdir, 'merge.bc')) or is_failed == "Merge BC Failed":
            return {
                'hexsha': hexsha,
                'workdir': workdir,
                'diff file': True,
                'before bc': True,
                'after bc': True,
                'version': '',
                'merge bc': False,
                'extract patch': False,
                '# peer functions': 0,
                'bug_report': '',
                'command': '',
                'is failed': 'Merge BC Failed',
                'reason': ' '.join(reason1 + reason2 + reason3)
            }

        check_cmd, reason4, total_time = self.find_similar_bugs(workdir)
        if len(reason4) != 0:
            return {
                'hexsha': hexsha,
                'workdir': workdir,
                'diff file': True,
                'before bc': True,
                'after bc': True,
                'version': '',
                'merge bc': True,
                'extract patch': False,
                '# peer functions': 0,
                'bug_report': os.path.join(workdir, 'bug.json'),
                'command': os.path.join(workdir, 'bug.json'),
                'is failed': 'Spec Extract Failed',
                'reason': ' '.join(reason1 + reason2 + reason3 + reason4)
            }

        return {
            'hexsha': hexsha,
            'workdir': workdir,
            'diff file': True,
            'before bc': True,
            'after bc': True,
            'version': output_df.loc[output_df['hexsha'] == item['hexsha'], 'version'].iloc[0],
            'merge bc': True,
            'extract patch': True,
            '# peer functions': 0,
            'bug_report': os.path.join(workdir, 'bug.json'),
            'command': check_cmd,
            'is failed': 'Succeed',
            'reason': total_time
        }

    def find_similar_bugs(self, workdir):
        reasons = []
        
        with open(os.path.join(workdir, 'check.sh'), 'r') as f:
            checker_cmd = f.read()
        st_time = time.time()
        timeout, succeed, stdout, stderr = run_cmd_timeout(PATCH_DIR, checker_cmd, timeout=600)
        total_time = time.time() - st_time

        # The file is automatically closed when you exit the with block.
        if timeout:
            print('Analyze timeout', item['hexsha'])
            reasons.append('Spec run timout ' + str(total_time))
            return checker_cmd, reasons, ''
        elif not succeed:
            print('Analyze failed', item['hexsha'])
            reasons.append('Spec gen crashed ' + stderr)
            return checker_cmd, reasons, ''
        print('Analyze succeed', item['hexsha'])
        return os.path.join(workdir, 'check.sh'), reasons, total_time


def process_patch(idx, parser, item, workdir, is_failed):
    try:
        global output_df
        # print('In', idx, item.hexsha)
        ret = parser.parse_commit(workdir, item, is_failed)
        ret['arch'] = item['arch']
        is_unique = True
        for data in data_list:
            if data['workdir'] == workdir:
                print('Error: duplicate workdir', workdir)
                is_unique = False
                break
        if is_unique:
            data_list.append(ret)
        # print('Out', idx, item.hexsha)
    except Exception as e:
        print('Exception in process_patch', workdir)
        print(e)
        import traceback
        print(traceback.format_exc())


def write_to_csv(stop_event):
    global output_df
    try:
        while True:
            content = list(data_list)
            for row in content:
                if row['workdir'] not in output_df['workdir'].values:
                    print('Appending to df before ', len(content), len(output_df), flush=True)
                    new_df = pd.DataFrame([row])
                    output_df = pd.concat([output_df, new_df], ignore_index=True)
                    print('Appending to df after ', len(content), len(output_df), flush=True)
                else:
                    mask = output_df["workdir"] == row['workdir']
                    # print('Updating to df before ', row['workdir'], output_df.loc[mask].values.tolist(), flush=True)
                    # print(output_df)
                    output_df.loc[mask, row.keys()] = row.values()
                    print('Updating to df after ', row['workdir'], output_df.loc[mask].values.tolist(), flush=True)

                    # print(output_df)
            output_df.to_csv(CMD_OUTPUT_PATCH, index=False)
            print('Flush to output dataframe', flush=True)

            with data_list._mutex:
                for row in content:
                    data_list.remove(row)

                if len(data_list) == 0 and stop_event.is_set():
                    break
            time.sleep(10)
        print('Exit from while', stop_event.is_set(), len(data_list), len(output_df))
    except Exception as e:
        print('Exception in write_to_csv', e, flush=True)


if __name__ == "__main__":
    df = pd.read_csv(FILTER_PATCH)
    df = df.fillna('')
    df = df[df['indirect call'] != '']
    df = df.drop_duplicates()
    # df.to_csv(FILTER_PATCH + ".uniq", index=False)
    print('Processing # Pathces ', len(df))

    parser = PatchParser()
    pbar = tqdm(total=len(df))
    pbar.set_description('Pacth Processing')
    update = lambda *args: pbar.update()

    stop_event = Event()
    write_thread = threading.Thread(target=write_to_csv, args=(stop_event,))
    write_thread.start()

    skip_idx = 0
    analyze_idx = 0
    all_workdir = set()
    with Pool(20) as p:
        for idx, item in df.iterrows():
            hexsha = item['hexsha']
            indirect_call = item['indirect call']
            workdir = os.path.join(PATCH_DIR,
                                hexsha + "_" + indirect_call.split(':')[-1] + "_" + str(idx))
            if workdir in all_workdir:
                print('error', workdir)
            else:
                all_workdir.add(workdir)

            is_failed = ""
            if workdir in output_df['workdir'].values:
                filtered_row = output_df.loc[output_df["workdir"] == workdir]
                is_failed = filtered_row["is failed"].values[0]
                if is_failed != "Succeed":
                    print('Do not have bitcode', item['hexsha'], skip_idx)
                    skip_idx += 1
                    # update()
                    continue
            p.apply_async(process_patch, args=(analyze_idx, parser, item, workdir, is_failed), callback=update)
            analyze_idx += 1

        p.close()
        p.join()

    print('Skipped ', skip_idx)
    print('Analyzed ', analyze_idx)

    stop_event.set()
    write_thread.join()
    print(len(output_df))
