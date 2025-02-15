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

pandarallel.initialize(progress_bar=True,
                       nb_workers=20,
                       use_memory_fs=False,
                       verbose=0)

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
        self.arch2func2peers = {}

    def parse_commit(self, workdir, item, is_failed):
        hexsha = item['hexsha']
        indirect_call = item['indirect call']
        if not os.path.exists(workdir):
            os.makedirs(workdir)

        reason1, reason2, reason3, reason4 = [], [], [], []
        if not os.path.exists(os.path.join(workdir, 'diff.txt')):
            self.parse_diff(workdir, hexsha)

        related_files = item['related files'].split(',')
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
                or is_failed == "Before BC Failed" or is_failed == "After BC Failed"
                or item['version'] == ''):
            
            ret, reason1, found_version = self.generate_bc(workdir, hexsha, related_files, item['arch'])
            if not ret:
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
            ret, reason3 = self.merge_bc(workdir)
            if not ret:
                return {
                    'hexsha': hexsha,
                    'workdir': workdir,
                    'diff file': True,
                    'before bc': True,
                    'after bc': True,
                    'version': found_version,
                    'merge bc': False,
                    'extract patch': False,
                    '# peer functions': 0,
                    'bug_report': '',
                    'command': '',
                    'is failed': 'Merge BC Failed',
                    'reason': ' '.join(reason1 + reason2 + reason3)
                }

        check_cmd, reason4, tot_time = self.find_similar_bugs(workdir, indirect_call)

        if len(reason4) != 0:
            return {
                'hexsha': hexsha,
                'workdir': workdir,
                'diff file': True,
                'before bc': True,
                'after bc': True,
                'version': found_version,
                'merge bc': True,
                'extract patch': False,
                '# peer functions': peer_num,
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
            'version': found_version,
            'merge bc': True,
            'extract patch': True,
            '# peer functions': peer_num,
            'bug_report': os.path.join(workdir, 'bug.json'),
            'command': check_cmd,
            'is failed': 'Succeed',
            'reason': tot_time
        }

    def parse_diff(self, workdir, hexsha):
        line_changes = []
        commit = self.repo.get_commit(hexsha)
        for f in commit.modified_files:
            if f.change_type != ModificationType.MODIFY:
                continue
            for added in f.diff_parsed['added']:
                line_changes.append('+' + f.new_path + ':' + str(added[0]))
            for deleted in f.diff_parsed['deleted']:
                line_changes.append('-' + f.old_path + ':' + str(deleted[0]))

        with open(os.path.join(workdir, 'diff.txt'), 'w') as f:
            for line in line_changes:
                f.write(line + '\n')
        return os.path.join(workdir, 'diff.txt')


    def find_required_h(self, filepath, curworkdir, type):
        required_h = set()
        with open(filepath, 'r') as f:
            file_content = f.read()
            dir_name = os.path.relpath(os.path.dirname(filepath), 
                                       os.path.join(curworkdir, type))
            
            pattern = r'#include\s+"([^"]+)"'
            matches = re.findall(pattern, file_content)
            
            for h_file in matches:
                to_be_find = h_file.split('/')[-1]
                if not to_be_find.endswith('.h'):
                    print(h_file)
                find_cmd = f"find . -name \"{to_be_find}\""
                status, output, _ = run_cmd(LINUX_SRC_TEMPLATE, find_cmd)
                if status != 0:
                    continue
                
                new_h_file = os.path.join(os.path.dirname(filepath), h_file)
                required_h.add(new_h_file)
                # for item in output.split('\n'):
                #     if not item.endswith(h_file):
                #         continue
                #     if item.startswith('./drivers') or item.startswith('./sound'):
                #         cur_h_file = item[2:].strip()
                #         if os.path.commonprefix([cur_h_file, dir_name]).count('/') < 2:
                #             continue
                #     else:
                #         continue
                #     new_h_file = os.path.join(curworkdir, type, cur_h_file)
                #     required_h.add(new_h_file)
        # print(required_h)
        return required_h
    
    # obtain the following two header for a specific commit in case outlined versions are failed 
    # arch and include 
    def obtain_commit_h_files(self, commit, curworkdir):
        reasons = []
        abs_path = os.path.abspath(curworkdir)
        linux_repo_path = os.path.join(abs_path, "linux")

        if os.path.exists(linux_repo_path):
            required_dirs = {'include', 'arch'}
            with os.scandir(linux_repo_path) as entries:
                dirs = {entry.name for entry in entries if entry.is_dir()}
                # Check if all required directories are present
                if required_dirs.issubset(dirs):
                    return reasons
            shutil.rmtree(linux_repo_path)  
        
        os.makedirs(linux_repo_path, exist_ok=True)
        repo = Repo.init(linux_repo_path)
        repo.create_remote('origin', 'https://github.com/torvalds/linux.git')
        repo.git.config('core.sparseCheckout', 'true')

        with open(os.path.join(linux_repo_path, '.git', 'info', 'sparse-checkout'), 'w') as sc_file:
            sc_file.write('include/\n')
            sc_file.write('arch/\n')
            
        status, stdout, error = run_cmd(LINUX_SRC_TEMPLATE, f"git log --format=format:%H | grep -E '^{commit}'")
        if status != 0:
            reasons.append(f'Error when obtain complex sha hex {commit}: {error}')
            return reasons
            
        commits = stdout.splitlines()
        
        status, stdout, error = run_cmd(linux_repo_path, f"git fetch --depth 1 origin {commits[0]}")
        if status != 0:
            reasons.append(f'Error when fetch {commit}: {error}')
            return reasons
        
        status, stdout, error = run_cmd(linux_repo_path, f"git checkout {commits[0]}")
        if status != 0:
            reasons.append(f'Error when obtain checout {commit}: {error}')
            return reasons
        
        required_dirs = {'include', 'arch'}
        with os.scandir(linux_repo_path) as entries:
            dirs = {entry.name for entry in entries if entry.is_dir()}
            # Check if all required directories are present
            if not required_dirs.issubset(dirs):
                reasons.append(f'Error no include/arch after checkout {commit}')
                return reasons
        
        try:
            for entry in os.listdir(linux_repo_path):
                entry_path = os.path.join(linux_repo_path, entry)
                if os.path.isdir(entry_path) and entry not in ["include", "arch", ".git"]:
                    shutil.rmtree(entry_path)
        except Exception as e:
            reasons.append(f"Error when removing redundant folder {str(e)}")
        
        return reasons
    
    def obtain_h_files(self, curworkdir, hexsha, new_c_files, type):
        reasons = []
        to_be_processed = []
        required_h_files = set()
        to_be_processed.extend(new_c_files)
        
        while len(to_be_processed) != 0:
            curfile = to_be_processed.pop(0)
            required_h_files.add(curfile)
            if not os.path.exists(curfile):
                try:
                    print("Downloading " + curfile)
                    url_h_file = os.path.relpath(curfile, os.path.join(curworkdir, type))
                    url = "https://raw.githubusercontent.com/torvalds/linux/" + hexsha + "/" + url_h_file
                    response = requests.get(url, timeout=5)
                    response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes

                    if response.status_code == 200:
                        html_content = response.text
                        if not os.path.exists(os.path.dirname(curfile)):
                            os.makedirs(os.path.dirname(curfile))
                        with open(curfile, 'w', encoding='utf-8') as file:
                            file.write(html_content)
                except requests.exceptions.RequestException as e:
                    reasons.append("Failed to find h_file " + h_file)
                    
            if os.path.exists(curfile):
                for h_file in self.find_required_h(curfile, curworkdir, type):
                    if h_file in required_h_files or h_file in to_be_processed:
                        continue
                    to_be_processed.append(h_file)
        return True, required_h_files, reasons

    def obtain_c_files(self, curworkdir, hexsha, filepath, type):
        dirname = os.path.dirname(filepath)
        if not os.path.exists(os.path.join(curworkdir, type, dirname)):
            os.makedirs(os.path.join(curworkdir, type, dirname))
        new_c_file = os.path.join(curworkdir, type, filepath)
        if os.path.exists(new_c_file):
            return new_c_file
        try:
            url = "https://raw.githubusercontent.com/torvalds/linux/" + hexsha + "/" + filepath
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
            if response.status_code == 200:
                html_content = response.text
                with open(new_c_file, 'w', encoding='utf-8') as file:
                    file.write(html_content)
                return new_c_file
            else:
                return ''
        except requests.exceptions.RequestException as e:
            return ''
        
    def obtain_ch(self, workdir, hexsha, related_files, type):
        reasons = []
        new_c_files = set()
        for driver_file in related_files:
            driver_file = os.path.normpath(driver_file)
            new_file = self.obtain_c_files(workdir, hexsha, driver_file, type)
            if new_file == '':
                reasons.append(f'Fail to retrieve {type} C source file ' + driver_file)
                continue
            new_c_files.add(new_file)

        status, _, reasons_h = self.obtain_h_files(workdir, hexsha, new_c_files, type)
        if not status:
            reasons.extend(reasons_h)
        return reasons
    
    def replace_cmd_header(self, compile_cmd, new_file, workdir, curtype, commit_header):
            commit_header_dirs = []
            src_header = []
            # Combined pattern to match both '-I<dir>' and '-I <dir>'
            include_dirs = re.findall(r'-I\s?(\S+)', compile_cmd)
            for dir_name in include_dirs:
                if 'src/drivers' in dir_name or 'src/sound' in dir_name:
                    src_header.append(os.path.join(os.path.abspath(workdir), curtype, dir_name[dir_name.find('src') + 4:]))
                elif commit_header and ('src/arch' in dir_name or 'src/include' in dir_name):
                    commit_header_dirs.append(os.path.join(os.path.abspath(workdir), 'linux', dir_name[dir_name.find('src') + 4:]))
                else: 
                    src_header.append(dir_name)
            final_header = commit_header_dirs + src_header
            final_header.append(os.path.dirname(new_file))
            extra_header = "-I" + " -I".join(final_header)
            header_idx = compile_cmd.find('-I')
            compile_cmd = re.sub(r'-I\s?\S+', '', compile_cmd)
            compile_cmd = compile_cmd[:header_idx] + extra_header + " " + compile_cmd[header_idx:]

            new_headers = []
            include_hs = re.findall(r'-include\s(\S+)', compile_cmd)
            for header in include_hs:
                if commit_header and 'compiler_types.h' in header:
                    continue
                else: 
                    new_headers.append(header)
            extra_header = "-include " + " -include ".join(new_headers)
            header_idx = compile_cmd.find('-include ')
            compile_cmd = re.sub(r'-include\s\S+', '', compile_cmd)
            compile_cmd = compile_cmd[:header_idx] + extra_header + " " + compile_cmd[header_idx:]
            return compile_cmd
        
    def compile_and_link(self, hexsha, cur_commit, arch, workdir, related_files, curtype):
        reasons = []
        link_bcs = []
        
        found_commit = ''
        linux_dir = COMPILED_BC_DIR.format(cur_commit, arch)
        for driver_file in related_files:
            driver_file = os.path.normpath(driver_file)
            new_file = os.path.join(workdir, curtype, driver_file)
            if not os.path.exists(new_file):
                reasons.append(f'Fail to retrieve {curtype} C source file ' + driver_file)
                continue
            
            if not os.path.exists(new_file.replace('.c', '.bc')):
                # obtain compile command
                o_cmd_file = "." + os.path.basename(driver_file).replace('.c', '.o.cmd')
                o_cmd_file = os.path.join(linux_dir, os.path.dirname(driver_file), o_cmd_file)
                if not os.path.exists(o_cmd_file):
                    reasons.append(f'No file found f{curtype} compiling ' + o_cmd_file)
                    return False, reasons, found_commit

                compile_cmd, target = process_file(linux_dir, o_cmd_file, False)
                if compile_cmd == '' or target == '' or compile_cmd is None:
                    reasons.append(f'No command found for compile {curtype} file ' + driver_file)
                    return False, reasons, found_commit

                # replace target and compiled code
                new_file = os.path.abspath(new_file)
                compile_cmd = compile_cmd.split()
                compile_cmd[-1] = new_file
                compile_cmd = ' '.join(compile_cmd)
                original_cmd = compile_cmd
                
                compile_cmd = self.replace_cmd_header(original_cmd, new_file, workdir, curtype, False)   
                compile_cmd = compile_cmd.replace("-o " + target.replace(linux_dir + '/', ''),
                                                  "-o " + new_file.replace('.c', '.bc'))
                status, _, error = run_cmd(linux_dir, compile_cmd)
                if status != 0:
                    reasons.extend(self.obtain_commit_h_files(hexsha, workdir))
                    compile_cmd = self.replace_cmd_header(original_cmd, new_file, workdir, curtype, True)   
                    compile_cmd = compile_cmd.replace("-o " + target.replace(linux_dir + '/', ''),
                                                      "-o " + new_file.replace('.c', '.bc'))
                    status, _, error = run_cmd(linux_dir, compile_cmd)
                    if status != 0:
                        with open(os.path.join(workdir, f'{curtype}.err'), 'w') as err_f:
                            err_f.write('Cmd: ' + compile_cmd + '\n')
                            err_f.write('Err: ' + error + '\n')
                        reasons.append(f'Error when compiling {curtype} bc with own commit header ' + os.path.join(workdir, f'{curtype}.err'))
                        return False, reasons, found_commit
                    else:
                        found_commit = hexsha
                else:
                    found_commit = cur_commit

            link_bcs.append(new_file.replace('.c', '.bc'))

        if len(link_bcs) == 0:
            return False, reasons
        link_target = os.path.abspath(os.path.join(workdir, f'{curtype}.bc'))
        if not os.path.exists(link_target):
            link_cmd = f"{LINKER} -v -o " + link_target + " " + " ".join(link_bcs)
            status, _, error = run_cmd(linux_dir, link_cmd)
            if status != 0:
                reasons.append(f'Error when link {curtype} ' + link_cmd)
                return False, reasons, found_commit
            
        return True, reasons, found_commit

    def generate_bc(self, workdir, hexsha, related_files, arch):
        reasons = []
        found_version = ''
        
        commit = self.repo.get_commit(hexsha)
        parent_hexsha = commit.parents[0]

        reasons.extend(self.obtain_ch(workdir, parent_hexsha, related_files, "before"))
        reasons.extend(self.obtain_ch(workdir, hexsha, related_files, "after"))
        
        path_pattern = os.path.join(workdir, '**', '*.bc')
        bc_files = glob.glob(path_pattern, recursive=True)
        for file_path in bc_files:
            try:
                os.remove(file_path)
            except Exception as e:
                reasons.append(f"Failed to delete {file_path}: {e}")
                break
        for cur_commit in LINUX_COMMIT.split(", "):
            reasons = []
            ret, reason1, found_version = self.compile_and_link(hexsha, cur_commit, arch, workdir, related_files, "before")
            reasons.extend(reason1)
            if not ret:
                continue

            ret, reason2, found_version = self.compile_and_link(hexsha, cur_commit, arch, workdir, related_files, "after")
            reasons.extend(reason2)
            if not ret:
                continue
            break

        if found_version != '':
            return True, reasons, found_version
        else:
            return False, reasons, found_version

    def merge_bc(self, dir_name):
        reasons = []
        if not os.path.exists(os.path.join(dir_name, 'after.bc')) or \
                not os.path.exists(os.path.join(dir_name, 'before.bc')):
            return False, reasons
        if not os.path.exists(os.path.join(dir_name, 'merge.bc')):
            cmd = MERGER + ' -after-bc=after.bc -before-bc=before.bc -o merge.bc'
            status, _, error = run_cmd(dir_name, cmd)
            if status != 0:
                reasons.append('Error when merging ' + cmd)
                return False, reasons
        return True, reasons

    def find_peer(self, workdir, to_be_query, arch):
        peers = [to_be_query]

        if to_be_query in self.arch2func2peers[arch]:
            peers += self.arch2func2peers[arch][to_be_query]

        with open(os.path.join(workdir, 'peer.txt'), 'w') as f:
            f.write(' '.join(peers) + '\n')
        return len(peers), True

    def detect_bugs(self, workdir, indirect_call):
        reasons = []
        diff_file = os.path.join(workdir, 'diff.txt')
        spec_file = os.path.join(workdir, 'specs.csv')
        input_bc = os.path.join(workdir, 'merge.bc')
        log_file = os.path.join(workdir, 'patch.log')
        checker_cmd = CBCHECK + (" -load=/seal-workdir/build/libSEGPatchPlugin.so "
                                 "-enable-patch-analysis "
                                 "-patch-plugin "
                                 "-omit-no-dbginfo "
                                 "-falcon-use-valuetostring "
                                 "-seg-enable-valuetostring "
                                 "-nworkders=1 "
                                 "-execution-mode=digging "
                                 "-set-inc-tactic=smt_tactic "
                                 "-infer-patch-spec "
                                 "-patch={} "
                                 "-output={}"
                                 "{} > {} 2>&1").format(diff_file, spec_file,
                                                        input_bc, log_file)
        with open(os.path.join(workdir, 'check.sh'), 'w') as f:
            f.write(checker_cmd)

        return os.path.join(workdir, 'check.sh'), reasons, ''


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
    print('Processing # Pathces ', len(df))

    parser = PatchParser()
    pbar = tqdm(total=len(df))
    pbar.set_description('Pacth Processing')
    update = lambda *args: pbar.update()

    stop_event = Event()
    write_thread = threading.Thread(target=write_to_csv, args=(stop_event,))
    write_thread.start()

    unfinished_idx = 0
    finished_idx = 0
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
                if is_failed == "Succeed":
                    print('Already processed', item['hexsha'], finished_idx)
                    finished_idx += 1
                    update()
                    continue
            p.apply_async(process_patch, args=(unfinished_idx, parser, item, workdir, is_failed), callback=update)
            unfinished_idx += 1

        p.close()
        p.join()

    print('Unfinished ', unfinished_idx)
    print('Finished ', finished_idx)

    stop_event.set()
    write_thread.join()
    print(len(output_df))

