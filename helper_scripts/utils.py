import os
import shutil
import subprocess
import multiprocessing
from config import *

link_cmds = multiprocessing.Manager().list()
gcc_o_files = multiprocessing.Manager().dict()


def run_cmd_timeout(dir: str, cmd: str, timeout):
    try:
        old_dir = os.getcwd()
        os.chdir(dir)
        output = subprocess.run(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True, shell=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        os.chdir(old_dir)
        return True, 124, "", "Timeout"
    os.chdir(old_dir)
    return False, output.returncode == 0, output.stdout, output.stderr


def run_cmd(dir: str, cmd: str):
    old_dir = os.getcwd()
    os.chdir(dir)
    output = subprocess.run(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True, shell=True)
    # if output.returncode != 0:
    #     print('Cmd: ', cmd)
    #     print('Error: ', output.stderr)
    os.chdir(old_dir)
    return output.returncode, output.stdout, output.stderr


def get_cmd(file_path: str) -> str:
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith('cmd_') and ':=' in line:
                subline = line.split(':=', 1)[1].strip()
                return subline


def count_files_with_suffix(directory, suffix):
    count = 0
    for root, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            if filename.endswith(suffix):
                count += 1
    return count


def replace_suffix(string, old_suffix, new_suffix):
    if string.endswith(old_suffix):
        return string[:-len(old_suffix)] + new_suffix
    else:
        return string

def handle_cc(linux_dir, cmd_o: str):
    if 'BUILD_STR(s)=$(pound)s' in cmd_o:
        return '', ''

    res = cmd_o[:cmd_o.find(" -I")]
    res += cmd_o[cmd_o.find(" -I"):cmd_o.find(" -c ")]
    res += " -w -g -fno-discard-value-names -emit-llvm -c -o "
    source = cmd_o[cmd_o.find(" -c "):].split()[3]
    target = cmd_o[cmd_o.find(" -c "):].split()[2]
    target = replace_suffix(target, ".o", ".bc")
    if source.endswith('.S'):
        compile_cmd = "echo \"\" > " + target
        status, _, error = run_cmd(linux_dir, compile_cmd)
        if status != 0 or not os.path.exists(target):
            print("Processing file:", compile_cmd)
            print('Error', error)
        return '', os.path.join(linux_dir, target)

    res += target + " " + source
    res = res.replace(" -ftrivial-auto-var-init=zero ", " ")
    res = res.replace("-O2", "-O0")

    flags = res.split()
    final_flags = []

    for flag in flags:
        if '-fsanitize' in flag or 'tsan' in flag or '-mllvm' in flag or '--param' in flag or ' asan-' in flag:
            continue
        final_flags.append(flag)

    res = ' '.join(final_flags)

    if ' ; ' in res:
        res = res.split(' ; ')[0]
        res = res.strip()

    return res, os.path.join(linux_dir, target)


def handle_objcopy(linux_dir, cmd_obj: str):
    cmd_obj.strip()

    res, target = '', ''
    res += f'{LINKER} -v -o '

    target = replace_suffix(cmd_obj.split()[-1], ".o", ".bc")
    res += target + " "

    objs = []
    for i, file in enumerate(cmd_obj.split()[:-1]):
        if not file.endswith('.o'):
            continue
        if file in gcc_o_files:
            continue
        objs.append(replace_suffix(file, ".o", ".bc"))

    if len(objs) == 0:
        return '', os.path.join(linux_dir, target)

    res += " ".join(objs)
    print('Handle_OBJCOPY', res)
    return res, os.path.join(linux_dir, target)


def handle_ld(linux_dir, cmd_ld: str):
    res, target = '', ''
    if '@' in cmd_ld:
        modfile = cmd_ld[cmd_ld.find('@') + 1:]
        modfile = os.path.join(linux_dir, modfile)
        with open(modfile, 'r') as f:
            o_files = f.readlines()
        res += f'{LINKER} -v -o '
        target = replace_suffix(cmd_ld[cmd_ld.find('-o') + 3:cmd_ld.find('@') - 1], ".o", ".bc")
        res += target + ' '

        objs = []
        for file in o_files:
            o_file = file.strip()
            if o_file not in gcc_o_files:
                objs.append(replace_suffix(o_file, ".o", ".bc"))

        if len(objs) != 0:
            res += " ".join(objs)
            res.strip()
            print('Handle_LD@', res)
            return res, os.path.join(linux_dir, target)
        else:
            return '', os.path.join(linux_dir, target)
    else:
        res += f'{LINKER} -v -o '
        bc_files = cmd_ld[cmd_ld.find('-o') + 3:].split()

        objs = []
        for i, file in enumerate(bc_files):
            if file in gcc_o_files:
                continue
            if i == 0:
                if file.endswith('.o'):
                    target = replace_suffix(file, ".o", ".bc")
                elif file.endswith('.a'):
                    target = replace_suffix(file, ".a", ".bc")
            if file.endswith('.o'):
                objs.append(replace_suffix(file, ".o", ".bc"))
            elif file.endswith('.a'):
                objs.append(replace_suffix(file, ".a", ".bc"))

        if len(objs) != 1:
            res += " ".join(objs)
            print('Handle_LD', res)
            return res, os.path.join(linux_dir, target)
        else:
            return '', os.path.join(linux_dir, target)


def handle_strip(linux_dir, cmd_strip: str):
    res, target = '', ''
    res += f'{LINKER} -v -o '
    cmd_strip = cmd_strip.split(';')[0]
    o_files = cmd_strip[cmd_strip.find('-o') + 3:].split()

    objs = []
    for i, file in enumerate(o_files):
        if file in gcc_o_files:
            continue
        objs.append(replace_suffix(file, ".o", ".bc"))
        if i == 0:
            target = replace_suffix(file, ".o", ".bc")
    if len(objs) != 1:
        res += " ".join(objs)
        print('Handle_STRIP', res)
        return res, os.path.join(linux_dir, target)
    else:
        return '', os.path.join(linux_dir, target)

def handle_ar(linux_dir, cmd_ar: str):
    res, target = '', ''
    cmd_ar.strip()
    if "cDPrST" in cmd_ar:
        target = cmd_ar[cmd_ar.find(" cDPrST") + 8:]
        if ' ' in target:
            target = target[:target.find(' ')]
        target = replace_suffix(target, '.a', '.bc')
        target = target.split()[0]
    if "; " in cmd_ar:
        cmd_ar = cmd_ar.split("; ")[-1]

    output = ''
    if " | xargs " in cmd_ar:
        cmd_ar = cmd_ar[:cmd_ar.find(" | xargs ")]

        if "echo " in cmd_ar or "printf" in cmd_ar:
            _, output, error = run_cmd(linux_dir, cmd_ar)
    else:
        objs = []
        for file in cmd_ar.split():
            if file.endswith('.o') or file.endswith('.a'):
                objs.append(file)
        output = " ".join(objs[1:])

    if output == '':
        return '', os.path.join(linux_dir, target)
    else:
        bc_files = []
        for file in output.split():
            file.strip()
            if file.endswith('.a'):
                bc_files.append(replace_suffix(file, ".a", ".bc"))
            if file.endswith('.o'):
                bc_files.append(replace_suffix(file, ".o", ".bc"))
        res += f"{LINKER} -v -o " + target + " " + " ".join(bc_files)
        print('Handle_AR', res)
        return res, os.path.join(linux_dir, target)


def process_file(linux_dir, file_path: str, run_ornot=True):
    if '.vmlinux.' in os.path.basename(file_path):
        return '', ''

    if file_path.endswith('.o.cmd'):
        compile_cmd = get_cmd(file_path)
        compiler = os.path.basename(compile_cmd.split()[0])

        if compiler.startswith('clang'):
            compile_cmd, target = handle_cc(linux_dir, compile_cmd)

            if compile_cmd == '' or target == '':
                return compile_cmd, target
            if not run_ornot or os.path.exists(target):
                return compile_cmd, target
            status, _, error = run_cmd(linux_dir, compile_cmd)
            if status != 0 or not os.path.exists(target):
                print("Processing file:", compile_cmd)
                print('Error', error)
                compile_cmd = get_cmd(file_path)
                handle_cc(linux_dir, compile_cmd)
            return compile_cmd, target
        elif compiler.endswith('ld'):
            compile_cmd, target = handle_ld(linux_dir, compile_cmd)
            link_cmds.append((compile_cmd, target))
            return compile_cmd, target
        elif compiler.endswith('objcopy'):
            compile_cmd, target = handle_objcopy(linux_dir, compile_cmd)
            link_cmds.append((compile_cmd, target))
            return compile_cmd, target
        elif compiler.endswith('strip'):
            compile_cmd, target = handle_strip(linux_dir, compile_cmd)
            link_cmds.append((compile_cmd, target))
            return compile_cmd, target
        elif compiler.endswith('gcc'):
            pass
        else:
            print("Compile command with other suffix:", file_path)
    elif file_path.endswith('.a.cmd'):
        compile_cmd = get_cmd(file_path)
        compile_cmd, target = handle_ar(linux_dir, compile_cmd)
        link_cmds.append((compile_cmd, target))
        return compile_cmd, target
    elif file_path.endswith('.S'):
        link_cmds.append(('', replace_suffix(file_path, '.S', '.bc')))
        return '', replace_suffix(file_path, '.S', '.bc')
    return '', ''


def skip_gcc(file_path: str):
    if (file_path.endswith('.o.cmd') and
            not '.vmlinux.' in os.path.basename(file_path)):
        cmd_gcc = get_cmd(file_path)
        if cmd_gcc.startswith('gcc'):
            target = cmd_gcc[cmd_gcc.find(" -c "):].split()[2]
            # print('Skip object files compiled with gcc', target)
            gcc_o_files[target] = 1
