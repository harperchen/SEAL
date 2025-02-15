import os.path
import shutil

from git import Repo
from utils import *
from config import *

def ignore_directory(directory_to_ignore):
    def _ignore_directory(path, directory_names):
        return set([directory for directory in directory_names if directory == directory_to_ignore])
    return _ignore_directory

def download_linux(linux_commit):
    target_dir = os.path.abspath(LINUX_SRC_DIR.format(linux_commit))
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
        if LINUX_SRC_TEMPLATE != "":
            repo = Repo(LINUX_SRC_TEMPLATE)
            commit = repo.commit(linux_commit)
            # Checkout the commit
            repo.head.reference = commit
            if repo.is_dirty(untracked_files=True):
                repo.git.clean('-fd')
            repo.head.reset(index=True, working_tree=True)
            shutil.copytree(LINUX_SRC_TEMPLATE, target_dir, ignore=ignore_directory(".git"))
        else:
            Repo.clone_from(LINUX_REPO, target_dir)
    
    print(f"Step 1: Repository cloned to {target_dir} and checked out to commit {linux_commit}")


def compile_linux(linux_commit, arch):
    linux_src_dir = os.path.abspath(LINUX_SRC_DIR.format(linux_commit))
    target_dir = os.path.abspath(COMPILED_BC_DIR.format(linux_commit, arch))

    if not os.path.exists(linux_src_dir):
        return

    if os.path.exists(target_dir):
        if os.path.exists(os.path.join(target_dir, 'vmlinux.o')):
            print('Step 2: Successfully Compiled', target_dir)
            return
        else:
            shutil.rmtree(target_dir)

    os.makedirs(target_dir)

    index = ARCHS.split(", ").index(arch)

    cmd_prefix = f'make CC={COMPILER} ARCH={arch} CROSS_COMPILE={CROSS_COMPILE.split(", ")[index]} ' + '{}'

    status, output, error = run_cmd(linux_src_dir, cmd_prefix.format("O={} clean").format(target_dir))
    if status != 0:
        print('Error ', error)
        return

    status, output, error = run_cmd(linux_src_dir, cmd_prefix.format("mrproper").format(target_dir))
    if status != 0:
        print('Error ', error)
        return

    status, output, error = run_cmd(linux_src_dir, cmd_prefix.format("O={} defconfig").format(target_dir))
    if status != 0:
        print('Error ', error)
        return

    status, output, error = run_cmd(linux_src_dir, cmd_prefix.format("O={} allyesconfig").format(target_dir))
    if status != 0:
        print('Error ', error)
        return

    disabled_config = [
        "CONFIG_KASAN", "CONFIG_KCSAN", "CONFIG_UBSAN", "CONFIG_HAVE_DEBUG_KMEMLEAK", "CONFIG_KCOV"
    ]
    with open(os.path.join(target_dir, '.config'), "a") as f:
        f.writelines([f"{c}=n\n" for c in disabled_config])
        f.write("CONFIG_FRAME_WARN=4096")
        f.write("CONFIG_DEBUG_INFO_NONE=n")
        f.write("CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y")

    status, output, error = run_cmd(target_dir, cmd_prefix.format("O={} olddefconfig").format(target_dir))
    if status != 0:
        print('Error ', error)
        return

    status, output, error = run_cmd(target_dir, cmd_prefix.format("O={} -j 32").format(target_dir))
    if status == 0 or os.path.exists(os.path.join(target_dir, 'vmlinux.o')):
        print('Step 2: Successfully Compiled', target_dir)
        return
    else:
        print('Error ', error)


def generate_bc(linux_commit, arch):
    target_dir = os.path.abspath(COMPILED_BC_DIR.format(linux_commit, arch))

    if not os.path.exists(target_dir):
        return
    pool = multiprocessing.Pool(processes=24)

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            pool.apply_async(skip_gcc, args=(file_path,))

    pool.close()
    pool.join()

    pool = multiprocessing.Pool(processes=24)
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            relevant = os.path.relpath(os.path.join(root, file), target_dir)
            # if relevant.startswith('drivers/') or relevant.startswith('sound/'):
            file_path = os.path.join(root, file)
            pool.apply_async(process_file, args=(target_dir, file_path))

    pool.close()
    pool.join()


def link_bc(linux_commit, arch):
    driver_bcs = set()
    bc_dir = os.path.abspath(COMPILED_BC_DIR.format(linux_commit, arch))

    bc_available = {}
    invalid_link_cmd = []

    while True:
        ready_cmds = set()

        for link_cmd, target in link_cmds:
            if (link_cmd, target) in invalid_link_cmd:
                continue

            bc_files = []
            for file in link_cmd.split():
                if not file.endswith(".bc"):
                    continue
                bc_files.append(file)

            if len(bc_files) != 0:
                if bc_files[0] == 'drivers/built-in.bc':
                    driver_bcs.update(bc_files[1:])
                driver_bcs.add('sound/built-in.bc')

            if os.path.exists(target):
                if link_cmd == '' and os.path.getsize(target) != 1:
                    os.remove(target)
                else:
                    bc_available[target] = True
                    continue

            is_ready = True
            if len(bc_files) != 0:
                for file in bc_files[1:]:
                    if not os.path.exists(os.path.join(bc_dir, file)):
                        is_ready = False
                        break
                    else:
                        bc_available[file] = True

            if is_ready or link_cmd == "":
                ready_cmds.add((link_cmd, target))

        if len(ready_cmds) == 0:
            break

        pool = multiprocessing.Pool(processes=24)

        for link_cmd, target in ready_cmds:
            bc_files = []
            for file in link_cmd.split():
                if not file.endswith(".bc"):
                    continue
                bc_files.append(file)

            if link_cmd == '' or len(bc_files) == 1:
                link_cmd = "echo \"\" > " + target
                print(link_cmd)

            print("Processing file:", link_cmd)
            pool.apply_async(run_cmd, args=(bc_dir, link_cmd))

        pool.close()
        pool.join()

        for link_cmd, target in ready_cmds:
            if os.path.exists(target):
                bc_available[target] = True
            else:
                invalid_link_cmd.append((link_cmd, target))

    for link_cmd, target in link_cmds:
        if not os.path.exists(target):
            invalid_link_cmd.append((link_cmd, target))

    for link_cmd, target in invalid_link_cmd:
        print('Invalid link cmd', link_cmd)
    link_cmds[:] = []
    return driver_bcs


def rename_driverbcs(driver_bcs, linux_commit, arch):
    renamed_bcs = set()
    bc_dir = os.path.abspath(COMPILED_BC_DIR.format(linux_commit, arch))
    if not os.path.exists(bc_dir):
        return

    target_dir = os.path.abspath(BCs_DIR.format(linux_commit, arch))

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    for bc in driver_bcs:
        driver_sub = os.path.dirname(bc).replace('drivers/', '')
        driver_sub = driver_sub.replace('/', '_') + '.bc'
        if not os.path.exists(os.path.join(target_dir, driver_sub)):
            shutil.copyfile(os.path.join(bc_dir, bc),
                            os.path.join(target_dir, driver_sub))
        renamed_bcs.add(os.path.join(target_dir, driver_sub))


if __name__ == "__main__":
    for commit in LINUX_COMMIT.split(", "):
        print('Download Linux...')
        download_linux(linux_commit=commit)

        for arch in ARCHS.split(", "):
            print('Processing ', arch)
            print('Compile Default Linux...')
            compile_linux(linux_commit=commit, arch=arch)
            print('Start Generating Bitcode...')
            generate_bc(linux_commit=commit, arch=arch)
            print('Start linking...')
            driver_bcs = link_bc(linux_commit=commit, arch=arch)
            print("All files processed. ")
            exit(0)

            rename_driverbcs(driver_bcs, linux_commit=commit, arch=arch)

            bc_dir = os.path.abspath(COMPILED_BC_DIR.format(commit, arch))
            print("# .o files", count_files_with_suffix(bc_dir, ".o"))
            print("# .a files", count_files_with_suffix(bc_dir, ".a"))
            print("# .S files", count_files_with_suffix(bc_dir, ".S"))
            print("# .bc files (correct)",
                  count_files_with_suffix(bc_dir, ".o") +
                  count_files_with_suffix(bc_dir, ".a") +
                  count_files_with_suffix(bc_dir, ".S"))

            print("# .bc files (generated)", count_files_with_suffix(bc_dir, ".bc"))
