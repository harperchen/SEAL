from utils import *
from config import *


def run_cmd_indirect(file_path, target_dir):
    cmd_prefix = (f'{CBCHECK} '
                  '-load=/seal-workdir/build/libSEGPatchPlugin.so '
                  '-enable-patch-analysis '
                  '-patch-plugin '
                  '-omit-no-dbginfo '
                  '-execution-mode=digging '
                  '-nworkers=2 '
                  '-segbuilder-aa=simple '
                  '-dump-indirect-call {} > {} 2>&1')

    driver_sub = os.path.basename(file_path)
    print('Generating indirect call list for ', driver_sub)
    call_file = os.path.join(target_dir, driver_sub.replace('.bc', '.dot'))

    status, output, error = run_cmd(os.getcwd(), f"grep \"Starting Checking\" {call_file}")
    if os.path.exists(call_file) and output != "":
        return

    cmd_indirect = cmd_prefix.format(file_path, call_file)
    status, output, error = run_cmd(os.getcwd(), cmd_indirect)
    if status == 0 and os.path.exists(call_file):
        with open(call_file, "r") as f:
            lines = f.readlines()
            content = "\n".join(lines)

            content = content[:content.find('\nSta')]
            content = content[content.rfind('...Done!\n') + len('...Done!\n'):]

            final_content = 'digraph G {\n'

            for line in content.split('\n'):
                if line == '':
                    continue
                if 'PSA Checking' in line:
                    continue
                if line.endswith(";"):
                    final_content += line + "\n"
                else:
                    final_content += line.strip()
            final_content += "}"
            filename, suffix = os.path.splitext(call_file)
            with open(os.path.join(filename + '_final.dot'), 'w') as f2:
                f2.write(final_content.replace('Dot Call Graph: ', ''))
    else:
        print('Error when generating call graph for ', driver_sub)


def generate_indirect_call(linux_commit, arch):
    src_dir = BCs_DIR.format(linux_commit, arch)
    target_dir = CALL_DIR.format(linux_commit, arch)

    if not os.path.exists(target_dir):
        os.makedirs(target_dir)

    pool = multiprocessing.Pool(processes=24)

    for root, dirs, files in os.walk(src_dir):
        files = sorted(files)
        for file in files:
            file_path = os.path.join(root, file)
            if not file_path.endswith('_36.bc'):
                continue

            pool.apply_async(run_cmd_indirect, args=(file_path, target_dir))

    pool.close()
    pool.join()


if __name__ == '__main__':
    LINUX_COMMIT = "v6.2"
    for commit in LINUX_COMMIT.split(", "):
        for arch in ARCHS.split(", "):
            generate_indirect_call(commit, arch)
