import os.path

from utils import *
from config import *

def perform_bug_detection(arch, mode):
    cmd_prefix = (CBCHECK + 
                  '-load=/seal-workdir/build/libSEGPatchPlugin.so '
                  '-enable-patch-analysis '
                  '-patch-plugin '
                  '-omit-no-dbginfo '
                  '-falcon-use-valuetostring '
                  '-seg-enable-valuetostring '
                  '-nworkers=20 '
                  '-execution-mode=digging '
                  f'--fast-mode -falcon-enable-file={os.path.abspath(SPEC_PATCH)} ' if mode == "fast" else ''
                  '-detect-patch-bug '
                  f'-specs={os.path.abspath(SPEC_PATCH)} '
                  '-report={} '
                  '{} > {} 2>&1')

    src_dir = BCs_DIR.format(LINUX_COMMIT, arch)
    target_dir = BUG_DIR.format(mode)

    for root, dirs, files in os.walk(src_dir):
        files = sorted(files)
        for file in files:
            file_path = os.path.join(root, file)
            if not file_path.endswith('.bc'):
                continue
            driver_sub = os.path.basename(file_path)
            print('Perform bug detection on ', driver_sub)
            log_file = os.path.join(target_dir, driver_sub.replace('.bc', 'log'))
            json_file = os.path.join(target_dir, driver_sub.replace('.bc', '.json'))

            cmd_detector = cmd_prefix.format(json_file, file_path, log_file)
            status, output, error = run_cmd(os.getcwd(), cmd_detector)
            if status == 0 and os.path.exists(log_file):
                print('Successfully detect bug on ', file_path)
            else:
                print('Error when generating call graph for ', driver_sub)

if __name__ == '__main__':
    for arch in ARCHS.split(", "):
        perform_bug_detection(arch, mode="fast")
        perform_bug_detection(arch, mode="slow")