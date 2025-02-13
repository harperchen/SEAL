import os

# clone kernel
LINUX_COMMIT = (
    "v6.2, v6.0, v5.19, v5.18, v5.15, v5.14, v5.12, v5.11, v5.10, v5.8, v5.5, v5.3"
)
# LINUX_COMMIT = 'v6.2'
LINUX_REPO = "https://github.com/torvalds/linux.git"
LINUX_SRC_TEMPLATE = "/home/seal/linux_upstream"

LINUX_SRC_DIR = "../Linux_Src/{}/src"
COMPILED_BC_DIR = "../Linux_Src/{}/bcs_{}"

# compile kernel
# ARCHS = "x86_64, arm64"
ARCHS = "x86_64"
CROSS_COMPILE = (
    ", /home/seal/DriverIceBreaker/gcc-linaro-13.0.0-2022.08-x86_64_aarch64-linux-gnu/"
    "bin/aarch64-linux-gnu-"
)

# toolkit
COMPILER = "/home/seal/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04/bin/clang"
LINKER = "/home/seal/clang+llvm-12.0.0-x86_64-linux-gnu-ubuntu-20.04/bin/llvm-link"
TRANSLATOR = "/home/seal/DriverIceBreaker/Translator/Translator"
KANALYZER = "/home/seal/DriverIceBreaker/mlta/src/build/lib/kanalyzer"
MERGER = "/home/seal/DriverIceBreaker/mlta/merge/build/lib/kanalyzer"
SEALBIN = "/home/seal/DriverIceBreaker/USENIX_DATA/IceBreaker/tools/patch-parser"
SEALBIN = "/home/seal/seal/build/seal-bin"


# intermediate files
BCs_DIR_12 = "../Drivers_Bc/{}/bcs_{}"
BCs_DIR_3 = "../Drivers_Bc/{}/bcs_{}_36"
FUNC_NAME = "../Drivers_Bc/{}/funcs_{}.name"
DOT_DIR = "../Drivers_Bc/{}/dots_{}"
CALL_DIR = "../Drivers_Bc/{}/calls_{}"
PEER_DIR = "../Drivers_Bc/{}/peers_{}"

# intermediate csv file
INPUT_PATCH = "../1_input_patches.csv"
FILTER_PATCH = "../2_filter_calls.csv"
CMD_OUTPUT_PATCH = "../3_cmd_outputs.csv"
# DATA_PATCH = "../4_data_info.csv"
# SPEC_PATCH = "../5_spec_info.csv"
DATA_PATCH = "../4_data_info_shurong.csv"
SPEC_PATCH = "../5_spec_info_shurong.csv"

# output files
PATCH_DIR = "../Patches_Bc"
BUG_DIR = "../Bug_Reports/{}"
