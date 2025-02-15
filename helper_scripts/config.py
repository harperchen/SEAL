import os

# clone kernel
LINUX_COMMIT = (
    "v6.2, v6.0, v5.19, v5.18, v5.15, v5.14, v5.12, v5.11, v5.10, v5.8, v5.5, v5.3"
)
# LINUX_COMMIT = 'v6.2'
LINUX_REPO = "https://github.com/torvalds/linux.git"
LINUX_SRC_TEMPLATE = "/linux"

# compile kernel
ARCHS = "x86_64, arm64"
CROSS_COMPILE = ("")

# toolkit
COMPILER = "/llvm/bin/clang"
LINKER = "/llvm/bin/llvm-link"
MERGER = "/llvm/bin/llvm-link-patch"
CBCHECK = "/clearblue/bin/cb-check"


# intermediate files
LINUX_SRC_DIR = "/seal_workdir/data/Linux_Data/{}/src"
COMPILED_BC_DIR = "/seal_workdir/data/Linux_Data/{}/bcs_{}"
BCs_DIR = "/seal_workdir/data/Linux_Data/{}/bcs_{}"
FUNC_NAME = "/seal_workdir/data/Linux_Data/{}/funcs_{}.name"
DOT_DIR = "/seal_workdir/data/Linux_Data/{}/dots_{}"
CALL_DIR = "/seal_workdir/data/Linux_Data/{}/calls_{}"
PEER_DIR = "/seal_workdir/data/Linux_Data/{}/peers_{}"

# intermediate csv file
INPUT_PATCH = "/seal_workdir/data/1_input_patches.csv"
FILTER_PATCH = "/seal_workdir/data/2_filter_calls.csv"
CMD_OUTPUT_PATCH = "/seal_workdir/data/3_cmd_outputs.csv"
DATA_PATCH = "/seal_workdir/data/4_data_info.csv"
SPEC_PATCH = "/seal_workdir/data/5_spec_info.csv"

# output files
PATCH_DIR = "/seal_workdir/data/Patch_BC"
BUG_DIR = "/seal_workdir/data/Bug_Reports/{}"
