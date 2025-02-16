# SEAL

## Description
This repository houses SEAL, a framework designed for the paper "Seal: Towards Diverse Specification Inference for
Linux Interfaces from Security Patches" (EuroSys 2025). 
SEAL leverages security patches as anti-examples to achieve progressive and automatic inference of diversified interface specifications. 
The specifications, formulated based on value-flow properties, could adeptly characterize interactive data behaviors for individual interfaces and also capture the synergistic relationships among multiple interfaces.
Technically, SEAL assesses the impact of code changes from multiple dimensions, draws properties from changed value-flow paths, and conducts bug detection via reachability analysis.

## Project Structure

```
SEAL
  |-- include/            # Include headers of SEAL
  |-- src/                # Source files of SEAL
  |-- helper_scripts/     # Scripts to automate batch tasks
  |-- CMakeLists.txt      # Build and configure SEAL using CMake
  |-- keywords.json       # Keywords we used to collect patches in 15 bug types
```

## Docker Environment
The environment for the compilation and execution of SEAL,.l has been set up in the docker image.

```
docker pull harperchen1110/seal-latest:1.0
docker run -it --name "seal-latest" seal-latest
```

## Installation Instructions

SEAL is developed on the basis of [LLVM 3.2](https://releases.llvm.org/3.2/docs/index.html) and [Clearblue](https://www.clearblueinnovations.org/) static analysis engine. Compiling our code would generate a shared object (`libSEGPatchPlugin.so`).

We have involved the necessary headers and libraries of LLVM and Clearblue in `/llvm` and `/clearblue` directories inside the docker image. The compilation process could be conducted with the following commands.

```
cd /seal-workdir
mkdir build && cd build

// set the path to clearblue and llvm libraries
cmake -DCB_HEADER_DIR=/clearblue -DLLVM_BUILD_MAIN_SRC_DIR=/llvm ../
make -j
```

The `libSEGPatchPlugin.so` are produced in `build` folder.

```
CMakeCache.txt  CMakeFiles  Makefile  cmake_install.cmake  libSEGPatchPlugin.so
```

## Minimum Running Example

We provide two minimal running examples, including [patch 39244cc](https://github.com/torvalds/linux/commit/39244cc754829b) and [patch 2b064d9](https://github.com/torvalds/linux/commit/2b064d9144), to illustrate how SEAL derives specifications from the code changes and detects violations inside kernel. The generated shared object (`libSEGPatchPlugin.so`) is loaded by shipped executable `/clearblue/bin/cb-check` at runtime.

### Patch 39244cc: Fix an out-of-bounds bug in ismt_access()

The patch 39244cc fixes an out-of-bounds bug in one implementation of function pointer `struct i2c_algorithm::smbus_xfer`.
The bug results from a missing sanity check on the malicious function parameter `data->block[0]`. Such malicious value is subsequently used as the length parameter of API `memcpy`, leading to out-of-bounds.
SEAL generates a reachability relation from the `block` field of the last parameter for interface `smbus_xfer` to the third parameter of API `memcpy`, guarded by the condition on `block` field. 


**Run the command as follows to generate specifications.** 

SEAL infers specifications under `infer-patch-spec` mode. It takes the following two inputs, whereas patch descriptions are excluded. The other options are utilized to control the sensitivities of the underlying static analysis engine.
- The input bitcode is placed at `/seal-workdir/test/39244cc/39244cc75482_ismt_access_11179.bc`, 
which contains pre-patch and post-patch functions, as well as all patch-related caller/callee functions.
- The code changes are placed in `/seal-workdir/test/39244cc/diff.txt`, which involves the line number of added and removed codes.


```
cd /seal-workdir/test/39244cc
/clearblue/bin/cb-check \
    -load=/seal-workdir/build/libSEGPatchPlugin.so \
    -enable-patch-analysis \
    -patch-plugin \
    -omit-no-dbginfo \
    -falcon-use-valuetostring \
    -seg-enable-valuetostring \
    -nworkers=1 \
    -execution-mode=digging \
    -set-inc-tactic=smt_tactic \
    -infer-patch-spec \
    -patch=diff.txt \
    -output=specs.csv \
    39244cc75482_ismt_access_11179.bc

// code changes in /seal-workdir/test/39244cc/diff.txt
+drivers/i2c/busses/i2c-ismt.c:512
+drivers/i2c/busses/i2c-ismt.c:513
+drivers/i2c/busses/i2c-ismt.c:514
```

The above command yields specifications in the following format. 
- `Spec Type` shows the quantifier of inferred reachability relation.
- `InputNode` specifies the regulated interactive data: the argument of the indirect call, i.e., `arg_6:0`, which is field with offset 0 from the seventh argument of the indirect call.
- `OutputNode` indicates the use to be concentrated on: the third parameter of API `memcpy`.
- `Spec Cond` represents the conditions under which the reachability relation should hold, which is transformed to SMT constraints when used by bug detection. 

```
[Spec Type] Src Must Not Reach Sink
[Start after.patch.ismt_access]
   [InputNode]: Indirect call: drivers/i2c/busses/i2c-ismt.c:after.patch.ismt_access Arg Name: arg_6:0
[End after.patch.ismt_access]
   [OutputNode]: Used in sensitive API: llvm.memcpy.p0i8.p0i8.i64 Arg idx: 2
[Spec Cond]
NOT  AND
    NOT      VALUE(  %cmp266 = icmp sgt i32 %conv265, 32, !dbg !180)    NOT      VALUE(  %cmp261 = icmp slt i32 %conv260, 1, !dbg !176)
```

The specification in csv format can be accessed in the output file `/seal-workdir/test/39244cc/specs.csv`.
```
Spec Type,Indirect Call,Spec Input,Spec Output,Spec Cond SMT,Spec Orders
Src Must Not Reach Sink,after.patch.ismt_access,Indirect call: drivers/i2c/busses/i2c-ismt.c:after.patch.ismt_access Arg Name: arg_6:0,Used in sensitive API: llvm.memcpy.p0i8.p0i8.i64 Arg idx: 2,/spec_smt_0.smt,,
```

**Run the following command to detect bugs**.

SEAL performs bug detection in `detect-path-bug` mode. It takes the generated specifications `specs.csv` as input, detects bugs with in given bitcode `media.bc`, and outputs bug reports in `bugs.json`. At a high level, the specifications are transformed into source-sink checkers and passed to the path-sensitive bug search engine of `cb-check` to detect violations. 

```
cd /seal-workdir/test/39244cc
/clearblue/bin/cb-check \
    -load=/seal-workdir/build/libSEGPatchPlugin.so \
    -enable-patch-analysis \
    -patch-plugin \
    -omit-no-dbginfo \
    -falcon-use-valuetostring \
    -seg-enable-valuetostring \
    -nworkers=1 \
    -execution-mode=digging \
    -set-inc-tactic=smt_tactic \
    -detect-patch-bug \
    -specs=specs.csv \
    -report=bugs.json \
    media.bc
```


### Patch 2b064d9: Fix a null-ptr-deref bug in buffer_prepare()

We showcase another null-ptr-deref bug in interface `struct vb2_ops::buf_prepare` that results from the wrong error code. The bug is triggered since the failure of APi `dma_alloc_coherent` is not conveyed to the invoker via the return value of the interface.
SEAL generates a reachability relation from the error code `-12` to the return value of the indirect call, under the condition the return of API `dma_alloc_coherent` is NULL.
The content of the generated specification in csv file `/seal-workdir/test/2b064d9/specs.csv` is shown below.
 
```
Spec Type,Indirect Call,Spec Input,Spec Output,Spec Cond SMT,Spec Orders
Src Must Reach Sink,after.patch.buffer_prepare,Error code: -12 Caused by Input Node: Return of API: after.patch.dma_alloc_coherent#-1,Return of indirect call: drivers/media/pci/cx88/cx88-vbi.c:after.patch.buffer_prepare,/seal-workdir/test/2b064d9/spec_smt_0.smt,,
```

## Batch Testing

We provide the lists of helper scripts we used for specifications extraction and subsequent Linux bug detection.

### Collect Patches

The script `00_patch_collector.py` automatically grasps security patches from Linux historical commits of branch Linux v6.2. It searches over the commit description to find bugs that fall into the 15 types with keywords outlined in `keywords.json`. The script could be executed as follows.

```
cd /
git clone https://github.com/torvalds/linux.git 
cd linux && git checkout v6.2
cd /seal-workdir/
python helper_scripts/00_patch_collector.py collect /seal_workdir/data/1_input_patches.csv
```

### Generate Linux bitcodes

The script `10_linux_compile.py` will generate bitcodes for source files in Linux v6.2 and link them to generate the final bitcodes for bug detection. Meanwhile, the compilation script for each source file is kept, for subsequent bitcode generation for input patches. The script could be executed as follows.

```
cd /seal-workdir/
python3 helper_scripts/10_linux_compile.py
```
The generated bitcodes are located at `/seal_workdir/data/Linux_Data/v6.2/bcs_x86_64`.

### Generate inputs of patches

The script `20_related_parser.py` iterates all security patches and determines the caller/callee functions of patched functions, which are necessary to generate bitcodes for security patches.

```
cd /seal-workdir/
python3 helper_scripts/20_related_parser.py
```

After the above command, the script `30_spec_gen.py` could generate the bitcodes for each input patch, prepares the `diff` file involving code changes, and generates commands to extract specifications.

```
cd /seal-workdir/
python3 helper_scripts/30_spec_gen.py
```

The above script generates a folder for each patch inside `/seal_workdir/data/Patch_BC`, which contains:
- `merge.bc`: the input bitcode to generate specifications
- `diff.txt`: the code changes inside patches
- `check.sh`: the script to generate specifications

### Specification Extraction

The script `31_run_analyzer.py` executes all `check.sh` scripts inside each patch folder in parallel.
Once finished, we can run `40_log_parser.py` to merge all specifications `/seal_workdir/data/5_spec_info.csv` and parse the execution log `/seal_workdir/data/4_data_info.csv`.

```
cd /seal-workdir/
python3 helper_scripts/31_run_analyzer.py
python3 helper_scripts/40_log_parser.py
```

### Bug Detection

The script `50_bug_detector.py` iterates all generated bitcodes of Linux v6.2 and performs bug detections. The final bug reports in JSON format can be found inside `/seal_workdir/data/Bug_Reports/`.

```
cd /seal-workdir/
python3 helper_scripts/50_bug_detector.py
```

### Other Scripts

- `11_call_graph.py` dumps the callee targets of all indirect calls, which would be used to determine the bug detection regions.
- `config.py` details the location of all intermediate data.

## Acknowledgement
We appreciate the underlying value-flow analysis engine Clearblue@HKUST. Please refer to the [offcial page](https://www.clearblueinnovations.org/) and [published papers](https://www.clearblueinnovations.org/docs/7-papers/) to gain more information about the powerful tool. You can learn how to [customize your bug checkers](https://www.clearblueinnovations.org/docs/4-develop-examples/vulnerability_detection/) and achieve [other program analysis tasks](https://www.clearblueinnovations.org/docs/4-develop-examples/generate_program_query/)!
