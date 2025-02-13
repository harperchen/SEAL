cmake_minimum_required(VERSION 2.8.8)
project(SEAL)

include(ExternalProject)

# 1: find LLVM package 
if (NOT LLVM_BUILD_PATH)
    message(FATAL_ERROR "please specified the build folder of LLVM by -DLLVM_BUILD_PATH=")
else ()
    message(STATUS "LLVM_BUILD_PATH set to : ${LLVM_BUILD_PATH}")
endif ()

find_package(LLVM
        REQUIRED
        CONFIG
        PATHS ${LLVM_BUILD_PATH}
        NO_DEFAULT_PATH)

if (NOT LLVM_FOUND)
    message(FATAL_ERROR "can not find LLVMConfig.cmake under paths: ${LLVM_BUILD_PATH}")
else ()
    message(STATUS "Found LLVM : ${LLVM_PACKAGE_VERSION}")
    message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
    message(STATUS "LLVM header files locate in : ${LLVM_INCLUDE_DIRS}")
    message(STATUS "LLVM definitions is : ${LLVM_DEFINITIONS}")

    # we incorporate the CMake features provided by LLVM:
    list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
    include(AddLLVM)
    include(HandleLLVMOptions)
    set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/bin)
    set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/lib)

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LLVM_CXXFLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LLVM_LDFLAGS}")

#    set(LLVM_REQUIRES_RTTI TRUE)
#    set(LLVM_REQUIRES_EH TRUE)

    include_directories(${LLVM_INCLUDE_DIRS})
    link_directories(${LLVM_LIBRARY_DIRS})
    add_definitions(${LLVM_DEFINITIONS})
    message(STATUS "definitions in LLVM ${LLVM_DEFINITIONS}")
endif ()
