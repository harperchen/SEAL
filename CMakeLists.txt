cmake_minimum_required(VERSION 2.8.8)
project(Clearblue)

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

# Set your project compile flags.
# E.g. if using the C++ header files
# you will need to enable C++11 support
# for your compiler.


list(APPEND CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#2: setup z3 library name and z3 link options
if (APPLE)
    SET(Z3LibExt .dylib)
elseif (UNIX)
    SET(Z3LibExt .so)
else ()
    SET(Z3LibExt .dll)
endif ()

if (APPLE)
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
        link_directories("/opt/homebrew/lib/")
        include_directories("/opt/homebrew/include")
    else()
        link_directories("/usr/local/lib/")
        include_directories("/usr/local/include")
    endif()
endif ()

if (NOT ENABLE_STATICZ3)
    SET(Z3LibraryName "libz3${Z3LibExt}")
else ()
    SET(Z3LibraryName "libz3.a")
endif ()


# check whether set up the option for loading vulnerability
#if (ENABLE_LOADABLE_CHECKERS)
#    SET(ENABLE_LOADABLE_CHECKERS 0)
#else ()
#    SET(ENABLE_LOADABLE_CHECKERS 1)
#endif ()
message(STATUS "ENABLE_LOADABLE_CHECKERS set to:" ${ENABLE_LOADABLE_CHECKERS})

#check whether need assertion

if (NOT ENABLE_ASSERT)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNDEBUG")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG")
endif ()

# Enable assertion in cmake build type RelWithDebInfo
string( REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")

if (ENABLE_ASAN)
    set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    set (CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
    message(STATUS "AddressSanitizer enabled")
endif()

# 2: find Z3 package
# message(STATUS "llvm_module_path is ${CMAKE_MODULE_PATH}")
#find_package(Z3 4.4.0)
#if( NOT Z3_FOUND )
#    message(FATAL_ERROR "Z3 4.4.0 not found")
#else()
#    include_directories(${Z3_INCLUDE_DIR})
#    message("Z3_INCLUDE_DIR: ${Z3_INCLUDE_DIR}")
#endif()
#if (NOT ENABLE_STATICZ3)
#    find_package(Z3 4.4)
#    if( NOT Z3_FOUND )
#        message(FATAL_ERROR "Z3 4.4 or above not found")
#    else()
#        include_directories(${Z3_INCLUDE_DIR})
#        message(STATUS "z3 include directory:" ${Z3_INCLUDE_DIR})
#    endif()
#endif()

# 3: send flags
# CXXFLAGS += -Wall -Wno-deprecated -I${LLVM_SRC_ROOT}/lib -I/usr/local/include -I${PROJ_SRC_ROOT}/lib -I${PROJ_SRC_ROOT}/submodule/canary/include -fexceptions 
# CXXFLAGS += -I${PROJ_SRC_ROOT}/third-party -I${PROJ_SRC_ROOT}/submodule
# CFLAGS += -std=c11
# LDFLAGS += -L/usr/local/lib
# LIBS += -lz3
# set(LLVM_ENABLE_EH TRUE)
set(TBB_TEST OFF CACHE INTERNAL "")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-comment -Wno-deprecated")
set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -L/usr/local/lib")
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/submodule/canary/bin)


# 4: add current include folder
include_directories(BEFORE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/oneTBB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/canary/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/coral/include
        ${CMAKE_CURRENT_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/third-party/z3/src/api/c++
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/third-party/z3/src/api/)

# 5: add black art in llvm project
include_directories(BEFORE
        ${LLVM_BUILD_MAIN_SRC_DIR}/lib)
include_directories(BEFORE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/)
message(STATUS "LLVM source code locate at : ${LLVM_BUILD_MAIN_SRC_DIR}")

# 5: add function definitions
function(CB_GET_SOURCE_FILES RETURN_LIST)
    file(GLOB ORIGINAL
            "*.c"
            "*.cpp"
            "*.cc")

    foreach (g ${ORIGINAL})
        get_filename_component(g ${g} NAME)
        list(APPEND FILES ${g})
    endforeach ()
    set(${RETURN_LIST} ${FILES} PARENT_SCOPE)
endfunction()

function(CB_ADD_LIBRARY LIB_NAME)
    CB_GET_SOURCE_FILES(SRC_LISTS)
    message(STATUS "found source files: ${SRC_LISTS}")
    add_llvm_library(${LIB_NAME}
            ${SRC_LISTS})
endfunction()

function(CB_ADD_SHARED_LIBRARY LIB_NAME)
    CB_GET_SOURCE_FILES(SRC_LISTS)
    message(STATUS "found source files: ${SRC_LISTS}")
    add_llvm_loadable_module(${LIB_NAME}
            ${SRC_LISTS})
endfunction()

function(CB_ADD_ALL_SUBDIRS)
    file(GLOB entries *)
    foreach (entry ${entries})
        if (IS_DIRECTORY ${entry} AND EXISTS ${entry}/CMakeLists.txt)
            add_subdirectory(${entry})
        endif ()
    endforeach (entry)
endfunction()

# 6: add subdirectory
# add_subdirectory(include)

add_subdirectory(third-party)
add_subdirectory(submodule)
add_subdirectory(lib)
add_subdirectory(tools)
# Now build our tools
# add_executable(simple-tool tool.cpp)

# Find the libraries that correspond to the LLVM components
# that we wish to use
# llvm_map_components_to_libnames(llvm_libs support core irreader)

# Link against LLVM libraries
# target_link_libraries(simple-tool ${llvm_libs})

# 7: add pre-commit hooks
IF (NOT EXISTS ${CMAKE_CURRENT_LIST_DIR}/.git/hooks/pre-commit)
    # FIND_PACKAGE(Python3 COMPONENTS Interpreter Development)
    IF (POLICY CMP0094)  # https://cmake.org/cmake/help/latest/policy/CMP0094.html
        CMAKE_POLICY(SET CMP0094 NEW)  # FindPython should return the first matching Python
    ENDIF ()
    # needed on GitHub Actions CI: actions/setup-python does not touch registry/frameworks on Windows/macOS
    # this mirrors PythonInterp behavior which did not consult registry/frameworks first
    IF (NOT DEFINED Python_FIND_REGISTRY)
        SET(Python_FIND_REGISTRY "LAST")
    ENDIF ()
    IF (NOT DEFINED Python_FIND_FRAMEWORK)
        SET(Python_FIND_FRAMEWORK "LAST")
    ENDIF ()
    FIND_PACKAGE(Python REQUIRED COMPONENTS Interpreter)
    MESSAGE(STATUS "Python executable: ${Python_EXECUTABLE}")
    EXECUTE_PROCESS(COMMAND ${Python_EXECUTABLE} -m pip install pip scikit-build --upgrade --user)
    EXECUTE_PROCESS(COMMAND ${Python_EXECUTABLE} -m pip install clang-format pre-commit --upgrade --user)
    EXECUTE_PROCESS(COMMAND ${Python_EXECUTABLE} -m pre_commit install WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
ENDIF ()

set(INSTALL_INCLUDE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/rapidjson/include/
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libiberty
        ${CMAKE_CURRENT_SOURCE_DIR}/third-party/oneTBB/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/third-party/z3/src/api/c++/
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/third-party/z3/src/api/)

set(INSTALL_INCLUDE_INCLUDE_DIR
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/SMT/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/canary/include
        ${CMAKE_CURRENT_SOURCE_DIR}/submodule/coral/include
        ${CMAKE_CURRENT_BINARY_DIR}/include)

install(DIRECTORY "${INSTALL_INCLUDE_INCLUDE_DIR}" # source directory
        DESTINATION "./" # target directory
        FILES_MATCHING # install only matched files
        PATTERN "*.h" # select header files
        )

foreach(dir ${INSTALL_INCLUDE_INCLUDE_DIR})
    install(DIRECTORY "${dir}" # source directory
        DESTINATION "./" # target directory
        FILES_MATCHING # install only matched files
        PATTERN "*.h" # select header files
        )
endforeach()

foreach(dir ${INSTALL_INCLUDE_DIR})
    install(DIRECTORY "${dir}" # source directory
            DESTINATION "include" # target directory
            FILES_MATCHING # install only matched files
            PATTERN "*.h" # select header files
            )
endforeach()

# 8: generate Doxygen documents
# Require dot, treat the other components as optional
if (ENABLE_DOCUMENT)
    find_package(Doxygen
            REQUIRED dot
            OPTIONAL_COMPONENTS mscgen dia)
    if (DOXYGEN_FOUND)
        # set input and output files
        set(DOXYGEN_IN ${CMAKE_CURRENT_LIST_DIR}/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

        # request to configure the file
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)

        # note the option ALL which allows to build the docs together with the application
        add_custom_target( docs ALL
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
                WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM )
    else (DOXYGEN_FOUND)
        message("Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif (ENABLE_DOCUMENT)

# 9: Example loadable checker
if (ENABLE_EXAMPLE_CHECKER)
    add_subdirectory(userdef)
endif(ENABLE_EXAMPLE_CHECKER)