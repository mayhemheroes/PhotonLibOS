cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(
        photon
        VERSION 0.6
        LANGUAGES C CXX ASM
)

# Utility Modules and Find Modules
include(FindPackageHandleStandardArgs)
include(CheckCXXCompilerFlag)
include(FetchContent)
set(FETCHCONTENT_QUIET false)
find_package(PkgConfig REQUIRED)

# Options
option(ENABLE_URING "enable io_uring function" OFF)
option(ENABLE_FUSE "enable fuse function" OFF)
option(ENABLE_SASL "enable sasl" OFF)
option(ENABLE_MIMIC_VDSO "enable mimic vdso" OFF)
option(BUILD_TESTING "enable build testing" OFF)
option(FETCH_GTEST_GFLAGS_SOURCE "Fetch gtest, gmock and gflags source code. Link their static libs" OFF)
option(ENABLE_FSTACK_DPDK "Use f-stack + DPDK as the event engine" OFF)
option(ENABLE_EXTFS "enable extfs" OFF)

# Get CPU arch
execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT (${ARCH} STREQUAL x86_64) AND NOT (${ARCH} STREQUAL aarch64) AND NOT (${ARCH} STREQUAL arm64))
    message(FATAL_ERROR "Unknown CPU architecture ${ARCH}")
endif ()

# Compiler options
add_compile_options(-Wall)  # -Werror is not enable yet

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED on)
set(CMAKE_CXX_EXTENSIONS off)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_RPATH_USE_ORIGIN on)
set(CMAKE_POSITION_INDEPENDENT_CODE on)

if (${ARCH} STREQUAL x86_64)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse4.2")
elseif (${ARCH} STREQUAL aarch64)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=generic+crc -fsigned-char -fno-stack-protector -fomit-frame-pointer")
endif ()

check_cxx_compiler_flag(-mcrc32 COMPILER_HAS_MCRC32_FLAG)
if (COMPILER_HAS_MCRC32_FLAG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcrc32")
endif ()

set(CMAKE_C_FLAGS ${CMAKE_CXX_FLAGS})
set(CMAKE_C_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
set(CMAKE_C_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})

# Default build type is Release
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# If ccache exists, use it to speed up compiling
find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
endif(CCACHE_FOUND)

# CMake dirs
list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMake)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/output)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/output)

# Third party
add_subdirectory(third_party)

# Find packages either from cmake-modules or external packages(in CMake dir)
if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    find_package(aio REQUIRED)
    if (ENABLE_FUSE)
        find_package(fuse REQUIRED)
    endif ()
    if (ENABLE_URING)
        find_package(uring)
        if (NOT URING_FOUND)
            message("liburing not found, fetch source and compile it")
            # Fetch liburing
            FetchContent_Declare(
                    liburing
                    GIT_REPOSITORY https://github.com/axboe/liburing.git
                    # GIT_REPOSITORY https://gitee.com/mirrors_axboe/liburing.git
                    GIT_TAG liburing-2.3
                    UPDATE_COMMAND ./configure
            )
            FetchContent_MakeAvailable(liburing)
            set(liburing_include_dir ${liburing_SOURCE_DIR}/src/include)
            add_library(
                    uring
                    STATIC
                    ${liburing_SOURCE_DIR}/src/setup.c
                    ${liburing_SOURCE_DIR}/src/queue.c
                    ${liburing_SOURCE_DIR}/src/register.c
                    ${liburing_SOURCE_DIR}/src/syscall.c
            )
            # CMake didn't provide an abstraction of optimization level for now.
            # When multiple -O options appear, only the last one is effective
            target_compile_options(uring PRIVATE -O3 -Wall -Wextra -fno-stack-protector -Wno-unused-parameter -Wno-sign-compare)
            target_compile_definitions(uring PRIVATE _GNU_SOURCE LIBURING_INTERNAL)
            target_include_directories(uring PRIVATE ${liburing_include_dir})
        else()
            message("liburing found")
        endif()
    endif ()
endif()
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)
if (ENABLE_SASL)
    find_package(gsasl REQUIRED)
endif ()
if (ENABLE_EXTFS)
    find_package(e2fs REQUIRED)
endif()

if (FETCH_GTEST_GFLAGS_SOURCE)
    FetchContent_Declare(
            gflags
            GIT_REPOSITORY https://github.com/gflags/gflags.git
            # GIT_REPOSITORY https://gitee.com/mirrors/gflags.git
            GIT_TAG v2.2.2
            GIT_SUBMODULES ""
    )
    FetchContent_MakeAvailable(gflags)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            # GIT_REPOSITORY https://gitee.com/mirrors/googletest.git
            GIT_TAG release-1.12.1
    )
    FetchContent_MakeAvailable(googletest)
endif()

# Compile photon objects
file(GLOB PHOTON_SRC
        photon.cpp
        common/*.cpp
        common/checksum/*.cpp
        common/executor/*.cpp
        common/memory-stream/*.cpp
        common/stream-messenger/*.cpp
        fs/aligned-file.cpp
        fs/async_filesystem.cpp
        fs/exportfs.cpp
        fs/filecopy.cpp
        fs/localfs.cpp
        fs/path.cpp
        fs/subfs.cpp
        fs/throttled-file.cpp
        fs/virtual-file.cpp
        fs/xfile.cpp
        fs/httpfs/*.cpp
        io/signal.cpp
        net/*.cpp
        net/http/*.cpp
        net/security-context/tls-stream.cpp
        rpc/*.cpp
        thread/*.cpp
        )
if (APPLE)
    list(APPEND PHOTON_SRC io/kqueue.cpp)
else ()
    list(APPEND PHOTON_SRC io/aio-wrapper.cpp io/epoll.cpp)
    if (ENABLE_URING)
        list(APPEND PHOTON_SRC io/iouring-wrapper.cpp)
    endif ()
endif ()
if (ENABLE_FUSE)
    list(APPEND PHOTON_SRC io/fuse-adaptor.cpp)
endif ()
if (ENABLE_SASL)
    list(APPEND PHOTON_SRC net/security-context/sasl-stream.cpp)
endif ()
if (ENABLE_FSTACK_DPDK)
    list(APPEND PHOTON_SRC io/fstack-dpdk.cpp)
endif ()
if (ENABLE_EXTFS)
    file(GLOB EXTFS_SRC fs/extfs/*.cpp)
    list(APPEND PHOTON_SRC ${EXTFS_SRC})
endif ()

# An object library compiles source files but does not archive or link their object files.
add_library(photon_obj OBJECT ${PHOTON_SRC})
target_include_directories(photon_obj PUBLIC include ${OPENSSL_INCLUDE_DIR})
target_compile_definitions(photon_obj PRIVATE _FILE_OFFSET_BITS=64 FUSE_USE_VERSION=29)
if (ENABLE_URING)
    target_include_directories(photon_obj PUBLIC ${liburing_include_dir})
    target_compile_definitions(photon_obj PRIVATE PHOTON_URING=on)
endif()
if (ENABLE_MIMIC_VDSO)
    target_compile_definitions(photon_obj PRIVATE ENABLE_MIMIC_VDSO=on)
endif()
if (ENABLE_EXTFS)
    target_include_directories(photon_obj PUBLIC ${LIBE2FS_INCLUDE_DIRS})
endif()
if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 8.0)
    # This option is enabled by default after -std=c++17
    target_compile_options(photon_obj PRIVATE -faligned-new)
endif()

# Add f-stack and dpdk libs.
if (ENABLE_FSTACK_DPDK)
    pkg_check_modules(DPDK REQUIRED libdpdk)
    find_package(fstack REQUIRED)
    target_include_directories(photon_obj PRIVATE ${DPDK_INCLUDE_DIRS} ${FSTACK_INCLUDE_DIRS})
    target_compile_definitions(photon_obj PRIVATE ENABLE_FSTACK_DPDK)

    add_library(fstack_dpdk INTERFACE)
    target_link_libraries(fstack_dpdk INTERFACE ${DPDK_STATIC_LDFLAGS} ${FSTACK_LIBRARIES})
endif()

# Make virtual interface for external dynamic libs.
add_library(external_lib INTERFACE)
set(EXTERNAL_LIB_ARGS
        ZLIB::ZLIB
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        -lpthread
        )

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    list(APPEND EXTERNAL_LIB_ARGS -lgcc)  # solve [hidden symbol `__cpu_model'] problem
endif ()
if (NOT APPLE)
    list(APPEND EXTERNAL_LIB_ARGS ${AIO_LIBRARIES} -lrt)
    if (ENABLE_FUSE)
        list(APPEND EXTERNAL_LIB_ARGS ${FUSE_LIBRARIES})
    endif ()
endif ()
if (ENABLE_SASL)
    list(APPEND EXTERNAL_LIB_ARGS ${GSASL_LIBRARIES})
endif ()
if (ENABLE_EXTFS)
    list(APPEND EXTERNAL_LIB_ARGS ${LIBE2FS_LIBRARIES})
endif ()
target_link_libraries(external_lib INTERFACE ${EXTERNAL_LIB_ARGS})

# Link photon shared lib
add_library(photon_shared SHARED $<TARGET_OBJECTS:photon_obj>)
set_target_properties(photon_shared PROPERTIES OUTPUT_NAME photon)
if (APPLE)
    set(shared_link_libs external_lib -Wl,-force_load easy_weak)
elseif (ENABLE_URING)
    set(shared_link_libs -Wl,--whole-archive easy_weak fstack_weak uring -Wl,--no-whole-archive external_lib)
else()
    set(shared_link_libs -Wl,--whole-archive easy_weak fstack_weak -Wl,--no-whole-archive external_lib)
endif ()
target_link_libraries(photon_shared ${shared_link_libs})

# Link photon static lib
add_library(photon_static STATIC $<TARGET_OBJECTS:photon_obj>)
set_target_properties(photon_static PROPERTIES OUTPUT_NAME photon)
if (ENABLE_URING)
    set(static_link_libs easy_weak fstack_weak uring external_lib)
else ()
    set(static_link_libs easy_weak fstack_weak external_lib)
endif ()
target_link_libraries(photon_static ${static_link_libs})

# Build test cases
if (BUILD_TESTING)
    include(CTest)

if (FETCH_GTEST_GFLAGS_SOURCE)
    set(testing_libs gtest gmock gflags::gflags)
else()
    find_package(GTest REQUIRED)
    find_package(gmock REQUIRED)
    find_package(gflags REQUIRED)
    set(testing_libs ${GTEST_BOTH_LIBRARIES} ${GMOCK_LIBRARIES} ${GFLAGS_LIBRARIES})
    include_directories(${GTEST_INCLUDE_DIRS} ${GMOCK_INCLUDE_DIRS} ${GFLAGS_INCLUDE_DIRS})
endif()

    add_subdirectory(examples)
    add_subdirectory(common/checksum/test)
    add_subdirectory(common/test)
    add_subdirectory(fs/test)
    add_subdirectory(io/test)
    add_subdirectory(net/test)
    add_subdirectory(net/http/test)
    add_subdirectory(rpc/test)
    add_subdirectory(thread/test)
    add_subdirectory(net/security-context/test)
if (ENABLE_EXTFS)
    add_subdirectory(fs/extfs/test)
endif ()

endif ()
