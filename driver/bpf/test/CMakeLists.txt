#
# Copyright (c) 2013-2021 Sysdig Inc.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_BPF_TEST "Build the tests for the BPF driver on Linux" OFF)
option(BPF_TEST_DEBUG "Enable debug mode for the BPF driver tests" OFF)

if (BUILD_BPF_TEST)
  message(STATUS "BPF tests build enabled")
  add_executable(test_fillers
    test_fillers.c
    "${PROJECT_BINARY_DIR}/driver/src/fillers_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/syscall_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/event_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/flags_table.c"
    "${PROJECT_BINARY_DIR}/driver/src/dynamic_params_table.c")
  if (BPF_TEST_DEBUG)
    message(STATUS "BPF test debug mode enabled")
    add_definitions(-DBPF_TEST_DEBUG)
  endif ()

  add_dependencies(test_fillers libbpf zlib)
  target_include_directories(
    test_fillers
    PUBLIC
    "${ZLIB_INCLUDE}"
    "${LIBBPF_INCLUDE}"
    "${PROJECT_BINARY_DIR}/driver/src"
    "${PROJECT_BINARY_DIR}/userspace")

  target_link_libraries(test_fillers elf rt z "${LIBBPF_LIB}")
endif ()