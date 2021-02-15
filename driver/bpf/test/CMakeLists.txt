#
# Copyright (c) 2013-2021 Sysdig Inc.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

option(BUILD_BPF_TEST "Build the tests for the BPF driver on Linux" OFF)
add_executable(test_fillers
  test_fillers.c
  "${PROJECT_BINARY_DIR}/driver/src/fillers_table.c"
  "${PROJECT_BINARY_DIR}/driver/src/syscall_table.c"
  "${PROJECT_BINARY_DIR}/driver/src/event_table.c"
  "${PROJECT_BINARY_DIR}/driver/src/flags_table.c"
  "${PROJECT_BINARY_DIR}/driver/src/dynamic_params_table.c")
add_dependencies(test_fillers libbpf zlib)
target_include_directories(
  test_fillers
  PUBLIC
  "${ZLIB_INCLUDE}"
  "${LIBBPF_INCLUDE}"
  "${PROJECT_BINARY_DIR}/driver/src"
  "${PROJECT_BINARY_DIR}/userspace")

#todo(fntlnz): replace zlib with our provided one
target_link_libraries(test_fillers elf rt z "${LIBBPF_LIB}")