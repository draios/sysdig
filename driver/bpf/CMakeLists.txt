#
# Copyright (c) 2013-2021 Sysdig Inc.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

configure_file(../driver_config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/../driver_config.h)

option(BUILD_BPF "Build the BPF driver on Linux" OFF)

if (BUILD_BPF)
  add_custom_target(bpf ALL
    COMMAND make LIBBPF_INCLUDE=-I${LIBBPF_INCLUDE}
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different probe.o "${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    VERBATIM)
  add_custom_target(bpf-btf ALL
    COMMAND make LIBBPF_INCLUDE=-I${LIBBPF_INCLUDE} btf-probe.o
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different btf-probe.o "${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    VERBATIM)
  add_custom_target(bpf-btf-core ALL
    COMMAND make LIBBPF_INCLUDE=-I${LIBBPF_INCLUDE} btf-core-probe.o
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different btf-core-probe.o "${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    VERBATIM)

  if (USE_BUNDLED_LIBBPF)
    add_dependencies(bpf libbpf)
    add_dependencies(bpf-btf libbpf)
    add_dependencies(bpf-btf-core libbpf)
  endif ()
endif ()

install(FILES
  filler_helpers.h
  fillers.h
  Makefile
  maps.h
  plumbing_helpers.h
  probe.c
  quirks.h
  ring_helpers.h
  types.h
  DESTINATION "src/${PACKAGE_NAME}-${PROBE_VERSION}/bpf"
  COMPONENT agent-kmodule)

add_subdirectory(test)