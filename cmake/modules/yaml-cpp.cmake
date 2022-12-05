#
# Copyright (C) 2013-2022 Draios Inc dba Sysdig.
#
# This file is part of sysdig .
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
mark_as_advanced(YAMLCPP_INCLUDE_DIR YAMLCPP_LIB)
if(NOT USE_BUNDLED_DEPS)
  find_path(YAMLCPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h)
  find_library(YAMLCPP_LIB NAMES yaml-cpp)
  if(YAMLCPP_INCLUDE_DIR AND YAMLCPP_LIB)
    message(STATUS "Found yamlcpp: include: ${YAMLCPP_INCLUDE_DIR}, lib: ${YAMLCPP_LIB}")
  else()
    message(FATAL_ERROR "Couldn't find system yamlcpp")
  endif()
else()
  set(YAMLCPP_SRC "${PROJECT_BINARY_DIR}/yaml-cpp-prefix/src/yaml-cpp")
  message(STATUS "Using bundled yaml-cpp in '${YAMLCPP_SRC}'")
  if(NOT WIN32)
    set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
  else()
    set(YAMLCPP_LIB "${YAMLCPP_SRC}/${CMAKE_BUILD_TYPE}/yaml-cpp.lib")
  endif()
  set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
  ExternalProject_Add(
    yaml-cpp
    URL "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.7.0.tar.gz"
    URL_HASH "SHA256=43e6a9fcb146ad871515f0d0873947e5d497a1c9c60c58cb102a97b47208b7c3"
    BUILD_BYPRODUCTS ${YAMLCPP_LIB}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DYAML_MSVC_SHARED_RT=Off -DYAML_BUILD_SHARED_LIBS=Off -DYAML_CPP_BUILD_TESTS=Off -DYAML_CPP_BUILD_TOOLS=OFF -DYAML_CPP_BUILD_CONTRIB=OFF -DCMAKE_DEBUG_POSTFIX=''
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
endif()
