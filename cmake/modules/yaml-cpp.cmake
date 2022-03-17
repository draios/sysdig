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
  set(YAMLCPP_LIB "${YAMLCPP_SRC}/libyaml-cpp.a")
  set(YAMLCPP_INCLUDE_DIR "${YAMLCPP_SRC}/include")
  ExternalProject_Add(
    yaml-cpp
    URL "https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-0.6.2.tar.gz"
    URL_HASH "SHA256=e4d8560e163c3d875fd5d9e5542b5fd5bec810febdcba61481fe5fc4e6b1fd05"
    BUILD_BYPRODUCTS ${YAMLCPP_LIB}
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND "")
endif()
