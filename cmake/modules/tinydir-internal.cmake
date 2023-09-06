#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

#
# Tinydir (https://github.com/cxong/tinydir/)
#

option(USE_BUNDLED_TINYDIR "Enable building of the bundled tinydir" ${USE_BUNDLED_DEPS})

if(TINYDIR_INCLUDE)
    # we already have tinydir
	message(STATUS "Using tinydir: include: ${TINYDIR_INCLUDE}")
elseif(NOT USE_BUNDLED_TINYDIR)
    find_path(TINYDIR_INCLUDE tinydir.h)
    if(TINYDIR_INCLUDE)
        message(STATUS "Found tinydir: include: ${TINYDIR_INCLUDE}")
    else()
        message(FATAL_ERROR "Couldn't find system tinydir")
    endif()
else()
    set(TINYDIR_SRC "${PROJECT_BINARY_DIR}/tinydir-prefix/src/tinydir")
    set(TINYDIR_INCLUDE "${TINYDIR_SRC}")

    message(STATUS "Using bundled tinydir in '${TINYDIR_SRC}'")

    ExternalProject_Add(tinydir-internal
            PREFIX "${PROJECT_BINARY_DIR}/tinydir-prefix"
            URL "https://github.com/cxong/tinydir/archive/refs/tags/1.2.5.tar.gz"
            URL_HASH "SHA256=7ab150a16fa78ea76e9fd58ef88922c03eca2334c023b8d9bc94755fdde522c7"
            CONFIGURE_COMMAND ""
            BUILD_COMMAND ""
            INSTALL_COMMAND "")
endif()

if(NOT TARGET tinydir-internal)
    add_custom_target(tinydir-internal)
endif()

include_directories("${TINYDIR_INCLUDE}")
