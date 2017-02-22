#!/bin/bash
set -e
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DUSE_BUNDLED_LUAJIT=OFF -DUSE_BUNDLED_ZLIB=OFF
make install
../test/sysdig_trace_regression.sh $(which sysdig) ./userspace/sysdig/chisels $TRAVIS_BRANCH