#!/bin/bash
set -e
export CC="gcc-4.8"
export CXX="g++-4.8"
wget https://s3.amazonaws.com/download.draios.com/dependencies/cmake-3.3.2.tar.gz
tar -xzf cmake-3.3.2.tar.gz
cd cmake-3.3.2
./bootstrap --prefix=/usr
make
sudo make install
cd ..
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE
make VERBOSE=1
make package
cd ..
test/sysdig_trace_regression.sh build/userspace/sysdig/sysdig build/userspace/sysdig/chisels $TRAVIS_BRANCH
