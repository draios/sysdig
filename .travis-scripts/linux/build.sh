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
rm -rf build
pushd $(mktemp -d --tmpdir sysdig.XXXXXXXXXX)
wget http://download.draios.com/dependencies/zlib-1.2.11.tar.gz
tar -xzf zlib-1.2.11.tar.gz
cd zlib-1.2.11
./configure
make
sudo make install
cd ..
wget https://github.com/open-source-parsers/jsoncpp/archive/0.10.5.tar.gz
tar zxvf 0.10.5.tar.gz
cd jsoncpp-0.10.5
cmake -DBUILD_SHARED_LIBS=ON .
make
sudo make install
cd ..
wget https://s3.amazonaws.com/download.draios.com/dependencies/libb64-1.2.src.zip
unzip libb64-1.2.src.zip
cd libb64-1.2
make
sudo cp -r include/* /usr/local/include/
sudo cp src/libb64.a /usr/local/lib/
cd ..
wget http://download.draios.com/dependencies/jq-1.5.tar.gz
tar -xzf jq-1.5.tar.gz
cd jq-1.5
./configure --disable-maintainer-mode
make LDFLAGS=-all-static
sudo cp ./jq.h /usr/local/include/
sudo cp ./jv.h /usr/local/include/
sudo cp .libs/libjq.a /usr/local/lib/
cd ..
popd
rm -rf userspace/libsinsp/third-party/jsoncpp
sudo apt-get install libncurses5-dev libluajit-5.1-dev libcurl4-openssl-dev libssl-dev
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DUSE_BUNDLED_DEPS=OFF
make VERBOSE=1
make package
cd ..
test/sysdig_trace_regression.sh build/userspace/sysdig/sysdig build/userspace/sysdig/chisels $TRAVIS_BRANCH