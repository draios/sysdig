FROM ghcr.io/draios/scap-driver-toolchains-base:dev AS llvm-7

ARG MAKE_JOBS=4
ENV MAKE_JOBS=${MAKE_JOBS}

WORKDIR /src/llvm/7

RUN curl --remote-name-all -L https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/cfe-7.1.0.src.tar.xz{,.sig} \
	https://github.com/llvm/llvm-project/releases/download/llvmorg-7.1.0/llvm-7.1.0.src.tar.xz{,.sig} \
	&& gpg --verify cfe-7.1.0.src.tar.xz.sig \
	&& gpg --verify llvm-7.1.0.src.tar.xz.sig \
	&& tar -xf llvm-7.1.0.src.tar.xz \
	&& tar -xf cfe-7.1.0.src.tar.xz \
	&& mv cfe-7.1.0.src clang

WORKDIR /src/llvm/7/build

RUN cmake -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_INSTALL_PREFIX=/opt/scap-driver-toolchains/llvm-7 -DLLVM_ENABLE_PROJECTS=clang -DCMAKE_CXX_FLAGS='-static-libgcc' -G "Unix Makefiles" ../llvm-7.1.0.src \
	&& make -j ${MAKE_JOBS} \
	&& make install/strip


FROM registry.access.redhat.com/ubi8
COPY --from=llvm-7 /opt/scap-driver-toolchains/ /opt/scap-driver-toolchains/
