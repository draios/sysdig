#
# Copyright (c) 2013-2021 Draios Inc. dba Sysdig.
#
# This file is dual licensed under either the MIT or GPL 2. See
# MIT.txt or GPL.txt for full copies of the license.
#

always += probe.o

LLC ?= llc
CLANG ?= clang

# BPFTOOL ?= bpftool

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

# DEBUG = -DBPF_DEBUG

all:
	$(MAKE) -C $(KERNELDIR) M=$$PWD

clean:
	$(MAKE) -C $(KERNELDIR) M=$$PWD clean
	@rm -f *~
	# rm -f btf-probe.h

$(obj)/probe.o: $(src)/probe.c \
		$(src)/filler_helpers.h \
		$(src)/fillers.h \
		$(src)/maps.h \
		$(src)/plumbing_helpers.h \
		$(src)/quirks.h \
		$(src)/ring_helpers.h \
		$(src)/types.h
	$(CLANG) $(LINUXINCLUDE) \
		$(KBUILD_CPPFLAGS) \
		$(KBUILD_EXTRA_CPPFLAGS) \
		$(DEBUG) \
		$(LIBBPF_INCLUDE) \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-fno-jump-tables \
		-fno-stack-protector \
		-Wno-tautological-compare \
		-O2 -g -emit-llvm -c $< -o $(patsubst %.o,%.ll,$@)
	$(LLC) -march=bpf -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)


# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
# This approach comes from libbpf-bootstrap
# https://github.com/libbpf/libbpf-bootstrap/blob/eb6709ae72f37e7af89b8527c3f8923b1721a6d5/src/Makefile#L14
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

btf-probe.o: probe.c \
		filler_helpers.h \
		fillers.h \
		maps.h \
		plumbing_helpers.h \
		quirks.h \
		ring_helpers.h \
		types.h \
		kernel_flags.h \
		vmlinux.h
	$(CLANG) \
		$(DEBUG) \
		$(CLANG_BPF_SYS_INCLUDES) \
		$(LIBBPF_INCLUDE) \
		-D__KERNEL__ \
		-D__SYSDIG_BTF_BUILD__ \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_X86__ \
		-O2 -target bpf -g  -c $< -o $@


# btf-probe.h: btf-probe.o
# 	$(BPFTOOL) gen skeleton $(patsubst %.h,%.o,$@) > $@
