SHELL := /bin/bash
ALL_ARCHS := x86_64 aarch64

# Equals function
eq = $(and $(findstring $(1),$(2)),$(findstring $(2),$(1)))

CONFIGS := $(call rwildcard,config/*,*.yaml)
VERSIONS := $(patsubst config/%,%,$(sort $(dir $(wildcard config/*/))))
VERSIONS := $(VERSIONS:/=)
TARGET_VERSION ?= *
TARGET_DISTRO ?= *
TARGET_KERNEL_RELEASE ?= *
TARGET_KERNEL_VERSION ?= *
TARGET_KERNEL ?= ${TARGET_KERNEL_RELEASE}_${TARGET_KERNEL_VERSION}
TARGET_ARCH ?= *
# If TARGET_ARCH value is "*" then we consider all the the supported archs in ALL_ARCHS,
# otherwise we just keep the one passed as parameter.
TARGET_ARCHS := $(if $(call eq,$(TARGET_ARCH),*),$(ALL_ARCHS),$(TARGET_ARCH))
TARGET_HEADERS ?=
TARGET_KERNEL_DEFCONFIG ?=

generate:
	$(foreach ARCH,$(TARGET_ARCHS),\
		$(foreach VERSION,$(VERSIONS),\
			utils/generate -a '$(ARCH)' -k '${TARGET_KERNEL}' -r '${TARGET_KERNEL_RELEASE}' -t '${TARGET_KERNEL_VERSION}' -d '${TARGET_DISTRO}' -h '${TARGET_HEADERS}' -v '${VERSION}' -c '${TARGET_KERNEL_DEFCONFIG}'; \
		)\
	)

generate/auto:
	$(foreach ARCH,$(TARGET_ARCHS),\
		utils/scrape_and_generate $(ARCH); \
	)
