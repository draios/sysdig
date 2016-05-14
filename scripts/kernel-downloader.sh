#!/bin/bash

set -euo pipefail

# USAGE:
# ./kernel-downloader.sh DISTRO [VERSION] URL...

# Where to download the kernel headers. A subfolder for each distro will be
# created.
declare -r BASEDIR="$(pwd)/kernels"
declare -r BUILDER_LOG_FILENAME=".sysdig-builder-log"

# A Python implementation of realpath from coreutils, which doesn't work
# in Ubuntu 14.04.4 LTS because the function we want is available only
# starting the lastest Debian Unstable package version implemented in Ubuntu
# and not yet under Debian Testing which Ubuntu LTS is based on.
# Thanks Debian.
function prealpath { # prealpath(path, relative_to)
	python -c "import os.path; print os.path.relpath('$1', '$2')"
}

# This is just because I was sick and tired of doing it over and over
function mkcd {
	if [ ! -d "$1" ]; then
		mkdir "$1"
	fi
	cd "$1"
}

# This helps handling race conditions with $BUILDER_LOG_FILENAME as a lock.
function create_log {
	local KERNEL_RELEASE="$1"
	local HASH="$2"
	local HASH_ORIG="$3"
	local KERNELDIR="$4"
	
	echo KERNEL_RELEASE=$KERNEL_RELEASE > "${BUILDER_LOG_FILENAME}.tmp"
	echo HASH=$HASH >> "${BUILDER_LOG_FILENAME}.tmp"
	echo HASH_ORIG=$HASH_ORIG >> "${BUILDER_LOG_FILENAME}.tmp"
	echo KERNELDIR=$KERNELDIR >> "${BUILDER_LOG_FILENAME}.tmp"
	
	mv "${BUILDER_LOG_FILENAME}.tmp" "$BUILDER_LOG_FILENAME"
}

#
# The purpose of this function is to download and decompress correctly
# aggregated packages.
# Its arguments are the same of this script so we'll find:
#   $DISTRO $VERSION $URL $URL $URL ...
# $URL is an ellipsis and files will be downloaded and extracted one by one.
# If links have been aggregated properly, once all files are downloaded no
# further action is required and probes can be later built.
#
function standard_downloader {

	local DISTRO=$1
	local VERSION=$2

	mkcd $DISTRO
	mkcd $VERSION

	# Download and extract the files, if not present
	for PKG_URL in "${@:3}"; do

		local PKG_NAME=$(basename $PKG_URL)

		if [ ! -f $PKG_NAME ]; then

			wget $PKG_URL

			case $DISTRO in
				"Ubuntu" )
					dpkg -x $PKG_NAME ./
				;;

				"Fedora" | "CentOS" )
					rpm2cpio $PKG_NAME | cpio -idm
				;;

				"CoreOS" )
					# Get the build number (main version, required later)
					local BUILD=$(echo $VERSION | grep -E -o "^[0-9]+")

					# Unzip and mount kernel image
					bunzip2 -k coreos_developer_container.bin.bz2
					local LOOPDEV=$(sudo kpartx -asv coreos_developer_container.bin | cut -d\  -f 3)
					sudo mkdir /tmp/loop/ || true
					sudo mount /dev/mapper/$LOOPDEV /tmp/loop

					# Get the configuration files
					cp /tmp/loop/usr/boot/config-* .
					cp config-* config_orig

					# Get CoreOS kernel release
					local KERNEL_RELEASE=$(ls config-* | sed s/config-//)

					# If it's a new CoreOS release, get the kernel headers from
					# the image
					if [ $BUILD -gt 890 ]; then
						cp -r /tmp/loop/lib/modules/$KERNEL_RELEASE .
					fi

					# Unmount kernel image and free space
					sudo umount /tmp/loop
					sudo kpartx -dv coreos_developer_container.bin
					rm coreos_developer_container.bin

					# For older CoreOS releases, get the kernel headers from
					# Linux source
					if [ $BUILD -le 890 ]; then
						local VANILLA=$(echo $KERNEL_RELEASE | sed s/[-+].*// | sed s/\.0$//)
						local MAJOR=$(echo $KERNEL_RELEASE | head -c1)
						local EXTRAVERSION=$(echo $KERNEL_RELEASE | sed s/[^-+]*//)
						local TGZ_NAME=linux-${VANILLA}.tar.xz
						local DIR_NAME=linux-${VANILLA}
						local KERNEL_URL=https://www.kernel.org/pub/linux/kernel/v${MAJOR}.x/$TGZ_NAME

						if [ ! -f $TGZ_NAME ]; then
							wget $KERNEL_URL
						fi

						if [ ! -d $DIR_NAME ]; then
							tar xf $TGZ_NAME
							cd $DIR_NAME
							make distclean
							sed -i "s/^EXTRAVERSION.*/EXTRAVERSION = $EXTRAVERSION/" Makefile
							cp ../config_orig .config
							make modules_prepare
							mv .config ../config
							cd ..
						fi
					fi
				;;
			esac
		fi
	done

	# After everything has been downloaded and extracted, get the data for the
	# builder
	if [ ! -f $BUILDER_LOG_FILENAME ]; then
		case $DISTRO in
			"Ubuntu" )
				local KERNEL_RELEASE=$(ls -1 linux-image-* | grep -E -o "[0-9]{1}\.[0-9]+\.[0-9]+-[0-9]+-[a-z]+")
				local HASH=$(md5sum boot/config-$KERNEL_RELEASE | cut -d' ' -f1)
				local HASH_ORIG=$HASH
				local KERNELDIR="./usr/src/linux-headers-${KERNEL_RELEASE}"
			;;

			"Fedora" | "CentOS" )
				local KERNEL_RELEASE=$(ls -1 *.rpm | head -n 1 | awk 'match($0, /[^kernel\-(core\-|devel\-)?].*[^(\.rpm)]/){ print substr($0, RSTART, RLENGTH) }')

				if [ -f boot/config-$KERNEL_RELEASE ]; then
					local HASH=$(md5sum boot/config-$KERNEL_RELEASE | cut -d' ' -f1)
				else
					local HASH=$(md5sum lib/modules/${KERNEL_RELEASE}/config | cut -d' ' -f1)
				fi

				local HASH_ORIG=$HASH
				local KERNELDIR="./usr/src/kernels/${KERNEL_RELEASE}"
			;;

			# Actually I could move this straight into the previous switch
			# statement, but I like to keep things clean
			"CoreOS" )
				local BUILD=$(echo $VERSION | grep -E -o "^[0-9]+")

				local KERNEL_RELEASE=$(ls config-* | sed s/config-//)
				local HASH_ORIG=$(md5sum config_orig | cut -d' ' -f1)
				
				if [ $BUILD -le 890 ]; then
					local HASH=$(md5sum config | cut -d' ' -f1)
					local KERNELDIR=$(ls -1d -- */ | head -n 1)
				else
					local HASH=$HASH_ORIG
					local KERNELDIR="./${KERNEL_RELEASE}/build"
				fi
			;;
		esac
		
		create_log $KERNEL_RELEASE $HASH $HASH_ORIG $KERNELDIR
	fi

	cd ../.. # Back to $BASEDIR
}

# Debian downloader has a different logic (required by more compless structure):
# while other distros can be considered "stateless", meaning that packages have
# been aggregated all together and every "folder" is indipendent from each
# other, all Debian links are provided together since kbuild packages are
# required by many kernel versions and aggregation is not possible.
# Thus, Debian downloader operates statefully and transactions between folder
# have to be managed ad-hoc.
function debian_downloader {
	
	mkcd Debian
	local DEBIAN_DIR=$(pwd)

	mkcd kbuild
	local KBUILD_DIR=$(pwd)

	# Download kbuild first since they're required later
	for URL in "$@"; do
		if [ -z "$URL" ]; then
			continue
		fi
		
		local DEB=$(basename $URL)
		if [[ $DEB == *"kbuild"* ]]; then
			if [ ! -f $DEB ]; then
				wget $URL
			fi
		fi
	done

	cd .. # back to $DEBIAN_DIR

	# Now download and extract all non-kbuild ones
	for URL in "$@"; do
		
		if [ -z "$URL" ]; then
			continue
		fi
		
		local DEB=$(basename $URL)
		if [[ $DEB != *"kbuild"* ]]; then

			local KERNEL_RELEASE=$(echo $DEB | grep -E -o "[0-9]{1}\.[0-9]+\.[0-9]+(-[0-9]+)?"| head -1)
			local KERNEL_MAJOR=$(echo $KERNEL_RELEASE | grep -E -o "[0-9]{1}\.[0-9]+")
			local PACKAGE=$(echo $DEB | grep -E -o "(common_[0-9]{1}\.[0-9]+.*amd64|amd64_[0-9]{1}\.[0-9]+.*amd64)" | sed -E 's/(common_|amd64_|_amd64)//g')

			mkcd $KERNEL_RELEASE
			mkcd $PACKAGE
			
			if [ ! -f $DEB ]; then
				wget $URL
				dpkg -x $DEB ./

				NUM_DEB=$(ls linux-*.deb -1 | grep -v kbuild | wc -l)

				if [ $NUM_DEB -eq 3 ]; then
					
					set +e
					KBUILD_PACKAGE=$(ls -1 $KBUILD_DIR | grep  "kbuild\-${KERNEL_MAJOR}" | head -n 1)
					set -e

					if [ ! -z $KBUILD_PACKAGE ]; then
						cp $KBUILD_DIR/$KBUILD_PACKAGE .
						dpkg -x $KBUILD_PACKAGE ./

						local KERNEL_FOLDER=$KERNEL_RELEASE
						local KERNEL_RELEASE=$(ls boot/config-* | sed 's|boot/config-||')

						# Fix symbolic links, making them relative
						unlink ./lib/modules/${KERNEL_RELEASE}/build
						ln -s $(prealpath ./usr/src/linux-headers-${KERNEL_RELEASE} ./lib/modules/${KERNEL_RELEASE}) ./lib/modules/${KERNEL_RELEASE}/build

						local COMMON_FOLDER=$(ls ./usr/src/ | egrep '*common')
						unlink ./lib/modules/${KERNEL_RELEASE}/source
						ln -s $(prealpath ./usr/src/${COMMON_FOLDER} ./lib/modules/${KERNEL_RELEASE}) ./lib/modules/${KERNEL_RELEASE}/source

						# Hack Makefile, can't make them relative unfortunately
						sed -i '0,/MAKEARGS.*$/s||MAKEARGS := -C '"${DEBIAN_DIR}/${KERNEL_FOLDER}/${PACKAGE}/usr/src/${COMMON_FOLDER}"' O='"${DEBIAN_DIR}/${KERNEL_FOLDER}/${PACKAGE}/usr/src/linux-headers-${KERNEL_RELEASE}"'|' ${DEBIAN_DIR}/${KERNEL_FOLDER}/${PACKAGE}/usr/src/linux-headers-${KERNEL_RELEASE}/Makefile
						sed -i 's/@://' ${DEBIAN_DIR}/${KERNEL_FOLDER}/${PACKAGE}/usr/src/linux-headers-${KERNEL_RELEASE}/Makefile
						sed -i 's|$(cmd) %.*$|$(cmd) : all|' ${DEBIAN_DIR}/${KERNEL_FOLDER}/${PACKAGE}/usr/src/linux-headers-${KERNEL_RELEASE}/Makefile

						# Now that all required files have been downloaded and
						# unpacked "export" build variables
						if [ ! -f $BUILDER_LOG_FILENAME ]; then
							local HASH=$(md5sum boot/config-${KERNEL_RELEASE} | cut -d' ' -f1)
							local HASH_ORIG=$HASH
							local KERNELDIR="./usr/src/linux-headers-${KERNEL_RELEASE}"

							create_log $KERNEL_RELEASE $HASH $HASH_ORIG $KERNELDIR
						fi
					fi
				fi
			fi

			cd ../.. # Back to $DEBIAN_DIR for next URL
		fi
	done
	
	cd .. # Back to $BASEDIR
}

mkcd "$BASEDIR"

#
# The purpose of every downloader is to download all packages required by the
# current distro in its folder, unpack them and create $BUILDER_LOG_FILENAME
# file containing the following fields and the go back to $BASEDIR
#   KERNEL_RELEASE : the name of the kernel release as it appears in the header
#                    of probe kernel module
#   HASH           : MD5 hash of kernel configuration file
#   HASH_ORIG      : required by older CoreOS distros, now equal to HASH
#   KERNELDIR      : path to the build folder relative to the $BUILDER_LOG file
#
case $1 in
	"Ubuntu" | "Fedora" | "CentOS" | "CoreOS" )
		standard_downloader "$@"
	;;

	"Debian" )
		debian_downloader "${@:2}"
	;;
esac

