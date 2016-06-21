#!/bin/bash
function install_if_not_present(){
	brew ls | grep ${1}
	if [[ ${?} -ne 0 ]]; then
		brew install ${1}
	else
		echo "dependency ${1} already installed"
	fi
}
install_if_not_present "cmake"
install_if_not_present "luajit"
install_if_not_present "coreutils"