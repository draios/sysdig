#!/bin/bash
sudo apt-get --force-yes install g++-4.8
sudo apt-get install rpm linux-headers-$(uname -r) libelf-dev
sudo apt-get purge cmake
