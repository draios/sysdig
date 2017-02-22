#!/bin/bash
sudo apt-get --force-yes install g++-4.8
sudo apt-get install rpm linux-headers-$(uname -r)
sudo apt-get purge libncurses5-dev cmake libcurl4-openssl-dev zlib1g-dev