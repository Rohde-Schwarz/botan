#!/bin/bash

# GitHub Actions setup script for Botan build
#
# (C) 2015,2017 Simon Warta
# (C) 2016,2017,2018,2020 Jack Lloyd
# (C) 2022 René Meusel, Rohde & Schwarz Cybersecurity
#
# Botan is released under the Simplified BSD License (see license.txt)

command -v shellcheck > /dev/null && shellcheck "$0" # Run shellcheck on this if available

set -ex

TARGET=$1

if type -p "apt-get"; then
    sudo apt-get -qq update
    sudo apt-get -qq install ccache
else
    export HOMEBREW_NO_AUTO_UPDATE=1
    brew install ccache
fi
