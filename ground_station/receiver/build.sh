#!/bin/sh
# Build the CTI receiver on the Raspberry Pi.
# Needs cmake, g++ and liblgpio-dev, and SPI enabled (raspi-config nonint do_spi 0).
# RadioLib 7.7.1 is fetched by CMake on the first build.
set -e
cd "$(dirname "$0")"
cmake -S . -B build
cmake --build build -j4
echo "built: $(pwd)/build/cti_receiver"
