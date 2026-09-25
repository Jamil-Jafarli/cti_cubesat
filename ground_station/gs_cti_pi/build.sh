#!/bin/sh
# Build the Phase-3 ground-station receiver on the Raspberry Pi.
# Needs: cmake, g++, liblgpio-dev; SPI enabled (raspi-config nonint do_spi 0).
set -e
cd "$(dirname "$0")"
cmake -S . -B build
cmake --build build -j4
echo "built: $(pwd)/build/gs_cti_pi"
