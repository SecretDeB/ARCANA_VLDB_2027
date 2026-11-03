#!/bin/bash
# Usage: ./setup_AWS.sh [hexl_on|hexl_off]   (default: hexl_off, same as
# setup_wulver.sh and the local build, so AWS times compare with them;
# Graviton/ARM instances need hexl_off)
set -euo pipefail

cd "$(dirname "$0")/../../.."

HEXL_MODE="${1:-hexl_off}"
case "$HEXL_MODE" in
    hexl_on)  HEXL_FLAG=ON ;;
    hexl_off) HEXL_FLAG=OFF ;;
    *)
        echo "Usage: $0 [hexl_on|hexl_off]"
        exit 1
        ;;
esac

sudo apt-get update
sudo apt-get -y install g++
sudo apt-get -y install libssl-dev
sudo apt-get install -y build-essential autoconf libtool pkg-config
sudo apt-get -y install git   # SEAL clones Intel HEXL with git when hexl_on

pushd ~
wget https://github.com/Kitware/CMake/releases/download/v3.18.4/cmake-3.18.4.tar.gz
tar -xzvf cmake-3.18.4.tar.gz
pushd cmake-3.18.4
./bootstrap
make -j4
sudo make install
sudo ln -sf /usr/local/bin/cmake /usr/bin/cmake
popd
popd
sudo apt-get -y install clang

pushd SEAL_parallel
rm -rf build install
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$(pwd)/install -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DSEAL_USE_INTEL_HEXL=$HEXL_FLAG -DBUILD_SHARED_LIBS=OFF -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF
cmake --build build
cmake --install build
popd

pushd rpclib
rm -rf CMakeCache.txt CMakeFiles librpc.a
cmake .
make
sudo make install
popd

chmod +x ./src/scripts/bash/run_sweep_AWS.sh
