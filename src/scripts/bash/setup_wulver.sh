#!/bin/bash
# Usage: ./setup_wulver.sh [hexl_on|hexl_off]   (default: hexl_off)
#
# Stop on the first failing command instead of silently limping forward with
# a partial SEAL install/rpclib build (that's what produced the "undefined
# reference to seal::..." link errors last time - the SEAL build had failed
# partway through but the script kept going and installed the incomplete
# library anyway).
set -euo pipefail

cd "$(dirname "$0")/../../.."

# hexl_off is the default here (unlike setup.sh) because SEAL's
# FetchContent-driven `git clone` of Intel HEXL fails on Wulver's login node
# ("fatal: unable to create thread: Resource temporarily unavailable"), and a
# pre-clone workaround below still hit the same wall. Without HEXL, SEAL
# falls back to its default (non-AVX-512-accelerated) NTT/modular
# arithmetic - NTT still works correctly, just not vectorized by HEXL, so
# benchmark numbers here won't be directly comparable to AWS runs (which do
# build with HEXL). Pass hexl_on to retry the workaround, e.g. if the login
# node's thread limit is ever resolved or you're building on a compute node.
HEXL_MODE="${1:-hexl_off}"
case "$HEXL_MODE" in
    hexl_on)  HEXL_FLAG=ON ;;
    hexl_off) HEXL_FLAG=OFF ;;
    *)
        echo "Usage: $0 [hexl_on|hexl_off]"
        exit 1
        ;;
esac

module load GCC/14.2.0
module load CMake/3.31.3
module load OpenSSL/3

pushd SEAL_parallel

HEXL_SRC_DIR="$(pwd)/thirdparty/hexl-src"
HEXL_COMMIT=0858760 # must match cmake/ExternalIntelHEXL.cmake's GIT_TAG
HEXL_CMAKE_ARGS=()
if [ "$HEXL_FLAG" = "ON" ]; then
    if [ ! -d "$HEXL_SRC_DIR/.git" ]; then
        mkdir -p "$HEXL_SRC_DIR"
        pushd "$HEXL_SRC_DIR"
        git init -q
        git remote add origin https://github.com/intel/hexl
        git -c protocol.version=2 -c pack.threads=1 fetch --depth 1 origin "$HEXL_COMMIT"
        git checkout -q FETCH_HEAD
        popd
    fi
    HEXL_CMAKE_ARGS=(-DFETCHCONTENT_SOURCE_DIR_HEXL="$HEXL_SRC_DIR")
fi

# -DCMAKE_INSTALL_LIBDIR=lib: RHEL's GNUInstallDirs defaults to installing
# into lib64/, but src/CMakeLists.txt hardcodes SEAL_DIR to .../install/lib/
# cmake/SEAL-0.0 (matches Mac/AWS's default lib/ layout) - without this,
# find_package(SEAL) fails to locate SEALConfig.cmake on Wulver.
rm -rf build install
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$(pwd)/install -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DSEAL_USE_INTEL_HEXL=$HEXL_FLAG -DBUILD_SHARED_LIBS=OFF -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF -DSEAL_USE_ZSTD=OFF "${HEXL_CMAKE_ARGS[@]}"
cmake --build build
cmake --install build
popd

pushd rpclib
rm -rf CMakeCache.txt CMakeFiles librpc.a
cmake .
make
popd

chmod +x ./src/scripts/bash/run_sweep_wulver*.sh
