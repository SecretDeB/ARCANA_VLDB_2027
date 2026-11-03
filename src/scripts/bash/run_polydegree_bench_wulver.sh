#!/bin/bash
# Polynomial-degree benchmark on Wulver: encrypt, add and multiply two vectors of 2^15 numbers (each <= 100)
# packed into BFV polynomials of degree N = 1024 ... 32768, with the project's own SEAL (SEAL_parallel).
# Single-threaded. Run it inside an allocated node (salloc), from anywhere (paths follow the script):
#   [SEAL_INSTALL=<.../SEAL_parallel/install>] ./src/scripts/bash/run_polydegree_bench_wulver.sh [repetitions=20]
# Output: <repo>/output/results/polydegree_bench/polydegree_bench.csv (+ machine.txt with the CPU it ran on)
# Columns: add_ok / mul_ok = 1 means every decrypted slot of every repetition matched the plain sum / product.
# N=1024 cannot multiply at 128-bit security (27-bit q): its mul_ok is 0 by design.
set -e
REPS="${1:-20}"
module load GCC/14.2.0
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"   # Code/
SEAL="${SEAL_INSTALL:-$ROOT/SEAL_parallel/install}"   # SEAL_INSTALL=<dir with include/SEAL-0.0 and lib/libseal-0.0.a> to override
[ -f "$SEAL/include/SEAL-0.0/seal/seal.h" ] || { echo "no SEAL install at $SEAL - set SEAL_INSTALL=<.../SEAL_parallel/install>"; exit 1; }
OUT="$ROOT/../output/results/polydegree_bench"
mkdir -p "$OUT" "$ROOT/src/bin"
g++ -std=c++17 -O3 -I"$SEAL/include/SEAL-0.0" "$ROOT/src/scripts/miscellaneous/Benchmark_PolyDegree.cpp" \
    -L"$SEAL/lib" -lseal-0.0 -pthread -o "$ROOT/src/bin/benchmark_polydegree"
{ date; hostname; lscpu | grep -E "Model name|^CPU\(s\)|MHz"; echo "SEAL: $SEAL"; } > "$OUT/machine.txt"
OMP_NUM_THREADS=1 taskset -c 0 "$ROOT/src/bin/benchmark_polydegree" "$REPS" | tee "$OUT/polydegree_bench.csv"
echo "wrote $OUT/polydegree_bench.csv"
