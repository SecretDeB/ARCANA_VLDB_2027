#!/bin/bash
# Thread-assignment ablation, "vertical" setup: YCSB, 2^24 keys, 256-bit keys, 2 KB values,
# skew 0.6, base 32, at 2, 4, 8, 16, 32 and 64 threads. In the equality step the server
# processes ONE key batch at a time with ALL threads working inside it (the batch's digits
# split over the threads, then the squarings of the Fermat step), then moves to the next
# batch: server -g 1 (BATCH_THREADS below). The "horizontal" setup - every thread takes its
# own batches, the server's default - is the thread ablation already run
# (run_sweep_wulver_threads_ablation.sh, output/results/threads_ablation) and is not rerun.
#   Exp 2  without data partitioning (no bucket), base 32
#   Exp 3  with data partitioning (bucket) at epsilon 25, base 32
# Results: output/results/threadmode_ablation/<RUN_TAG>.
#   RUN_TAG=exp2_vertical ./scripts/bash/run_sweep_wulver_threadmode_ablation.sh server 2   (and client 2)
# THREADS="2 4" on the command line runs only those thread counts (both roles).
# Needs ycsb_k256_n2p24_skew0.6_vmax2050_no_bucket.csv and its gamma25 bucket file.
# (copied from run_sweep_wulver_threads_ablation.sh)
#
# Merged run_sweep_server.sh + run_sweep_client.sh: same script for both
# roles, selected by the first argument, so every shared variable (mode
# flags, K_COMBOS/N_VALUES/B_VALUES/V_VALUES/T_VALUES, RESULTS_DIR, etc.)
# only needs to be edited in one place instead of kept in sync by hand
# across two files. The second argument picks which experiment's params to
# use (1, 2, or 6 - the only ones with sweep params defined in this file),
# so both the server and client process agree on the params without either
# side needing to hand-edit the file to match the other.
#
# Usage: ./run_sweep.sh server <1|2|6>   (run this in one terminal)
#        ./run_sweep.sh client <1|2|6>   (run this in another terminal)
ROLE="$1"
EXP="$2"
# Exp 1: synthetic, Exp 2: thread-assignment ablation without data partitioning (no bucket),
# Exp 3: thread-assignment ablation with data partitioning (bucket)
if [ "$ROLE" != "server" ] && [ "$ROLE" != "client" ]; then
    echo "Usage: $0 <server|client> <1|2|3>"
    exit 1
fi
if [ "$EXP" != "1" ] && [ "$EXP" != "2" ] && [ "$EXP" != "3" ]; then
    echo "Usage: $0 <server|client> <1|2|3>"
    exit 1
fi

clear
pkill -f "./bin/$ROLE" 2>/dev/null
# Also kill any other run_sweep.sh process for THIS SAME ROLE only (e.g.
# one Ctrl-Z'd and left suspended from a previous invocation) - the
# word-boundary match on "$ROLE" means a client startup can never match
# (and kill) a running server's process, or vice versa. $$ is excluded so
# this invocation doesn't kill itself.
for pid in $(pgrep -f "run_sweep\.sh[[:space:]]+$ROLE([[:space:]]|\$)" 2>/dev/null); do
    [ "$pid" != "$$" ] && kill -9 "$pid" 2>/dev/null
done
cd "$(dirname "$0")/../.."

# rm -rf build bin
# Out-of-source build: CMakeCache.txt/CMakeFiles/Makefile now live in
# build/ instead of cluttering src/ directly. Compiled executables still
# land in bin/ regardless (CMAKE_RUNTIME_OUTPUT_DIRECTORY is anchored to
# CMAKE_SOURCE_DIR in CMakeLists.txt, not to the build directory).
module load GCC/14.2.0 CMake/3.31.3 OpenSSL/3
cmake -S . -B build > /dev/null
if ! cmake --build build --target "$ROLE" -j4; then
    echo "ERROR: build failed for $ROLE - aborting instead of running a stale ./bin/$ROLE." >&2
    exit 1
fi

# ---- mode flags shared by every experiment ----
SYSTEM="ARCANA"    # tags every row so runs from different systems/setups are distinguishable in sweep_result.csv
SEEDED_SERIALIZATION=1   # -s on both: 0/1, required by server.cpp/client.cpp
FOLD_DATA=0

# NUMA-interleave wrapper for the server binary - fixes the 9-11x
# row-processing slowdown seen on Wulver's 8-NUMA-node nodes when
# query_expansion is on (expand_query() first-touches memory with 64
# threads, row processing then reads it with 32 threads from other nodes).
# Hardcoded on (not opt-in via env var) - confirmed on Wulver
# (~43s->~4.65s on the combos tested so far). Override to "" here to run
# unwrapped for comparison. Printed below so it's visible in the log which
# mode a given run actually used.
NUMA_WRAP="numactl --interleave=all"
if [ "$ROLE" = "server" ]; then
    if [ -n "$NUMA_WRAP" ]; then
        echo "NUMA_WRAP is active: $NUMA_WRAP"
    else
        echo "NUMA_WRAP is NOT set - row processing may be slow if query_expansion is on."
    fi
fi

# Resolves the uniform-dataset data file for a given key_size k - the only
# file mapping Exp 1/Exp 2 need. Exp 6 instead derives its file and params
# from each TPC-H file's own metadata header via parse_meta() below, since
# its k doesn't line up with this uniform-dataset table.
data_file_for_k() {
    case "$1" in
        24|32|40|48|56) echo "../../Python_Codes/output/data/uniform/n524288_k$1_keysonly.csv" ;;   # 2^19 keys each
        64)  echo "../../Python_Codes/output/data/uniform/n16777216_k64_keysonly.csv" ;;
        128) echo "../../Python_Codes/output/data/uniform/n16777216_k128_keysonly.csv" ;;
        192)
            if [ "$BUCKETIZATION" = "1" ]; then
                echo "../../Python_Codes/output/data/YCSB/data/bitsize_192/$SKEW/${SKEW}_bucket_contents.csv"
            else
                echo "../../Python_Codes/output/data/YCSB/data/bitsize_192/$SKEW/${SKEW}_nobucket_contents.csv"
            fi ;;
        256) echo "../../Python_Codes/output/data/uniform/n16777216_k256_keysonly.csv" ;;
        512) echo "../../Python_Codes/output/data/uniform/n16777216_k512_keysonly.csv" ;;
    esac
}

# ---- YCSB datasets (Exp 2/3) ----
# One dataset per skew, made by Python_Codes/YCSB/generate_dataset.py (no-bucket
# file) and Python_Codes/bucketization/build_buckets_from_sweep.py (one bucket
# file per gamma_bar), all in $YCSB_ROOT/keysize_<bits>/skew_<s>/:
#   ycsb_k256_n2p26_skew<s>_vmax2050_no_bucket.csv          key,$,<value size>
#   ycsb_k256_n2p26_skew<s>_vmax2050_gamma<g>_bucket.csv    bucket_id,#,!,key,$,<size>,...
# Keys are text: "user" + zero-padded digits (184-bit: 19 digits, 256-bit: 28, 512-bit: 60).
YCSB_ROOT="../../Python_Codes/output/data/YCSB"
YCSB_KEY_BITS=256   # the datasets' key size (Exp 2's base ablation loops over EXP2_KEY_SIZES)
YCSB_SKEWS=(0 0.3 0.6 0.9)
# SKEWS="0.3 0.6" on the command line runs only those skews (both roles must get the same)
[ -n "$SKEWS" ] && read -ra YCSB_SKEWS <<< "$SKEWS"
YCSB_VMAXS=(2050)   # max_value_size_bytes in the file names: 2050 = 2 KB values (+2 B for "$")
YCSB_GAMMAS=(1 5 10 15 20 25 30 35 40 45 50)
YCSB_KEYS_LOG2=26   # the datasets' key count, 2^this (Exp 2's base ablation sets 24)

# ycsb_file <skew> <vmax> <suffix>: e.g. ycsb_file 0.3 2050 no_bucket, ycsb_file 0.3 2050 gamma5_bucket
ycsb_file() {
    echo "$YCSB_ROOT/keysize_${YCSB_KEY_BITS}/skew_$1/ycsb_k${YCSB_KEY_BITS}_n2p${YCSB_KEYS_LOG2}_skew$1_vmax$2_$3.csv"
}

# header_field <file> <name>: a name=value field of the file's first line
header_field() {
    head -n1 "$1" | tr ',' '\n' | sed -n "s/^$2=//p" | head -n1
}

# The client's query key for a skew: row 1's key of its no-bucket file (the
# same key is in every gamma_bar's bucket file)
ycsb_query_key() {   # <skew> <vmax>
    sed -n 3p "$(ycsb_file "$1" "$2" no_bucket)" | cut -d, -f1
}

# Original DB size for a skew, in bytes: total_db_size_gb (GB = 2^30 bytes)
# from the no-bucket file's header - every key at 32 B + 2 B for "$" + its
# value rounded up to even
ycsb_org_db_bytes() {   # <skew> <vmax>
    header_field "$(ycsb_file "$1" "$2" no_bucket)" total_db_size_gb | awk '{ printf "%.0f", $1 * 1073741824 }'
}

# The ORIGINAL dataset each result row comes from, written as the last columns
# of server_results.csv/client_results.csv so a bucket row (whose number_of_keys/
# key_size/value_size are its bucket file's) can be paired with the no-bucket row
# of the same data: same skew + org_key_size + org_number_of_keys + org_value_size.
#   org_key_size        the dataset's key size in bits
#   org_number_of_keys  the dataset's key count (the whole file, also on Exp 2 parts)
#   org_value_size      the dataset's max_value_size_bytes
#   gamma_bar           Exp 3's gamma_bar; 0 = no bucketization
#   part                Exp 2's part of the file (1..EXP2_PARTS); 0 = the whole file
#   gamma_achieved      value_size / org_value_size: the bucket file's max bucket
#                       size over the dataset's max value size (1 without bucketization)
# Set by the Exp 2/3 loops; left unset, a combo's own n/domain_size/v and 0 are used.
ORG_COLUMNS="org_key_size,org_number_of_keys,org_value_size,gamma_bar,part,gamma_achieved"

# org_row_fields <n> <domain_size> <v>: the ORG_COLUMNS values for a combo's CSV row
org_row_fields() {
    local org_v="${ORG_VALUE_SIZE:-$3}"
    echo "${ORG_KEY_SIZE:-$2},${ORG_NUM_KEYS:-$1},$org_v,${GAMMA_BAR:-0},${PART:-0},$(awk -v v="$3" -v o="$org_v" 'BEGIN { printf "%.6f", v / o }')"
}

# set_ycsb_org <skew> <vmax>: ORG_* for that YCSB dataset, from its no-bucket header
set_ycsb_org() {
    local f
    f="$(ycsb_file "$1" "$2" no_bucket)"
    ORG_KEY_SIZE="$(header_field "$f" key_size_bits)"
    ORG_NUM_KEYS="$(header_field "$f" num_keys)"
    ORG_VALUE_SIZE="$(header_field "$f" max_value_size_bytes)"
}

# CSV header check: the results CSVs are append-only, so an existing file must
# already have this header (e.g. one from before the org_* columns were added
# can't take these rows) - use another RUN_TAG for a fresh folder instead
check_csv_header() {   # <csv> <header>
    if [ -f "$1" ] && [ "$(head -n1 "$1")" != "$2" ]; then
        echo "ERROR: $1 has a different header (older columns). Move it away or set RUN_TAG=<new folder>."
        exit 1
    fi
}

# Exp 2 runs each no-bucket file in EXP2_PARTS equal parts over its rows (the
# whole 2^26-row file needs more server RAM than one node has); part i is
# saved once as <file>_part<i>.csv with the file's two header lines and
# reused after. ycsb_part_file <full> <i> names it.
ycsb_part_file() {
    echo "${1%.csv}_part$2.csv"
}

# exp2_data_file <full> <i>: the file part i runs on - the full file itself when
# EXP2_PARTS is 1 (no part file written)
exp2_data_file() {
    if [ "$EXP2_PARTS" = "1" ]; then echo "$1"; else ycsb_part_file "$1" "$2"; fi
}

# set_large_pm <key bits> <base>: LARGE_PLAIN_MODULUS (-l on both server and
# client) for that combo, from the non-unary equality's largest sum, digits x
# (base - 1)^2 (digits = ceil(bits / log2 base), base a power of 2): 0 below
# p = 65537, 1 below the large p = 786433 (helper.hpp's LARGE_PLAIN_MODULUS);
# returns 1 (skip the combo) when even the large p is too small.
PLAIN_MODULUS=65537
LARGE_PLAIN_MODULUS_VALUE=786433
set_large_pm() {
    local bits=$1 b=$2 lg=0 x=$2 digits sum
    while [ "$x" -gt 1 ]; do x=$((x / 2)); lg=$((lg + 1)); done
    digits=$(( (bits + lg - 1) / lg ))
    sum=$(( digits * (b - 1) * (b - 1) ))
    LARGE_PLAIN_MODULUS=0
    [ "$sum" -ge "$PLAIN_MODULUS" ] && LARGE_PLAIN_MODULUS=1
    [ "$sum" -lt "$LARGE_PLAIN_MODULUS_VALUE" ]
}

# make_ycsb_parts <full> <rows per part>: writes the missing part files
make_ycsb_parts() {
    local full=$1 count=$2 i part start
    for i in $(seq 1 "$EXP2_PARTS"); do
        part="$(ycsb_part_file "$full" "$i")"
        start=$(( (i - 1) * count ))
        if [ ! -f "$part" ]; then
            echo "Writing $part (data rows $start to $((start + count - 1)))"
            awk -v s="$start" -v n="$count" 'NR <= 2 { print; next } NR - 3 >= s + n { exit } NR - 3 >= s { print }' "$full" > "$part"
        fi
    done
}

# ---- per-experiment params ----
# K_COMBOS bundles key_size, domain_size, and selected_bit together as ONE
# entity per entry ("k:domain_size:selected_bit") instead of three separate
# arrays - domain_size and selected_bit are only meaningful paired with a
# specific k, so looping them independently against unrelated k values
# would build nonsensical queries. selected_bit is left empty for
# non-bucketization entries (unused there).
# set_exp_params <exp> sets that experiment's params.
set_exp_params() {
case "$1" in
    1)
        # ---- Exp 1: synthetic values (uniform keys-only file) ----
        # needs synthetic_values = true in helper.hpp, and the client's
        # synthetic key + client/expected_row_synthetic.csv
        UNARY_ENCODING=0
        QUERY_EXPANSION=1
        PIR_COMPRESSION=1
        NUM_RUNS=3
        BUCKETIZATION=0
        N_VALUES=($((2**22)))
        B_VALUES=(2)
        V_VALUES=($((2**12)))
        T_VALUES=(1 2 4 8 16 32 64 96 128 )
        K_COMBOS=(
            "64:64:"
        )
        # skip any (N, k, V) whose original DB (org_db_bytes) is over this many
        # GB - keeps N*V <= 2^36, 60 of the 100 combos
        MAX_ORG_DB_GB=100
        ;;
    2)
        # ---- Exp 2: thread ablation, YCSB no bucket, base 32 (2^24 keys, one run each) ----
        # ycsb_k256_n2p<n>_skew0.6_vmax2050_no_bucket.csv for each n in
        # KEYS_LOG2_VALUES, base 32 (the base ablation's best for 256-bit keys, on
        # the default plaintext modulus); -v is the header's max_value_size_bytes.
        # A file runs whole, or - from 2^KEYS_TWO_PARTS_FROM keys on, whose PIR
        # database is more than one node holds (~550 GB at 2^26) - in 2 equal row
        # parts, as the baseline comparison did (full-file equality/PIR time = the
        # sum over the parts). needs synthetic_values = false in helper.hpp; the
        # client gets row 1's key (-q) and client/expected_row_ycsb_nobucket.csv
        UNARY_ENCODING=0
        QUERY_EXPANSION=1
        PIR_COMPRESSION=1
        NUM_RUNS=3
        BUCKETIZATION=0
        KEYS_LOG2_VALUES=(24)
        KEYS_TWO_PARTS_FROM=26
        YCSB_SKEWS=(0.6)
        YCSB_VMAXS=(2050)
        EXP2_KEY_SIZES=(256)
        B_VALUES=(32)
        T_VALUES=(2 4 8 16 32 64)
        ;;
    3)
        # ---- Exp 3: thread ablation, YCSB with data partitioning (bucket), 2^24 keys ----
        # at the epsilon ablation's best epsilon (25) and the bucket base
        # ablation's best base (32): ycsb_k256_n2p<n>_skew0.6_vmax2050_gamma25_bucket.csv
        # for each n in KEYS_LOG2_VALUES. The file's header gives the run's -n (num_buckets), -k
        # (key_size = the bucket id's 19 bits), -v (max_bucket_size_bytes), -o
        # (key_size_org) and -a (selected_bit) - see the Exp 3 loops. The file
        # stores bucket ids as base-2 bits; the server and client write them as
        # base-b digits (key_text_to_digits / extract_query_digits_from_digits).
        # -l is set per base from the bucket id's bits, as in Exp 2 (set_large_pm):
        # the ids here (about 17-22 bits) fit the default plaintext modulus. needs
        # synthetic_values = false in helper.hpp; the client gets row 1's key
        # (-q) and client/expected_row_ycsb_bucket.csv
        UNARY_ENCODING=0
        QUERY_EXPANSION=1
        PIR_COMPRESSION=1
        NUM_RUNS=3
        BUCKETIZATION=1
        KEYS_LOG2_VALUES=(24)
        YCSB_KEY_BITS=256
        YCSB_SKEWS=(0.6)
        YCSB_VMAXS=(2050)
        YCSB_GAMMAS=(25)   # the best epsilon of the epsilon ablation
        B_VALUES=(32)      # the best base of the bucket base ablation
        T_VALUES=(2 4 8 16 32 64)
        ;;
esac
}

# Size of the ORIGINAL data (before PIR encoding), in bytes, for a combo:
#   Exp 1 (synthetic): N * (domain_size/8 + V)
#   Exp 2/3 (YCSB): YCSB_ORG_DB_BYTES, set per skew from the no-bucket header
#                   (ycsb_org_db_bytes) - the whole dataset, also on each Exp 2 part
# org_db_too_big <n> <domain_size> <v>: true (skip the combo) when the
# experiment sets MAX_ORG_DB_GB and this combo's original DB is over it
org_db_too_big() {
    [ -n "$MAX_ORG_DB_GB" ] && [ "$(org_db_bytes "$1" "$2" "$3")" -gt $((MAX_ORG_DB_GB * 1000000000)) ]
}

# org_db_bytes <n> <domain_size> <v>
org_db_bytes() {
    case "$EXP" in
        1) echo $(( $1 * ($2 / 8 + $3) )) ;;
        2|3) echo "$YCSB_ORG_DB_BYTES" ;;
    esac
}

# Parses a data distribution file's metadata header line into META_* globals
# (KEY_SIZE_ORG/KEY_SIZE/NUM_DISTINCT_KEYS/MAX_BUCKET_SIZE/SELECTED_BIT) -
# selected_bit=[...] is always the last field and is the only one that can
# contain internal commas, so it's peeled off first (between the first "["
# and the following "]") and everything before it is safe to split on ','.
# Used by Exp 3 (and Exp 6).
parse_meta() {
    local file="$1"
    local header
    header=$(head -n1 "$file")
    local before_sel="${header%%selected_bit=*}"
    local after_sel="${header#*selected_bit=}"
    META_SELECTED_BIT="${after_sel#\[}"
    META_SELECTED_BIT="${META_SELECTED_BIT%%\]*}"
    META_SELECTED_BIT="$(echo "$META_SELECTED_BIT" | tr -d ' ')"
    META_KEY_SIZE_ORG=""
    META_KEY_SIZE=""
    META_NUM_BUCKETS=""
    META_MAX_BUCKET_SIZE=""
    local kv
    local old_ifs="$IFS"
    IFS=','
    for kv in $before_sel; do
        case "$kv" in
            key_size_org=*) META_KEY_SIZE_ORG="${kv#key_size_org=}" ;;
            key_size=*) META_KEY_SIZE="${kv#key_size=}" ;;
            num_buckets=*) META_NUM_BUCKETS="${kv#num_buckets=}" ;;
            max_bucket_size=*) META_MAX_BUCKET_SIZE="${kv#max_bucket_size=}" ;;
            max_bucket_size_bytes=*) META_MAX_BUCKET_SIZE="${kv#max_bucket_size_bytes=}" ;;   # YCSB bucket files (already in bytes)
        esac
    done
    IFS="$old_ifs"
    if [ -z "$META_KEY_SIZE" ] || [ -z "$META_NUM_BUCKETS" ] || [ -z "$META_MAX_BUCKET_SIZE" ]; then
        echo "ERROR: failed to parse metadata header in $file: $header"
        exit 1
    fi
}

set_exp_params "$EXP"
# key batches processed at once in the equality step (server -g): 1 = vertical, 0 = the
# server's default (horizontal). Only the server takes it.
BATCH_THREADS="${BATCH_THREADS:-1}"
[ -n "$THREADS" ] && read -ra T_VALUES <<< "$THREADS"
# BASES="2" on the command line runs that base (default 32, the base ablation's best); both roles
[ -n "$BASES" ] && read -ra B_VALUES <<< "$BASES"

# Caps a combo's value_size (bytes) at 32768 regardless of what the file's
# max_bucket_size actually is - skew 0.6/0.8's true max_bucket_size (36578/
# 199916) would otherwise drive pir_num_columns_per_obj into the thousands,
# so this trades completeness (wider buckets get truncated, same as
# FOLD_DATA's truncation elsewhere) for a bounded, always-runnable combo.
# Only used by Exp 6.
EXP6_MAX_VALUE_SIZE=32768
cap_value_size() {
    local raw="$1"
    if [ "$raw" -gt "$EXP6_MAX_VALUE_SIZE" ]; then
        echo "$EXP6_MAX_VALUE_SIZE"
    else
        echo "$raw"
    fi
}

RESULTS_DIR="../../output/results/threadmode_ablation"
mkdir -p "$RESULTS_DIR"
# Fixed folder (output/results/arcana), not a timestamp: the server and
# client roles always write into the same RUN_DIR without having to share a
# tag, and every invocation lands in the same place - the logs and result
# CSVs are append-only, so results across separate runs accumulate here
# instead of scattering into a new folder each time.
# Set RUN_TAG explicitly beforehand to write into a different folder.
RUN_TAG="${RUN_TAG:-arcana}"
RUN_DIR="$RESULTS_DIR/${RUN_TAG}"
mkdir -p "$RUN_DIR"

extract() {
    # extract <file> <label>: prefer the program's own pre-computed
    # "Average <label>...: X" summary line when one exists - that's the
    # codebase's trimmed-mean average() (drops the single highest/lowest
    # of the NUM_RUNS samples), not a plain mean, so re-deriving it here
    # by averaging the raw per-round lines would give a different (and
    # less outlier-resistant) number than what the program itself reports.
    # Falls back to a plain average across every matching per-round line
    # only for labels the program doesn't separately average (e.g. sizes).
    local avg_line val
    avg_line=$(grep -a "^Average .*$2" "$1" 2>/dev/null | tail -1)
    if [ -n "$avg_line" ]; then
        val=$(echo "$avg_line" | awk '{
            v = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^-?[0-9.]+$/) v = $i
            }
            print v
        }')
        [ -n "$val" ] && printf "%.6f" "$val"
        return
    fi
    grep -a "$2" "$1" 2>/dev/null | grep -v "^Average " | awk '{
        val = ""
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^-?[0-9.]+$/) val = $i
        }
        if (val != "") { sum += val; n++ }
    } END { if (n > 0) printf "%.6f", sum/n }'
}

if [ "$ROLE" = "server" ]; then
    # RUN_DIR is reused across restarts (it's a fixed folder, see above)
    # but every sweep here always restarts from the first combo rather than
    # actually resuming - so a leftover .server_ready_<tag> from a previous,
    # now-dead server would otherwise tell the client "combo <tag> is ready"
    # before the fresh server for that combo has even started. Wipe this
    # role's own marker namespace once at startup so only markers this run
    # actually writes exist.
    rm -f "$RUN_DIR"/.server_ready_*
    SERVER_LOG="$RUN_DIR/server.log"
    SERVER_CSV="$RUN_DIR/server_results.csv"
    # Only write the header for a brand-new file - appending (not
    # truncating) lets re-running against the same RUN_DIR/path accumulate
    # rows instead of wiping out previously-collected data.
    SERVER_HEADER="system,query_expansion,pir_compression,fold,unary_encoding,bucketization,skew,number_of_threads,base,number_of_keys,key_size,value_size,populate_time_s,query_expansion_time_s,equality_time_s,equality_time_e2c*/e2e+,equality_time_e2e*_s,pir_time_s,org_db_GB,db_GB,db_sum_GB,pir_db_GB,$ORG_COLUMNS"
    check_csv_header "$SERVER_CSV" "$SERVER_HEADER"
    if [ ! -f "$SERVER_CSV" ]; then
        echo "$SERVER_HEADER" > "$SERVER_CSV"
    fi

    # bucket/skew/data_file are explicit per-combo args (not a global
    # $BUCKETIZATION lookup) so the same runner works for Exp 1/Exp 2
    # (skew="", bucket/data_file fixed per sweep) and Exp 6 (skew swept,
    # bucket/data_file resolved per skew from each TPC-H file's metadata).
    run_server_combo() {
        local n=$1 k=$2 b=$3 v=$4 t=$5 domain_size=$6 selected_bit=$7 bucket=$8 data_file=$9 skew=${10}
        # Tag matches the client's tag exactly so the two processes can hand
        # off per-combo marker files by the same name. Omits the skew/
        # bucket prefix when there's no skew (Exp 1/Exp 2), matching their
        # original tag format.
        local tag
        if [ -n "$skew" ]; then
            tag="skew${skew}_d${bucket}_n${n}_k${k}_b${b}_v${v}_t${t}_g${GAMMA_BAR:-0}_p${PART:-0}"   # key count/gamma_bar/part keep YCSB runs' tags unique
        else
            tag="k${k}_b${b}_v${v}_t${t}"
        fi
        echo "Running server for $tag"
        echo "===== $tag =====" >> "$SERVER_LOG"
        local args=(-n "$n" -k "$k" -b "$b" -v "$v" -t "$t" -u "$UNARY_ENCODING" -r "$NUM_RUNS" -s "$SEEDED_SERIALIZATION" -d "$bucket" -e "$FOLD_DATA" -c "$PIR_COMPRESSION" -y "$QUERY_EXPANSION" -l "${LARGE_PLAIN_MODULUS:-0}" -g "$BATCH_THREADS")
        if [ "$bucket" = "1" ]; then
            args+=(-o "$domain_size" -a "$selected_bit")
        fi
        if [ -n "$data_file" ] && [ -f "$data_file" ]; then
            args+=(-f "$data_file")
        else
            echo "ERROR: no data file for $tag (expected $data_file)"
            return 1
        fi
        # tmp_log holds just this combo's output so extract() below only
        # averages over this combo's NUM_RUNS - full output is also streamed
        # live into SERVER_LOG (see tail -f below) as it's written, then
        # tmp_log itself is discarded.
        local tmp_log
        tmp_log=$(mktemp)
        rm -f "$RUN_DIR/.server_ready_${tag}"
        # Backgrounded (not a foreground `| tee`) so this function can poll
        # tmp_log for the "Listening on port" line and only then touch
        # .server_ready_<tag> - a plain "is port 8080 open" probe (the old
        # wait_for_server_port) can match a *different*, about-to-exit
        # combo's listener and let the client start talking to the wrong
        # combo's server - the actual cause of the input-stream-ended-
        # unexpectedly crash: client and server silently drifting onto
        # different combos.
        # done_marker is touched by the subshell the instant ./bin/server
        # exits - exit detection below polls for THIS FILE, not the
        # process's PID. Originally this polled `kill -0 "$server_pid"`,
        # but on a machine that's spawned/killed as many processes as this
        # one has, a dead server's PID number can get recycled by some
        # unrelated live process before the poll notices - kill -0 then
        # (correctly, but misleadingly) reports "still alive" forever,
        # hanging the script right here with server_results.csv never
        # getting its data row. A PID is inherently reusable; a fresh temp
        # file is not.
        local done_marker
        done_marker=$(mktemp)
        rm -f "$done_marker"
        ( $NUMA_WRAP ./bin/server "${args[@]}" > "$tmp_log" 2>&1; touch "$done_marker" ) &
        local server_pid=$!
        # Streams tmp_log both to the console (tee's default stdout
        # passthrough) and into SERVER_LOG live as it's written, instead of
        # only appending to the file once the combo finishes - a slow combo
        # (e.g. a big key_size) could otherwise leave the terminal and
        # SERVER_LOG both looking frozen for minutes at a time even though
        # the server is actively working.
        tail -f -n +1 "$tmp_log" | tee -a "$SERVER_LOG" &
        local tail_pid=$!

        local waited=0
        while ! grep -q "Listening on port" "$tmp_log" 2>/dev/null; do
            if [ -f "$done_marker" ]; then
                echo "WARNING: server for $tag exited before it started listening"
                break
            fi
            sleep 0.2
            waited=$((waited + 1))
            if [ "$waited" -ge 300 ]; then
                echo "WARNING: server for $tag never reported listening after 60s - signalling ready anyway"
                break
            fi
        done
        touch "$RUN_DIR/.server_ready_${tag}"

        while [ ! -f "$done_marker" ]; do
            sleep 0.2
        done
        rm -f "$done_marker"
        sleep 0.3   # let the tail -f catch up on the last lines before it's killed
        kill "$tail_pid" 2>/dev/null
        disown "$tail_pid" 2>/dev/null

        local populate_time query_expansion_time equality_time pir_processing equality_e2c_e2e_time equality_e2e_mult_time
        populate_time=$(extract "$tmp_log" "Database populated in")
        query_expansion_time=$(extract "$tmp_log" "Query expansion time")
        equality_time=$(extract "$tmp_log" "Row processing wall time")
        pir_processing=$(extract "$tmp_log" "PIR processing wall time")
        # Same label text regardless of unary_encoding (see server.cpp's
        # Averages block), so this works for either mode without branching
        # here.
        equality_e2c_e2e_time=$(extract "$tmp_log" "e2c\*/e2e+ computation time")
        equality_e2e_mult_time=$(extract "$tmp_log" "e2e\* computation time")
        # database sizes from the populate functions' [DIAG] lines (MB -> GB)
        local db_gb db_sum_gb pir_db_gb
        db_gb=$(extract "$tmp_log" "\[DIAG\] db:" | awk '{ if ($1 != "") printf "%.6f", $1 / 1000 }')
        db_sum_gb=$(extract "$tmp_log" "\[DIAG\] db_sum:" | awk '{ if ($1 != "") printf "%.6f", $1 / 1000 }')
        pir_db_gb=$(extract "$tmp_log" "\[DIAG\] pir_encoded_db:" | awk '{ if ($1 != "") printf "%.6f", $1 / 1000 }')
        # original data size (see org_db_bytes), bytes -> GB
        local org_db_gb
        org_db_gb=$(awk -v bytes="$(org_db_bytes "$n" "$domain_size" "$v")" 'BEGIN { if (bytes != "") printf "%.6f", bytes / 1e9 }')
        rm -f "$tmp_log"

        # skew is "" for Exp 1/Exp 2 (no skew concept there) - only the tag
        # naming above cares about that distinction ([ -n "$skew" ]);
        # displayed in the CSV as 0 instead of blank.
        echo "$SYSTEM,$QUERY_EXPANSION,$PIR_COMPRESSION,$FOLD_DATA,$UNARY_ENCODING,$bucket,${skew:-0},$t,$b,$n,$k,$v,$populate_time,$query_expansion_time,$equality_time,$equality_e2c_e2e_time,$equality_e2e_mult_time,$pir_processing,$org_db_gb,$db_gb,$db_sum_gb,$pir_db_gb,$(org_row_fields "$n" "$domain_size" "$v")" >> "$SERVER_CSV"

        # Don't start the NEXT combo's server until this combo's client has
        # actually finished - no shared filesystem to check a marker file
        # across separate machines, so a fixed delay is the simplest thing
        # that works regardless of topology, giving the client time to
        # finish its last round (query send, wait for PIR, result transfer,
        # decode) before the next combo's server takes over the port.
        sleep 5
    }

    if [ "$EXP" = "6" ]; then
        for skew in "${EXP6_SKEW_VALUES[@]}"; do
            # ---- bucketization combo for this skew ----
            if [ "$EXP6_RUN_BUCKET" = "1" ]; then
                bucket_file="$EXP6_TPCH_DIR/$skew/${skew}_base_${EXP6_BASE}_bucket_contents.csv"
                parse_meta "$bucket_file"
                v="$(cap_value_size "$META_MAX_BUCKET_SIZE")"
                run_server_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$EXP6_BASE" "$v" "$EXP6_THREADS" "$META_KEY_SIZE_ORG" "$META_SELECTED_BIT" 1 "$bucket_file" "$skew"
            fi

            # ---- non-bucketization combo for this skew ----
            if [ "$EXP6_RUN_NOBUCKET" = "1" ]; then
                nobucket_file="$EXP6_TPCH_DIR/$skew/${skew}_nobucket_contents.csv"
                parse_meta "$nobucket_file"
                v="$(cap_value_size "$META_MAX_BUCKET_SIZE")"
                run_server_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$EXP6_BASE" "$v" "$EXP6_THREADS" "" "" 0 "$nobucket_file" "$skew"
            fi
        done
    elif [ "$EXP" = "2" ]; then
      # one pass per key count (2^n keys)
      for YCSB_KEYS_LOG2 in "${KEYS_LOG2_VALUES[@]}"; do
        EXP2_KEYS=$((2 ** YCSB_KEYS_LOG2))
        if [ "$YCSB_KEYS_LOG2" -ge "$KEYS_TWO_PARTS_FROM" ]; then EXP2_PARTS=2; else EXP2_PARTS=1; fi
        # per (key size, skew, value size, base): the no-bucket file in EXP2_PARTS
        # row ranges (or whole, when EXP2_PARTS is 1), one combo each
        part_rows=$((EXP2_KEYS / EXP2_PARTS))
        for YCSB_KEY_BITS in "${EXP2_KEY_SIZES[@]}"; do
          for skew in "${YCSB_SKEWS[@]}"; do
            for vmax in "${YCSB_VMAXS[@]}"; do
                full="$(ycsb_file "$skew" "$vmax" no_bucket)"
                [ "$EXP2_PARTS" != "1" ] && make_ycsb_parts "$full" "$part_rows"
                set_ycsb_org "$skew" "$vmax"
                YCSB_ORG_DB_BYTES="$(ycsb_org_db_bytes "$skew" "$vmax")"
                GAMMA_BAR=0
                for b in "${B_VALUES[@]}"; do
                    if ! set_large_pm "$YCSB_KEY_BITS" "$b"; then
                        echo "===== skipping ${YCSB_KEY_BITS}-bit base $b: its equality sum is too big even for the large plaintext modulus =====" | tee -a "$SERVER_LOG"
                        continue
                    fi
                    for i in $(seq 1 "$EXP2_PARTS"); do
                        if [ "$EXP2_PARTS" = "1" ]; then PART=0; else PART=$i; fi
                        part="$(exp2_data_file "$full" "$i")"
                        echo "===== ${YCSB_KEY_BITS}-bit skew=$skew vmax=$vmax base=$b (-l $LARGE_PLAIN_MODULUS) part $i/$EXP2_PARTS: $part =====" | tee -a "$SERVER_LOG"
                        for t in "${T_VALUES[@]}"; do
                            run_server_combo "$part_rows" "$YCSB_KEY_BITS" "$b" "$ORG_VALUE_SIZE" "$t" "$YCSB_KEY_BITS" "" 0 "$part" "$skew"
                        done
                    done
                    # the full file's equality and PIR time = the sum over its parts
                    # (the last EXP2_PARTS x |T_VALUES| rows of SERVER_CSV)
                    tail -n "$((EXP2_PARTS * ${#T_VALUES[@]}))" "$SERVER_CSV" | awk -F, -v s="$skew" -v m="$vmax" -v b="$b" -v k="$YCSB_KEY_BITS" '{ eq += $15; pir += $18; n += $10 } END {
                        printf "Exp 2 %s-bit skew %s vmax %s base %s total over %d parts (%d keys): equality %.6f s, PIR %.6f s\n", k, s, m, b, NR, n, eq, pir }' | tee -a "$SERVER_LOG"
                done
            done
          done
        done
      done
    elif [ "$EXP" = "3" ]; then
      # one pass per key count (2^n keys)
      for YCSB_KEYS_LOG2 in "${KEYS_LOG2_VALUES[@]}"; do
        # per (skew, value size, gamma_bar), one combo per base, every parameter from the file's header
        PART=0
        for skew in "${YCSB_SKEWS[@]}"; do
            for vmax in "${YCSB_VMAXS[@]}"; do
                set_ycsb_org "$skew" "$vmax"
                YCSB_ORG_DB_BYTES="$(ycsb_org_db_bytes "$skew" "$vmax")"
                for g in "${YCSB_GAMMAS[@]}"; do
                    GAMMA_BAR=$g
                    gamma_file="$(ycsb_file "$skew" "$vmax" "gamma${g}_bucket")"
                    parse_meta "$gamma_file"
                    for b in "${B_VALUES[@]}"; do
                        if ! set_large_pm "$META_KEY_SIZE" "$b"; then
                            echo "===== skipping ${META_KEY_SIZE}-bit bucket ids in base $b: equality sum too big even for the large plaintext modulus =====" | tee -a "$SERVER_LOG"
                            continue
                        fi
                        echo "===== skew=$skew vmax=$vmax gamma_bar=$g base=$b (-l $LARGE_PLAIN_MODULUS): $gamma_file =====" | tee -a "$SERVER_LOG"
                        for t in "${T_VALUES[@]}"; do
                            run_server_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$b" "$META_MAX_BUCKET_SIZE" "$t" "$META_KEY_SIZE_ORG" "$META_SELECTED_BIT" 1 "$gamma_file" "$skew"
                        done
                    done
                done
            done
        done
      done
    else
        for n in "${N_VALUES[@]}"; do
            for k_combo in "${K_COMBOS[@]}"; do
                IFS=':' read -r k domain_size selected_bit <<< "$k_combo"
                data_file="$(data_file_for_k "$domain_size")"   # second field of the combo: the key's real size (= k without bucketization)
                for b in "${B_VALUES[@]}"; do
                    for v in "${V_VALUES[@]}"; do
                        org_db_too_big "$n" "$domain_size" "$v" && continue   # same check as the client loop
                        for t in "${T_VALUES[@]}"; do
                            run_server_combo "$n" "$k" "$b" "$v" "$t" "$domain_size" "$selected_bit" "$BUCKETIZATION" "$data_file" "$SKEW"
                        done
                    done
                done
            done
        done
    fi

    echo "Done. Log: $SERVER_LOG (CSV: $SERVER_CSV)"

    # Whichever of server/client finishes ALL its combos second is the one
    # that finds the other's marker already there - that one (and only that
    # one) triggers the merge, so it only runs once both sides have
    # actually stopped, regardless of which finishes first.
    touch "$RUN_DIR/.server_done"
    if [ -f "$RUN_DIR/.client_done" ]; then
        python3 scripts/python/merge_sweep_results.py "$RUN_DIR"
    fi

else # ROLE = client
    rm -f "$RUN_DIR"/.client_done_*
    CLIENT_LOG="$RUN_DIR/client.log"
    CLIENT_CSV="$RUN_DIR/client_results.csv"
    # Only write the header for a brand-new file - see the matching comment
    # on SERVER_CSV above.
    CLIENT_HEADER="system,query_expansion,pir_compression,fold,unary_encoding,bucketization,skew,number_of_threads,base,number_of_keys,key_size,value_size,query_size_MB,query_gen_time_s,query_send_time_s,result_size_MB,result_send_time_s,result_decode_time_s,sanity_correct,$ORG_COLUMNS"
    check_csv_header "$CLIENT_CSV" "$CLIENT_HEADER"
    if [ ! -f "$CLIENT_CSV" ]; then
        echo "$CLIENT_HEADER" > "$CLIENT_CSV"
    fi

    # bucket/skew are explicit per-combo args (see the matching comment on
    # run_server_combo) - client doesn't take a data file at all (client.cpp
    # has no -f option; it derives its query purely from -n/-k/-b/-v/-o/-a).
    run_client_combo() {
        local n=$1 k=$2 b=$3 t=$4 v=$5 domain_size=$6 selected_bit=$7 bucket=$8 skew=$9
        local tag
        if [ -n "$skew" ]; then
            tag="skew${skew}_d${bucket}_n${n}_k${k}_b${b}_v${v}_t${t}_g${GAMMA_BAR:-0}_p${PART:-0}"   # key count/gamma_bar/part keep YCSB runs' tags unique
        else
            tag="k${k}_b${b}_v${v}_t${t}"
        fi
        echo "Running client for $tag"
        rm -f "$RUN_DIR/.client_done_${tag}"
        # Wait until the server for THIS combo is listening - both roles run on
        # the same Wulver node and RUN_DIR, so its .server_ready_<tag> marker is
        # visible here. A fixed sleep isn't enough: loading a 2^26-key database or
        # writing Exp 2's part files takes minutes, and a client that starts early
        # fails (empty row) and then stays one combo ahead of the server.
        local ready_wait=0
        while [ ! -f "$RUN_DIR/.server_ready_${tag}" ]; do
            [ $((ready_wait % 60)) -eq 0 ] && echo "Waiting for the server of $tag ..."
            sleep 1
            ready_wait=$((ready_wait + 1))
        done
        echo "===== $tag =====" >> "$CLIENT_LOG"
        # tmp_log holds just this combo's output so extract() below only
        # averages over this combo's NUM_RUNS - full output still lands in
        # CLIENT_LOG (appended) right after, then tmp_log is discarded.
        local tmp_log
        tmp_log=$(mktemp)
        local args=(-n "$n" -k "$k" -b "$b" -t "$t" -v "$v" -u "$UNARY_ENCODING" -r "$NUM_RUNS" -s "$SEEDED_SERIALIZATION" -d "$bucket" -e "$FOLD_DATA" -c "$PIR_COMPRESSION" -y "$QUERY_EXPANSION" -l "${LARGE_PLAIN_MODULUS:-0}")
        if [ "$bucket" = "1" ]; then
            args+=(-a "$selected_bit" -o "$domain_size")
        fi
        if [ -n "$QUERY_KEY" ]; then
            args+=(-q "$QUERY_KEY")   # YCSB (Exp 2/3): row 1's key of the skew's no-bucket file
        fi
        ./bin/client "${args[@]}" 2>&1 | tee -a "$tmp_log" "$CLIENT_LOG"

        local query_gen_time query_size query_send_time result_size result_send_time result_decode_time
        query_gen_time=$(extract "$tmp_log" "Query generation time")
        query_size=$(extract "$tmp_log" "Query size (MByte)")
        query_send_time=$(extract "$tmp_log" "Query send time")
        result_size=$(extract "$tmp_log" "Result size (MByte)")
        result_send_time=$(extract "$tmp_log" "Result send time")
        result_decode_time=$(extract "$tmp_log" "Result decode time")
        # "Sanity check: 10 of 10 run(s) correct" -> 10/10
        local sanity_correct
        sanity_correct=$(grep -a "^Sanity check: [0-9]* of [0-9]* run(s) correct" "$tmp_log" | tail -1 | awk '{ print $3 "/" $5 }')
        rm -f "$tmp_log"

        # skew is "" for Exp 1/Exp 2 (no skew concept there) - only the tag
        # naming above cares about that distinction ([ -n "$skew" ]);
        # displayed in the CSV as 0 instead of blank.
        echo "$SYSTEM,$QUERY_EXPANSION,$PIR_COMPRESSION,$FOLD_DATA,$UNARY_ENCODING,$bucket,${skew:-0},$t,$b,$n,$k,$v,$query_size,$query_gen_time,$query_send_time,$result_size,$result_send_time,$result_decode_time,$sanity_correct,$(org_row_fields "$n" "$domain_size" "$v")" >> "$CLIENT_CSV"
        # Acknowledges this combo is fully done so the server role knows
        # it's safe to move on to the next combo's server.
        touch "$RUN_DIR/.client_done_${tag}"
        # No shared filesystem between client/server when they run on
        # separate machines, so marker-file polling (wait_for_server_ready)
        # can never work there - a fixed delay after finishing this combo is
        # the simplest thing that works regardless of topology, giving the
        # next combo's server time to build, init SEAL, and populate_db
        # before this loop tries to connect to it.
        sleep 10
    }

    if [ "$EXP" = "6" ]; then
        for skew in "${EXP6_SKEW_VALUES[@]}"; do
            # ---- bucketization combo for this skew ----
            if [ "$EXP6_RUN_BUCKET" = "1" ]; then
                bucket_file="$EXP6_TPCH_DIR/$skew/${skew}_base_${EXP6_BASE}_bucket_contents.csv"
                parse_meta "$bucket_file"
                v="$(cap_value_size "$META_MAX_BUCKET_SIZE")"
                run_client_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$EXP6_BASE" "$EXP6_THREADS" "$v" "$META_KEY_SIZE_ORG" "$META_SELECTED_BIT" 1 "$skew"
            fi

            # ---- non-bucketization combo for this skew ----
            if [ "$EXP6_RUN_NOBUCKET" = "1" ]; then
                nobucket_file="$EXP6_TPCH_DIR/$skew/${skew}_nobucket_contents.csv"
                parse_meta "$nobucket_file"
                v="$(cap_value_size "$META_MAX_BUCKET_SIZE")"
                run_client_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$EXP6_BASE" "$EXP6_THREADS" "$v" "" "" 0 "$skew"
            fi
        done
    elif [ "$EXP" = "2" ]; then
      # one pass per key count (2^n keys)
      for YCSB_KEYS_LOG2 in "${KEYS_LOG2_VALUES[@]}"; do
        EXP2_KEYS=$((2 ** YCSB_KEYS_LOG2))
        if [ "$YCSB_KEYS_LOG2" -ge "$KEYS_TWO_PARTS_FROM" ]; then EXP2_PARTS=2; else EXP2_PARTS=1; fi
        # same key sizes, skews, value sizes, bases (and skipped combos) and parts as the server loop
        part_rows=$((EXP2_KEYS / EXP2_PARTS))
        for YCSB_KEY_BITS in "${EXP2_KEY_SIZES[@]}"; do
          for skew in "${YCSB_SKEWS[@]}"; do
            for vmax in "${YCSB_VMAXS[@]}"; do
                full="$(ycsb_file "$skew" "$vmax" no_bucket)"
                set_ycsb_org "$skew" "$vmax"
                QUERY_KEY="$(ycsb_query_key "$skew" "$vmax")"
                GAMMA_BAR=0
                # the sanity check's expected row: row 1 of the no-bucket file, made
                # once with make_expected_row.py (1000000 so a long value isn't cut
                # off), then copied to the file name the client reads; named by the
                # key size and count too, since those files of a skew differ
                exp_row="client/expected_row_ycsb_nobucket_k${YCSB_KEY_BITS}_n2p${YCSB_KEYS_LOG2}_skew${skew}_vmax${vmax}.csv"
                if [ ! -f "$exp_row" ]; then
                    python3 scripts/python/make_expected_row.py "$full" "$QUERY_KEY" "$exp_row" 0 1000000 \
                        || echo "WARNING: could not make $exp_row"
                fi
                cp "$exp_row" client/expected_row_ycsb_nobucket.csv
                for b in "${B_VALUES[@]}"; do
                    if ! set_large_pm "$YCSB_KEY_BITS" "$b"; then
                        echo "===== skipping ${YCSB_KEY_BITS}-bit base $b (as the server does) =====" | tee -a "$CLIENT_LOG"
                        continue
                    fi
                    for i in $(seq 1 "$EXP2_PARTS"); do
                        if [ "$EXP2_PARTS" = "1" ]; then PART=0; else PART=$i; fi
                        echo "===== ${YCSB_KEY_BITS}-bit skew=$skew vmax=$vmax base=$b (-l $LARGE_PLAIN_MODULUS) part $i/$EXP2_PARTS (query key $QUERY_KEY) =====" | tee -a "$CLIENT_LOG"
                        for t in "${T_VALUES[@]}"; do
                            run_client_combo "$part_rows" "$YCSB_KEY_BITS" "$b" "$t" "$ORG_VALUE_SIZE" "$YCSB_KEY_BITS" "" 0 "$skew"
                        done
                    done
                done
            done
          done
        done
      done
    elif [ "$EXP" = "3" ]; then
      # one pass per key count (2^n keys)
      for YCSB_KEYS_LOG2 in "${KEYS_LOG2_VALUES[@]}"; do
        # same skew/value-size/gamma_bar/base order (and skipped combos) and header-derived parameters as the server loop
        PART=0
        for skew in "${YCSB_SKEWS[@]}"; do
            for vmax in "${YCSB_VMAXS[@]}"; do
                set_ycsb_org "$skew" "$vmax"
                QUERY_KEY="$(ycsb_query_key "$skew" "$vmax")"
                for g in "${YCSB_GAMMAS[@]}"; do
                    GAMMA_BAR=$g
                    gamma_file="$(ycsb_file "$skew" "$vmax" "gamma${g}_bucket")"
                    parse_meta "$gamma_file"
                    echo "===== skew=$skew vmax=$vmax gamma_bar=$g: $gamma_file (query key $QUERY_KEY) =====" | tee -a "$CLIENT_LOG"
                    # the sanity check's expected row for this (skew, vmax, gamma_bar):
                    # the bucket holding the query key, made once with
                    # make_expected_row.py (key_size_org/8 = 32 key bytes; 1000000 so
                    # buckets wider than the script's 65536-value default aren't cut
                    # off), then copied to the file name the client reads
                    # named by key size and count too: the 2^26 datasets' files of a skew differ
                    exp_row="client/expected_row_ycsb_bucket_k${YCSB_KEY_BITS}_n2p${YCSB_KEYS_LOG2}_skew${skew}_vmax${vmax}_gamma${g}.csv"
                    if [ ! -f "$exp_row" ]; then
                        python3 scripts/python/make_expected_row.py "$gamma_file" "$QUERY_KEY" "$exp_row" \
                            "$((META_KEY_SIZE_ORG / 8))" 1000000 || echo "WARNING: could not make $exp_row"
                    fi
                    cp "$exp_row" client/expected_row_ycsb_bucket.csv
                    for b in "${B_VALUES[@]}"; do
                        if ! set_large_pm "$META_KEY_SIZE" "$b"; then
                            echo "===== skipping ${META_KEY_SIZE}-bit bucket ids in base $b (as the server does) =====" | tee -a "$CLIENT_LOG"
                            continue
                        fi
                        echo "===== base=$b (-l $LARGE_PLAIN_MODULUS) =====" | tee -a "$CLIENT_LOG"
                        for t in "${T_VALUES[@]}"; do
                            run_client_combo "$META_NUM_BUCKETS" "$META_KEY_SIZE" "$b" "$t" "$META_MAX_BUCKET_SIZE" "$META_KEY_SIZE_ORG" "$META_SELECTED_BIT" 1 "$skew"
                        done
                    done
                done
            done
        done
      done
    else
        for n in "${N_VALUES[@]}"; do
            for k_combo in "${K_COMBOS[@]}"; do
                IFS=':' read -r k domain_size selected_bit <<< "$k_combo"
                for b in "${B_VALUES[@]}"; do
                    for v in "${V_VALUES[@]}"; do
                        org_db_too_big "$n" "$domain_size" "$v" && continue   # same check as the server loop
                        for t in "${T_VALUES[@]}"; do
                            run_client_combo "$n" "$k" "$b" "$t" "$v" "$domain_size" "$selected_bit" "$BUCKETIZATION" "$SKEW"
                        done
                    done
                done
            done
        done
    fi

    echo "Done. Log: $CLIENT_LOG (CSV: $CLIENT_CSV)"

    # # Whichever of server/client finishes ALL its combos second is the one
    # # that finds the other's marker already there - that one (and only
    # # that one) triggers the merge, so it only runs once both sides have
    # # actually stopped, regardless of which finishes first.
    # touch "$RUN_DIR/.client_done"
    # if [ -f "$RUN_DIR/.server_done" ]; then
    #     python3 scripts/python/merge_sweep_results.py "$RUN_DIR"
    # fi
fi
