#!/bin/bash
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
if [ "$ROLE" != "server" ] && [ "$ROLE" != "client" ]; then
    echo "Usage: $0 <server|client> <1|2|6>"
    exit 1
fi
if [ "$EXP" != "1" ] && [ "$EXP" != "2" ] && [ "$EXP" != "6" ]; then
    echo "Usage: $0 <server|client> <1|2|6>"
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
cmake -S . -B build > /dev/null
cmake --build build --target "$ROLE" -j4

# ---- mode flags shared by every experiment ----
SYSTEM="ARCANA"    # tags every row so runs from different systems/setups are distinguishable in sweep_result.csv
SEEDED_SERIALIZATION=1   # -s on both: 0/1, required by server.cpp/client.cpp

# Resolves the uniform-dataset data file for a given key_size k - the only
# file mapping Exp 1/Exp 2 need. Exp 6 instead derives its file and params
# from each TPC-H file's own metadata header via parse_meta() below, since
# its k doesn't line up with this uniform-dataset table.
data_file_for_k() {
    case "$1" in
        32)  echo "../../Python_Codes/output/data/uniform/n1048576_k32_v256.csv" ;;
        64)  echo "../../Python_Codes/output/data/uniform/n1048576_k64_v256.csv" ;;
        128) echo "../../Python_Codes/output/data/uniform/n1048576_k128_v256.csv" ;;
        256) echo "../../Python_Codes/output/data/uniform/n1048576_k256_v256.csv" ;;
        512) echo "../../Python_Codes/output/data/uniform/n1048576_k512_v256.csv" ;;
    esac
}

# ---- per-experiment params ----
# K_COMBOS bundles key_size, domain_size, and selected_bit together as ONE
# entity per entry ("k:domain_size:selected_bit") instead of three separate
# arrays - domain_size and selected_bit are only meaningful paired with a
# specific k, so looping them independently against unrelated k values
# would build nonsensical queries. selected_bit is left empty for
# non-bucketization entries (unused there).
case "$EXP" in
    1)
        # ---- Exp 1: unary encoding, base sweep at a fixed key/value/N ----
        UNARY_ENCODING=0
        QUERY_EXPANSION=0
        PIR_COMPRESSION=0
        NUM_RUNS=1
        BUCKETIZATION=0
        FOLD_DATA=0
        N_VALUES=($((2**20)))
        # B_VALUES=(2 4 6 8 10 12 14 16 18 20 22 24 26 28 30)
        B_VALUES=(2)
        V_VALUES=($((2**8)))
        T_VALUES=(1)
        K_COMBOS=(
            "64:64:"
        )
        ;;
    2)
        # ---- Exp 2: XOR encoding + query expansion + PIR compression,
        # key_size sweep across N values ----
        UNARY_ENCODING=0
        QUERY_EXPANSION=1
        PIR_COMPRESSION=1
        NUM_RUNS=5
        BUCKETIZATION=0
        FOLD_DATA=1
        N_VALUES=($((2**17)) $((2**18)) $((2**19)) $((2**20)))
        B_VALUES=(12)
        V_VALUES=($((2**8)))
        T_VALUES=(18)
        K_COMBOS=(
            "64:64:"
            "128:128:"
            "256:256:"
            "512:512:"
        )
        ;;
    6)
        # ---- Exp 6: bucketization vs non-bucketization under TPC-H skew ----
        UNARY_ENCODING=0
        QUERY_EXPANSION=1
        PIR_COMPRESSION=1
        NUM_RUNS=5
        FOLD_DATA=1
        EXP6_THREADS=10
        EXP6_BASE=12
        EXP6_SKEW_VALUES=(0.6)
        EXP6_TPCH_DIR="../../Python_Codes/output/data/TPCH/data/bitsize_64"
        EXP6_RUN_BUCKET=1     # set to 0 to skip the bucketization combo per skew
        EXP6_RUN_NOBUCKET=0   # set to 1 to also run the non-bucketization combo per skew
        ;;
esac

# Parses a data distribution file's metadata header line into META_* globals
# (KEY_SIZE_ORG/KEY_SIZE/NUM_DISTINCT_KEYS/MAX_BUCKET_SIZE/SELECTED_BIT) -
# selected_bit=[...] is always the last field and is the only one that can
# contain internal commas, so it's peeled off first (between the first "["
# and the following "]") and everything before it is safe to split on ','.
# Only used by Exp 6.
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
        esac
    done
    IFS="$old_ifs"
    if [ -z "$META_KEY_SIZE" ] || [ -z "$META_NUM_BUCKETS" ] || [ -z "$META_MAX_BUCKET_SIZE" ]; then
        echo "ERROR: failed to parse metadata header in $file: $header"
        exit 1
    fi
}

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

RESULTS_DIR="../../output/results"
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
    if [ ! -f "$SERVER_CSV" ]; then
        echo "system,query_expansion,pir_compression,fold,unary_encoding,bucketization,skew,number_of_threads,base,number_of_keys,key_size,value_size,populate_time_s,query_expansion_time_s,equality_time_s,equality_time_e2c*/e2e+,equality_time_e2e*_s,pir_time_s,db_GB,db_sum_GB,pir_db_GB" > "$SERVER_CSV"
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
            tag="skew${skew}_d${bucket}_k${k}_b${b}_v${v}_t${t}"
        else
            tag="k${k}_b${b}_v${v}_t${t}"
        fi
        echo "Running server for $tag"
        echo "===== $tag =====" >> "$SERVER_LOG"
        local args=(-n "$n" -k "$k" -b "$b" -v "$v" -t "$t" -u "$UNARY_ENCODING" -r "$NUM_RUNS" -s "$SEEDED_SERIALIZATION" -d "$bucket" -e "$FOLD_DATA" -c "$PIR_COMPRESSION" -y "$QUERY_EXPANSION")
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
        ( ./bin/server "${args[@]}" > "$tmp_log" 2>&1; touch "$done_marker" ) &
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
        rm -f "$tmp_log"

        # skew is "" for Exp 1/Exp 2 (no skew concept there) - only the tag
        # naming above cares about that distinction ([ -n "$skew" ]);
        # displayed in the CSV as 0 instead of blank.
        echo "$SYSTEM,$QUERY_EXPANSION,$PIR_COMPRESSION,$FOLD_DATA,$UNARY_ENCODING,$bucket,${skew:-0},$t,$b,$n,$k,$v,$populate_time,$query_expansion_time,$equality_time,$equality_e2c_e2e_time,$equality_e2e_mult_time,$pir_processing,$db_gb,$db_sum_gb,$pir_db_gb" >> "$SERVER_CSV"

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
    else
        for n in "${N_VALUES[@]}"; do
            for k_combo in "${K_COMBOS[@]}"; do
                IFS=':' read -r k domain_size selected_bit <<< "$k_combo"
                data_file="$(data_file_for_k "$k")"
                for b in "${B_VALUES[@]}"; do
                    for v in "${V_VALUES[@]}"; do
                        for t in "${T_VALUES[@]}"; do
                            run_server_combo "$n" "$k" "$b" "$v" "$t" "$domain_size" "$selected_bit" "$BUCKETIZATION" "$data_file" ""
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
    if [ ! -f "$CLIENT_CSV" ]; then
        echo "system,query_expansion,pir_compression,fold,unary_encoding,bucketization,skew,number_of_threads,base,number_of_keys,key_size,value_size,query_size_MB,query_gen_time_s,query_send_time_s,result_size_MB,result_send_time_s,result_decode_time_s,sanity_correct" > "$CLIENT_CSV"
    fi

    # bucket/skew are explicit per-combo args (see the matching comment on
    # run_server_combo) - client doesn't take a data file at all (client.cpp
    # has no -f option; it derives its query purely from -n/-k/-b/-v/-o/-a).
    run_client_combo() {
        local n=$1 k=$2 b=$3 t=$4 v=$5 domain_size=$6 selected_bit=$7 bucket=$8 skew=$9
        local tag
        if [ -n "$skew" ]; then
            tag="skew${skew}_d${bucket}_k${k}_b${b}_v${v}_t${t}"
        else
            tag="k${k}_b${b}_v${v}_t${t}"
        fi
        echo "Running client for $tag"
        rm -f "$RUN_DIR/.client_done_${tag}"
        echo "===== $tag =====" >> "$CLIENT_LOG"
        # tmp_log holds just this combo's output so extract() below only
        # averages over this combo's NUM_RUNS - full output still lands in
        # CLIENT_LOG (appended) right after, then tmp_log is discarded.
        local tmp_log
        tmp_log=$(mktemp)
        local args=(-n "$n" -k "$k" -b "$b" -t "$t" -v "$v" -u "$UNARY_ENCODING" -r "$NUM_RUNS" -s "$SEEDED_SERIALIZATION" -d "$bucket" -e "$FOLD_DATA" -c "$PIR_COMPRESSION" -y "$QUERY_EXPANSION")
        if [ "$bucket" = "1" ]; then
            args+=(-a "$selected_bit" -o "$domain_size")
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
        echo "$SYSTEM,$QUERY_EXPANSION,$PIR_COMPRESSION,$FOLD_DATA,$UNARY_ENCODING,$bucket,${skew:-0},$t,$b,$n,$k,$v,$query_size,$query_gen_time,$query_send_time,$result_size,$result_send_time,$result_decode_time,$sanity_correct" >> "$CLIENT_CSV"
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
    else
        for n in "${N_VALUES[@]}"; do
            for k_combo in "${K_COMBOS[@]}"; do
                IFS=':' read -r k domain_size selected_bit <<< "$k_combo"
                for b in "${B_VALUES[@]}"; do
                    for v in "${V_VALUES[@]}"; do
                        for t in "${T_VALUES[@]}"; do
                            run_client_combo "$n" "$k" "$b" "$t" "$v" "$domain_size" "$selected_bit" "$BUCKETIZATION" ""
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
