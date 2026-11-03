#pragma GCC diagnostic ignored "-Wnarrowing"

#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <utility>
#include <algorithm>
#include <set>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <sstream>
#include <cmath>
#include <ctime>
#include <stack>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <cassert>
#include <fstream>

#include "seal/seal.h"

#include <globals.h>
#include <openssl/sha.h>
#include "utils.hpp"

using namespace std;
using namespace seal;

int NUM_ENCODING_THREAD = 1;
int NUM_BATCH_KEY_THREAD = 1;
int NUM_EXPANSION_THREAD = 1;
int NUM_THREAD = 1;
int NUM_EXPONENT_THREAD = 1;
int NUM_PIR_THREAD = 1;
// Equality step only. How many key batches are processed at the same time (server -g).
// 0 (default): min(batches, threads) - every thread takes its own batches ("horizontal": with
// at least as many batches as threads, each thread works through its batches alone).
// 1: one batch at a time with ALL threads working inside it - the digits of a batch are split
// over threads, then the squarings of the Fermat step - before the next batch ("vertical").
// Other values: that many batches at once, the threads shared out between them.
int batch_thread_override = 0;

// Populated by process_rows() below, one entry per THREAD per run (not per
// row): each process_rows call is itself one of NUM_BATCH_KEY_THREAD
// threads, and accumulates the sum of its own rows' base-wise/Fermat
// durations locally (no overlap within one thread's own sequential row
// loop, so this sum is that thread's real active time in the phase), then
// pushes ONE total after its row loop finishes. Guarded by a mutex so
// concurrent threads can push safely (NUM_BATCH_KEY_THREAD pushes per run,
// far less contention than the old per-row scheme). See
// average_max_thread_total_per_run()'s doc comment for how these are
// reduced to a per-run number. Only populated when !unary_encoding, same as
// before. Averaged and printed once at the end of server.cpp's num_runs loop.
std::vector<double> base_wise_computation_thread_totals;
std::vector<double> fermat_computation_thread_totals;
// Unary-mode counterpart to base_wise_computation_thread_totals/
// fermat_computation_thread_totals above - unary has no Fermat phase (the
// one-hot multiply-reduction already computes exact equality), but its
// column-processing work still splits into two phases worth timing
// separately: the process_columns_unary spawn/join (the "fused e2c*/e2e+"
// per-column multiply-and-partial-reduce step), and the multiply_columns
// combine tree that reduces those partial results down to one. Same
// accumulate-then-push-once pattern. Only populated when unary_encoding.
std::vector<double> unary_base_wise_computation_thread_totals;
std::vector<double> unary_multiply_computation_thread_totals;
std::mutex row_computation_times_mutex;

// Server IP and port
const std::string SERVER_IP = "127.0.0.1";
const int SERVER_PORT = 48173;
bool query_expansion = false;
bool read_from_file = false;
// Set via server.cpp's -c flag: selects process_pir (rotate-and-pack
// compressed result, fewer/smaller output ciphertexts) over
// process_pir_no_compression (one ciphertext per column) in the PIR phase.
bool pir_compression = false;
// Set via server.cpp's -y flag only; shared here so any helper.hpp function
// can read it too.
bool bucketization = false;
// Set via both server.cpp's and client.cpp's -e flag; halves the number of
// distinct random keys generated per batch (duplicating into the mirrored
// slot) and halves pir_num_columns_per_obj to match.
bool fold_data = false;
//======================================================================
// HARD-CODED ON/OFF SWITCHES - all in one place.
// These are not command-line flags: change true/false here and rebuild.
//======================================================================
// Merge each pair of compressed PIR result chunks into one ciphertext
// (merge_pir_chunk_pairs), halving the number of result ciphertexts. Only
// acts with pir_compression on and fold_data off. Read by BOTH the server
// and the client, so rebuild both.
bool pir_merge_chunk_pairs = true;
// WHEN the equality check drops ciphertext primes (mod switches). The total
// number of switches is MOD_SWITCH_COUNT either way and the result ends at
// the same level. Read by the server only.
// Non-unary: false does all the squarings of the Fermat step at the full size
// and every switch at the end; true drops a prime after every 2nd squaring.
bool non_unary_early_mod_switch = true;
// Unary: false runs the whole multiply tree at the full size and every switch
// at the end; true drops unary_pre_drop_count() primes from each position sum
// before the tree.
bool unary_early_mod_switch = true;
// Threads used to LOAD the database (populate_db, populate_db_synthetic_values)
// - setup work done once before any query, outside every reported query
// time, so it can use the whole machine instead of -t. Defaults to every
// hardware thread the machine reports; set a fixed number instead when the
// job only owns part of a node (e.g. a Slurm allocation smaller than the node).
int TOTAL_MACHINE_THREAD = std::max(1u, std::thread::hardware_concurrency());
// Non-unary only. The equality check computes sum((q - d)^2) mod p before
// Fermat; once digits * (base - 1)^2 reaches p = 65537, a different key can
// wrap to 0 and count as a match. true: for the bases that need it, use the
// larger p = LARGE_PLAIN_MODULUS (15 primes, 12 mod switches) so the sum never
// wraps. Works while the sum stays below LARGE_PLAIN_MODULUS (up to base 256
// for 64-bit keys, 128 for 128-, 184- and 256-bit, 64 for 512-bit) - see
// apply_plain_modulus_choice(). Read by BOTH the server and the client, so
// rebuild both. -l 0|1 on the server and client overrides it per run (the base
// ablation passes -l 1 only where the sum reaches 65537).
bool large_plain_modulus = false;
// Where the database values come from. Read by BOTH the server and the client.
// true:  populate_db_synthetic_values() - keys from the file, values generated;
//        the client writes the retrieved row as numbers.
// false: populate_db() - keys and values from the file; the client writes the
//        retrieved row as text, one 2-byte string per value (e.g. "ad,yQ,u7").
bool synthetic_values = false;
//======================================================================

bool pir_pair_merge_active()
{
    return pir_merge_chunk_pairs && pir_compression && !fold_data;
}
// How many primes a unary position sum can lose before the multiply tree.
// Everything about the primes comes from CT_PRIMES (data primes first, the
// key-switching prime last; mod switches drop data primes from the back) and
// MOD_SWITCH_COUNT. The remaining constants are noise offsets measured for
// N = 32768 and the 16-bit plaintext modulus, which are fixed:
//   45 - bits a position sum has already used before the tree (encryption +
//        plaintext multiply); 83 when the query went through query expansion
//   30 - bits one level of the multiply tree uses
//   25 - gap between the final level's prime bits and the budget the result
//        ends with there (35 bits on one 60-bit prime)
//   18 - the first dropped prime costs this much less than its size
// Primes are dropped while a whole prime's worth of budget would still be
// left in reserve after the tree.
int unary_pre_drop_count(int positions)
{
    int levels = 0;
    while ((1 << levels) < positions)
    {
        levels++;
    }
    int data_primes = (int)CT_PRIMES.size() - 1;
    int final_primes = std::max(1, data_primes - MOD_SWITCH_COUNT); // primes left at the result's final level
    int total_bits = 0, final_bits = 0;
    for (int i = 0; i < data_primes; i++)
    {
        total_bits += CT_PRIMES[i];
        if (i < final_primes)
        {
            final_bits += CT_PRIMES[i];
        }
    }
    int budget = total_bits - (query_expansion ? 83 : 45); // of a position sum, before the tree
    int needed = 30 * levels + (final_bits - 25);          // the tree, plus what the result ends with
    int reserve = CT_PRIMES[0];
    int drop = 0;
    while (drop < MOD_SWITCH_COUNT && drop < data_primes - 1)
    {
        int prime_bits = CT_PRIMES[data_primes - 1 - drop];
        int cost = drop == 0 ? prime_bits - 18 : prime_bits;
        if (budget - cost - needed < reserve)
        {
            break;
        }
        budget -= cost;
        drop++;
    }
    return drop;
}
// unary_pre_drop_count()'s result for this run - set once by server.cpp
// before the run loop, and left at 0 unless unary_early_mod_switch is on.
int unary_pre_drop = 0;
int num_runs = 2; // how many query/response rounds to repeat and average over
bool unary_encoding = false;
int total_capacity = 0;
// Controls how the client serializes freshly-encrypted symmetric ciphertexts
// it sends over the wire: seeded (Serializable<Ciphertext>::save - compact,
// second polynomial stored as a PRNG seed) vs non-seeded (encrypt into a
// concrete Ciphertext, then Ciphertext::save - full size, but the only option
// once the ciphertext needs an in-place op like mod-switching before it's
// sent, since Evaluator can't operate on a Serializable<Ciphertext>).
bool seeded_serialization = true;
// x: target number of ciphertexts the query_expansion input is split
// across. Any value >= 1 is valid (see compute_query_chunk_plan). Note the
// actual count sent can be x+1 when spawn_extra_ciphertext_for_leftover is
// set and the leftover-ciphertext branch is taken - see that flag below.
int num_query_ciphertexts = 1;
// Only consulted when expanded_slot_count is closer to the power of two
// below it than the one above it (i.e. rounding up and dividing evenly
// would waste too much) - decides how the leftover real digits beyond that
// lower power of two are handled: false packs them into the x-th
// ciphertext's own padded-up capacity (same total ciphertext count, x);
// true gives them their own (x+1)-th ciphertext sized to its own next
// power of two instead (one more ciphertext, but the first x stay exactly
// full/unpadded). Edit directly to experiment.
bool spawn_extra_ciphertext_for_leftover = false;
// Only consulted by compute_query_chunk_plan: when true, bypasses the
// closer-to-prev-or-next-power-of-two selection between Strategies A/B/C
// entirely and always uses Strategy D (build_greedy_chunk_plan) instead.
// Strategy D self-sizes its own piece count from expanded_slot_count's
// popcount (see compute_query_chunk_plan), so unlike Strategies A/B/C it
// needs no num_query_ciphertexts tuning to stay padding-free - default is
// on. Set to false to fall back to the A/B/C selection instead.
bool use_greedy_chunk_plan = true;
// -p 1 (client and server must agree): pack all the real digits into ONE query ciphertext, padded up to the next
// power of two (e.g. 53 digits -> one ciphertext of capacity 64), instead of one ciphertext per power of two
// (32 + 16 + 4 + 1). The server still expands only the real digits (53 of them): the padding only sets the block
// capacity, i.e. each digit's log2(capacity) rotate-and-adds (6 instead of 5, 4, 2 and 0). Off by default.
bool single_query_ciphertext = false;

void sha256(const char *str, int len, unsigned char *dest);
void preallocate_memory();
void *expand_query(void *arg);
void *process_rows(void *arg);
void populate_db();
void populate_db_from_file(const std::string &path);
void populate_db_uniform();
// void encode_key_batches(const std::vector<uint64_t> &keys);
void encode_key_batches(const std::vector<std::vector<int>> &keys);
void *process_columns(void *arg);
void *process_pir(void *arg);
void *process_pir_no_compression(void *arg);
uint32_t pir_num_chunks();
uint32_t pir_compressed_output_count();
uint32_t pir_scratch_ct_count();
void merge_pir_chunk_results(uint32_t chunk_index);
void print_report();
void *apply_fermat(void *arg);
void init_pir_params();
uint32_t get_next_power_of_two(uint32_t number);
uint32_t get_number_of_bits(uint64_t number);
void set_pir_db(const std::vector<std::vector<uint64_t>> &db);
void encode_pir_columns(uint32_t col_start, uint32_t num_cols, const std::vector<std::vector<uint64_t>> &group_vals);
void pir_encode_db(std::vector<std::vector<uint64_t>> db);
Ciphertext get_sum(Ciphertext *query, uint32_t start, uint32_t end);
vector<uint64_t> rotate_plain(const std::vector<uint64_t> &original, int index);
int digits_in_power_of_two(int k, int base);
double average(const std::vector<double> &values);
double average_max_thread_total_per_run(const std::vector<double> &values, int threads_per_run);
void *add_columns_range(void *arg);
void *process_columns_non_unary(void *arg);
void *process_columns_unary(void *arg);
void *multiply_columns(void *arg);
void *combine_partial_sums_range(void *arg);

int batch_count_for_keys = 32;
int encoding_size = 8;
uint32_t encoding_size_to_power_of_two = 0;

// x must be at least 1. assert() alone isn't enough here - this project's
// cached CMake build type is Release (-DNDEBUG), which compiles assert()
// out entirely, letting a bad num_query_ciphertexts silently reach
// expand_query and fail deep inside with a cryptic SEAL exception instead
// of a clear error at the source. Both client.cpp and server.cpp call this
// once encoding_size/unary_encoding are known.
void check_num_query_ciphertexts()
{
    if (num_query_ciphertexts < 1)
    {
        std::cerr << "num_query_ciphertexts must be >= 1, got " << num_query_ciphertexts << "\n";
        std::exit(1);
    }
}

// Per-ciphertext plan for splitting expanded_slot_count real digits across
// num_query_ciphertexts pieces. real[m]/capacity[m] are that ciphertext's
// real digit count and block capacity (a power of two >= real[m]).
struct QueryChunkPlan
{
    std::vector<int> real;
    std::vector<int> capacity;
};

// Largest power of two <= n (n must be >= 1).
static inline int largest_power_of_two_le(int n)
{
    return 1 << (get_number_of_bits(n) - 1);
}

// Number of set bits in n's binary representation - equivalently, the exact
// number of pieces build_greedy_chunk_plan needs to represent n as a sum of
// distinct powers of two with zero padding on every piece (e.g. 137 =
// 0b10001001 -> 3 -> {128, 8, 1}). Lets compute_query_chunk_plan derive its
// own x for Strategy D directly from expanded_slot_count instead of the
// caller having to hand-tune num_query_ciphertexts to match.
static inline int count_set_bits(int n)
{
    int count = 0;
    while (n)
    {
        n &= (n - 1);
        count++;
    }
    return count;
}

// Strategy A: pad expanded_slot_count up to its own next power of two
// first, then divide THAT evenly across up to x pieces (same base_share
// capacity for every full piece; the last one absorbs whatever's short of a
// full base_share and pads only itself up to its own next power of two).
// Used when expanded_slot_count is closer to (or equidistant from) the
// power of two above it than the one below - the padding cost of rounding
// up is small relative to expanded_slot_count itself, so eating it once up
// front and dividing cleanly beats any leftover-juggling strategy (e.g. 127
// digits, x=4: pads to 128, 32 each).
// Self-limiting: stops creating pieces as soon as every real digit is
// accounted for, even if that happens before reaching x pieces - an x
// chosen larger than expanded_slot_count actually needs must not produce
// empty, all-padding trailing ciphertexts (each one is a real ciphertext
// sent and expanded for zero benefit). This also means every piece it
// produces is valid by construction (real in [0, capacity], loop stops
// before real could go negative), unlike the old fixed-x-pieces version.
static QueryChunkPlan build_padded_uniform_chunk_plan(int expanded_slot_count, int x)
{
    QueryChunkPlan plan;
    int padded_total = get_next_power_of_two(expanded_slot_count);
    int base_share = largest_power_of_two_le(padded_total / x >= 1 ? padded_total / x : 1);
    int remaining = expanded_slot_count;
    for (int i = 0; i < x && remaining > 0; i++)
    {
        int this_real = (remaining < base_share) ? remaining : base_share;
        int this_capacity = (this_real == base_share) ? base_share : get_next_power_of_two(this_real);
        plan.real.push_back(this_real);
        plan.capacity.push_back(this_capacity);
        remaining -= this_real;
    }
    return plan;
}

// Strategy B (spawn_extra_ciphertext_for_leftover == false): used when
// expanded_slot_count is closer to the power of two below it - rounding up
// front-loads too much padding, so instead every "regular" piece gets the
// same base share (largest power of two <= floor(largest_pow2(count) / x));
// whatever's left after handing that base to as many regular pieces as
// needed (up to x-1 of them) is absorbed by one final piece, padded up to
// its own next power of two.
// Self-limiting like Strategy A: stops handing out regular pieces once
// there's nothing more than one base_share left (so the trailing piece
// isn't left with a bigger-than-base_share leftover it can't represent
// cleanly), and skips the trailing piece entirely if there's nothing left
// for it - an oversized x here simply produces fewer than x ciphertexts
// rather than empty ones.
static QueryChunkPlan build_uniform_base_chunk_plan(int expanded_slot_count, int x)
{
    QueryChunkPlan plan;
    int leading = largest_power_of_two_le(expanded_slot_count);
    int base_share = largest_power_of_two_le(leading / x >= 1 ? leading / x : 1);
    int remaining = expanded_slot_count;
    for (int i = 0; i < x - 1 && remaining > base_share; i++)
    {
        plan.real.push_back(base_share);
        plan.capacity.push_back(base_share);
        remaining -= base_share;
    }
    if (remaining > 0)
    {
        plan.real.push_back(remaining);
        plan.capacity.push_back(get_next_power_of_two(remaining));
    }
    return plan;
}

// Strategy C (spawn_extra_ciphertext_for_leftover == true): same base-share
// split of expanded_slot_count's leading power-of-two component as Strategy
// B, but instead of folding the leftover into the last regular piece's own
// padding, it gets an entirely separate extra ciphertext sized to its own
// next power of two. Up to x+1 pieces total (x regular + 1 extra), but see
// self-limiting note below - can be fewer.
static QueryChunkPlan build_spawn_extra_chunk_plan(int expanded_slot_count, int x)
{
    QueryChunkPlan plan;
    int leading = largest_power_of_two_le(expanded_slot_count);
    int base_share = largest_power_of_two_le(leading / x >= 1 ? leading / x : 1);
    int remaining = expanded_slot_count;
    for (int i = 0; i < x && remaining >= base_share; i++)
    {
        plan.real.push_back(base_share);
        plan.capacity.push_back(base_share);
        remaining -= base_share;
    }
    // Whatever's left (< base_share, or all of expanded_slot_count if even
    // the first regular piece couldn't be filled) gets its own extra,
    // padded ciphertext - skipped entirely if nothing's left, so an
    // oversized x doesn't spawn a pointless empty extra piece either.
    if (remaining > 0)
    {
        plan.real.push_back(remaining);
        plan.capacity.push_back(get_next_power_of_two(remaining));
    }
    return plan;
}

// Strategy D (use_greedy_chunk_plan == true): peels off the largest
// power-of-two component of expanded_slot_count one piece at a time - e.g.
// 129 -> {128, 1}, 137 -> {128, 8, 1} - instead of dividing by a single
// base_share like Strategies A-C. Every piece except possibly the last is
// exact (real == capacity, zero padding); Strategies A-C always eat some
// padding on at least one piece unless expanded_slot_count happens to divide
// evenly.
// Stops after x pieces even if bits remain: whatever's left over is folded
// into the x-th (last) piece's own capacity, padded up to its own next power
// of two - the same merge-the-remainder move Strategy A's last piece makes.
// So x is a hard cap on ciphertext count, not just a suggestion - a count
// with more set bits than x (e.g. 255 needs 8 pieces to represent exactly
// with zero padding) still pays padding on that final merged piece.
// In practice compute_query_chunk_plan always calls this with x =
// count_set_bits(expanded_slot_count) - exactly enough pieces to hit zero
// padding on every one of them - so this cap is a defensive fallback, not
// something callers need to size themselves.
static QueryChunkPlan build_greedy_chunk_plan(int expanded_slot_count, int x)
{
    QueryChunkPlan plan;
    int remaining = expanded_slot_count;
    for (int i = 0; i < x && remaining > 0; i++)
    {
        int chunk = largest_power_of_two_le(remaining);
        plan.real.push_back(chunk);
        plan.capacity.push_back(chunk);
        remaining -= chunk;
    }
    if (remaining > 0)
    {
        plan.real.back() += remaining;
        plan.capacity.back() = get_next_power_of_two(plan.real.back());
    }
    return plan;
}

// A plan is only usable if every piece's real digit count is in
// [0, capacity] - build_padded_uniform_chunk_plan's last piece can go
// negative when x pieces at its base share would overshoot the real count.
// (Checking sum(real) == expanded_slot_count is NOT enough: the last piece
// is always defined as expanded_slot_count - sum(the rest), so the sum is
// tautologically correct even when that piece itself is negative - and a
// negative real multiplied into a cost calculation can make an invalid,
// digit-dropping plan look artificially cheap.)
static bool query_chunk_plan_is_valid(const QueryChunkPlan &plan)
{
    for (size_t i = 0; i < plan.real.size(); i++)
    {
        if (plan.real[i] < 0 || plan.real[i] > plan.capacity[i])
            return false;
    }
    return true;
}

QueryChunkPlan compute_query_chunk_plan(int expanded_slot_count, int x)
{

    int greedy_x = count_set_bits(expanded_slot_count);
    return build_greedy_chunk_plan(expanded_slot_count, greedy_x > 0 ? greedy_x : 1);
}

// masks[m][local_i] - m's own mask set, sized to m's block capacity (which
// can differ per ciphertext depending on which chunk plan strategy won).
vector<vector<Plaintext>> masks;
// Set once in server.cpp's pre-loop setup (compute_query_chunk_plan's
// result is fixed for the whole run) and read directly by expand_query,
// instead of every expand_query call (once per round, per thread)
// recomputing the same deterministic plan itself.
QueryChunkPlan query_chunk_plan;
// query_chunk_offset[m] = the real-digit index where ciphertext m's share
// starts (prefix sum over query_chunk_plan.real). Same reasoning as
// query_chunk_plan above - deterministic from it, set once alongside it
// rather than rebuilt by every expand_query call.
std::vector<int> query_chunk_offset;
// digit_offset[m] = the digit_indices index where chunk m's own capacity[m]
// slots start (prefix sum over query_chunk_plan.capacity - note this is
// capacity, not real, unlike query_chunk_offset above: build_compressed_query
// packs every one of a chunk's capacity slots, including any padding ones,
// so digit_indices needs room for all of them). Client-side counterpart to
// query_chunk_offset, set once by setup_query_expansion_client().
std::vector<int> digit_offset;
// unary_encoding ? encoding_size : (encoding_size + 1) - the +1 is the
// non-unary sum-of-squares slot, treated as just another "digit" by the
// chunk plan/expand_query. Set once by setup_query_expansion().
int expanded_slot_count = 0;
// query_chunk_plan.capacity.size() - how many ciphertexts the client
// actually sends when query_expansion is on (1 when it's off, since the
// per-digit path doesn't chunk anything). Set once by setup_query_expansion().
int actual_ciphertext_count = 1;
uint64_t number_of_keys = 0;
uint32_t base = 0;
vector<Plaintext> pir_encoded_db;
uint32_t pir_num_obj;
uint32_t value_size;
uint32_t key_size; //  in bits
uint32_t pir_num_columns_per_obj;
uint32_t pir_plain_bit_count;
uint32_t pir_db_rows;
// value columns (plaintexts) kept for each key batch - set by populate_db:
// batch 0 keeps all pir_num_columns_per_obj, every other batch only up to its
// longest row; the rest would be all zero, so they are not stored and PIR
// skips them. Empty (other populate functions): every batch keeps every column.
std::vector<uint32_t> batch_value_cols;
// true when PIR needs plaintext (col, batch)
inline bool pir_plain_used(uint32_t col, int batch) { return batch_value_cols.empty() || col < batch_value_cols[batch]; }
// Result ciphertexts are sent over rpclib in batches of this many at a time
// (via the getResultChunk RPC), instead of one giant blob - a single
// message holding thousands of ciphertexts can exceed msgpack's container
// size limit or spike memory enough to get OOM-killed for large PIR results.
#define RESULT_CHUNK_SIZE 4096
vector<string> result_chunks;
// Populated by populate_db()'s read_from_file branch: each key's digits
// straight from the larp file, one per row of `keys`. Lets encode_key_batches
// build mat_db directly from the file's already-known digits instead of
// re-deriving them from an integer via mod/div.
vector<vector<int>> file_key_digits;
Ciphertext *expanded_query;
Ciphertext *expanded_query_sum;
Ciphertext *row_result;
Ciphertext *client_query_ct, *one_ct;
Ciphertext *server_query_ct; // array sized off QueryChunkPlan's actual length (server.cpp) - not always num_query_ciphertexts, see compute_query_chunk_plan
Ciphertext *column_results;
Ciphertext *pir_results;
vector<vector<Plaintext>> db;
vector<Plaintext> db_sum;
pthread_t *query_expansion_thread;
int *expansion_thread_id;
// Tracks the last-allocated size of query_expansion_thread/expansion_thread_id
// (same grow-only reuse pattern as row_thread_capacity in server.cpp) so
// load_and_expand_query doesn't leak a fresh array every round.
int query_expansion_thread_capacity = 0;
pthread_t *row_process_thread;
int *row_thread_id;
pthread_t *pir_thread;
int *pir_thread_id;
pthread_t *col_process_thread;
int *col_thread_id;
std::string data_dist_file = "";

SEALContext *context;
MemoryPoolHandle *column_pools;
Evaluator *evaluator;
BatchEncoder *batch_encoder;
KeyGenerator *keygen;
Encryptor *encryptor;
Decryptor *decryptor;
size_t batch_row_size;
// Allocated at runtime (init_seal_context_and_keys), not default-constructed
// as static globals: RelinKeys/GaloisKeys default-initialize a MemoryPoolHandle
// member from MemoryManager::GetPool(), which depends on SEAL's own global
// memory pool having already been constructed - a static-init-order race that
// left these permanently bound to an uninitialized pool when they were plain
// value globals.
GaloisKeys *galois_keys = nullptr;
RelinKeys *relin_keys = nullptr;
seal::parms_id_type compact_pid;
seal::parms_id_type pid;

rpc::client *rpc_client_conn = nullptr; // client.cpp: connection to the server
rpc::server *rpc_server_conn = nullptr; // server.cpp: listener for the client
// Plain value globals, not pointers: unlike RelinKeys/GaloisKeys (see the
// comment above), std::promise/std::future have no static-init-order
// dependency on SEAL's memory pool, so there's no reason to heap-allocate
// them. "Recreated" each round (see comments below) just means move-
// assigning a fresh one over the global, which also correctly destroys the
// old promise/future's shared state - the previous new-without-delete
// pattern silently leaked one of these every round instead.
std::future<std::string> one_ct_future;
// Recreated at the start of every round in the query/response loop (not just
// once in init_seal_context_and_keys) so main() can wait on a fresh query
// each round instead of a promise that can only ever be set once.
std::promise<std::string> query_promise;
std::future<std::string> query_future;
// Guards query_promise/query_future against concurrent access between the
// "sendQuery" RPC handler thread (set_value) and main()'s get()+reset of the
// same globals every round - without this, a set_value() for the next
// round's query can race the reset for the current round.
std::mutex query_mutex;
// Fulfilled by main() right after it finishes loading the query into
// ciphertexts (not by the "sendQuery" handler, which only stores the raw
// bytes) - lets the client's "waitForQueryLoaded" call block until loading
// is actually done, not just received. Recreated each round too. Carries
// the server-measured loading duration (seconds) rather than just a bool,
// so the client can report that number directly instead of its own
// wall-clock time around the call - which would otherwise be contaminated
// by however much of populate_db() was still running when the query
// arrived (the "sendQuery" handler can receive it well before main() even
// reaches the round loop, since populate_db() runs first).
std::promise<double> query_loaded_promise;
std::future<double> query_loaded_future;
// Guards query_loaded_promise/query_loaded_future: main() calls set_value()
// then immediately reassigns both globals for the next round, while the
// "waitForQueryLoaded" RPC handler thread may concurrently be mid-get() on
// the same future - the exact race that caused the SIGSEGV in
// exception_ptr::_M_addref (concurrent access to the future's shared state).
std::mutex query_loaded_mutex;
// Fulfilled by the server's main() once the PIR result is computed; the
// "getResult" RPC handler blocks on result_future until then. Also recreated
// each round, same reason as query_promise/query_future above.
std::promise<std::string> result_promise;
std::future<std::string> result_future;
// Guards result_promise/result_future - same shape of race as
// query_loaded_mutex above (main() sets then resets, "getResult" RPC handler
// thread reads).
std::mutex result_mutex;
// Fulfilled by the "clientDone" RPC call once the client has actually
// received the result. Without this, main() could move on to the next round
// (or return, tearing down rpc_server_conn) right after result_promise is
// set but before the getResult response has actually been flushed to the
// client's socket - a race that leaves the client blocked forever on a dead
// connection. Recreated each round too.
std::promise<bool> done_promise;
std::future<bool> done_future;
// Guards done_promise/done_future - same shape of race as query_mutex above
// ("clientDone" RPC handler thread sets, main() gets then resets).
std::mutex done_mutex;

// time measurement variables
chrono::high_resolution_clock::time_point time_start,
    time_end, total_start, total_end;
clock_t total_cpu_start, total_cpu_end, cpu_start, cpu_end;
std::stringstream ss, qss;
uint64_t query_gen_time, query_send_time, expansion_time, equality_time, pir_time, result_send_time, result_decode_time;

typedef std::vector<seal::Ciphertext> PIRQuery;
typedef seal::Ciphertext PIRResponse;
struct column_thread_arg
{
    int col_id;
    int row_idx;
    Ciphertext *column_result;
    column_thread_arg(int c_id, int r_idx, Ciphertext *res)
    {
        col_id = c_id;
        row_idx = r_idx;
        column_result = res;
    }
};
struct reduce_thread_arg
{
    int worker_id;
    int diff;
    int num_pairs;
    int num_workers;
    Ciphertext *column_result;
};
struct final_combine_thread_arg
{
    int worker_id;
    int diff;
    int num_pairs;
    int num_workers;
    int count;
    Ciphertext *column_result;
};
struct mult_thread_arg
{
    int id;
    int diff;
    Ciphertext *column_result;
    mult_thread_arg(int _id, int _diff, Ciphertext *_column_result)
    {
        id = _id;
        diff = _diff;
        column_result = _column_result;
    }
};
// One worker of a unary multiply round (multiply_columns_range): handles its
// share of the round's num_pairs pairs, each multiply using num_threads threads.
struct mult_range_thread_arg
{
    int worker_id;
    int num_workers;
    int diff;
    int num_pairs;
    int num_threads;
    Ciphertext *column_result;
};

//**************Display and others********************/
// Returns number of digits of the largest k-bit key (2^k - 1) when written in given base.
// That is the smallest d >= 1 with base^d >= 2^k. base^d is built as a big number
// (32-bit limbs, least significant first) so k is not limited by any integer type.
// Called by the client and the server once encoding_size/base are known and
// before the SEAL context is made (both must pick the same parameters). Only
// with large_plain_modulus on and non-unary encoding:
//   - largest sum before Fermat, encoding_size * (base - 1)^2, below
//     PLAIN_MODULUS: nothing to do, the default parameters are exact;
//   - otherwise, when the sum stays below LARGE_PLAIN_MODULUS (e.g. 64-bit keys
//     up to base 256, 128-, 184- and 256-bit up to 128, 512-bit up to 64):
//     LARGE_PLAIN_MODULUS with 15 primes (881 bits, the 128-bit security limit
//     at N = 32768) and 12 mod switches - the result ends at two primes to keep
//     enough noise budget;
//   - otherwise, when it stays below XL_PLAIN_MODULUS (512-bit keys in base
//     128): XL_PLAIN_MODULUS with the same primes - one more squaring and one
//     more multiply in the Fermat step, so the noise budget is tighter (the
//     client's sanity check shows whether it held);
//   - anything else stops with an error.
void apply_plain_modulus_choice()
{
    if (!large_plain_modulus || unary_encoding)
    {
        return;
    }
    uint64_t max_sum = (uint64_t)encoding_size * (base - 1) * (base - 1);
    if (max_sum < PLAIN_MODULUS)
    {
        std::cout << "Large plaintext modulus: not needed (largest sum " << max_sum << " < " << PLAIN_MODULUS << ")" << std::endl;
        return;
    }
    // the larger p works for any key size whose largest sum stays below it (for
    // 64/128/256/512-bit keys: up to base 256/128/128/64; for 184-bit up to 128)
    if (max_sum >= XL_PLAIN_MODULUS)
    {
        throw std::runtime_error("largest plaintext modulus " + std::to_string(XL_PLAIN_MODULUS) + " is too small for " +
                                 std::to_string(key_size) + "-bit keys in base " + std::to_string(base) +
                                 " (largest sum " + std::to_string(max_sum) + ")");
    }
    plain_modulus_value = max_sum < LARGE_PLAIN_MODULUS ? LARGE_PLAIN_MODULUS : XL_PLAIN_MODULUS;
    CT_PRIMES.assign(13, 60);
    CT_PRIMES.push_back(41); // first prime dropped by mod switching
    CT_PRIMES.push_back(60); // special prime (key switching)
    MOD_SWITCH_COUNT = 12;
    std::cout << "Large plaintext modulus: " << plain_modulus_value << " (largest sum " << max_sum << "), "
              << CT_PRIMES.size() << " primes, " << MOD_SWITCH_COUNT << " mod switches" << std::endl;
}

int digits_in_power_of_two(int k, int base)
{
    if (k < 0)
        return -1; // invalid exponent
    if (base <= 1)
        return -1; // invalid base
    if (k == 0)
        return 1;                      // only key is 0, which is one digit
    std::vector<uint32_t> power(1, 1); // base^0 = 1
    int digits = 0;
    while (true)
    {
        // bit length of power; power >= 2^k exactly when its bit length is > k
        int bits = 32 * static_cast<int>(power.size() - 1);
        for (uint32_t top = power.back(); top; top >>= 1)
            bits++;
        if (bits > k)
            return digits;
        uint64_t carry = 0; // power *= base
        for (uint32_t &limb : power)
        {
            uint64_t cur = static_cast<uint64_t>(limb) * static_cast<uint64_t>(base) + carry;
            limb = static_cast<uint32_t>(cur);
            carry = cur >> 32;
        }
        if (carry)
            power.push_back(static_cast<uint32_t>(carry));
        digits++;
    }
}

// Used by client.cpp/server.cpp to average per-round timings over num_runs.
// Drops the single highest and single lowest sample first (trimmed mean) so
// one slow/fast outlier round doesn't skew the reported average - only
// kicks in once there are more than 2 samples, otherwise falls back to a
// plain average (removing both would leave nothing to average).
double average(const std::vector<double> &values)
{
    if (values.empty())
    {
        return 0.0;
    }
    if (values.size() <= 2)
    {
        double sum = 0.0;
        for (double v : values)
        {
            sum += v;
        }
        return sum / values.size();
    }
    std::vector<double> sorted_values(values);
    std::sort(sorted_values.begin(), sorted_values.end());
    double sum = 0.0;
    for (size_t i = 1; i + 1 < sorted_values.size(); i++)
    {
        sum += sorted_values[i];
    }
    return sum / (sorted_values.size() - 2);
}

// values holds one entry per THREAD, back to back for each run (exactly
// threads_per_run entries per run - not necessarily in thread-id order at
// NUM_THREAD > 1, since concurrent process_rows threads push through a
// shared mutex, but every thread still pushes exactly once before the next
// round starts) - e.g. base_wise_computation_thread_totals/
// fermat_computation_thread_totals in server.cpp, where each entry is
// already that thread's own summed duration across all the rows it
// processed (no overlap within one thread's sequential row loop, so the sum
// is real time for that thread alone). For each run, takes the max across
// that run's threads_per_run entries - the slowest thread's total time in
// this phase, which is what actually determines when pthread_join returns
// (the other threads finish sooner and just wait), so it's a much closer
// approximation to that phase's real contribution to Row processing wall
// time than either a raw sum (double-counts concurrent threads) or an
// envelope across all rows (double-counts overlap between DIFFERENT rows'
// phases - see the earlier discussion). Averages those per-run maxes across
// runs.
double average_max_thread_total_per_run(const std::vector<double> &values, int threads_per_run)
{
    if (threads_per_run <= 0 || values.empty())
    {
        return 0.0;
    }
    std::vector<double> per_run_maxes;
    for (size_t i = 0; i + (size_t)threads_per_run <= values.size(); i += (size_t)threads_per_run)
    {
        double run_max = values[i];
        for (size_t j = i; j < i + (size_t)threads_per_run; j++)
        {
            run_max = std::max(run_max, values[j]);
        }
        per_run_maxes.push_back(run_max);
    }
    return average(per_run_maxes);
}

void print_plaintext_slots(const seal::Plaintext &pt, std::size_t print_count = 10)
{
    std::vector<uint64_t> decoded;
    batch_encoder->decode(pt, decoded);

    std::cout << "plaintext slots:" << std::endl;
    for (std::size_t j = 0; j < std::min(print_count, decoded.size()); j++)
    {
        std::cout << decoded[j] << " ";
    }
    std::cout << std::endl;
}

void print_ciphertext_slots(
    const seal::Ciphertext &ct,
    std::size_t print_count = 10)
{
    std::size_t slot_count = batch_encoder->slot_count();
    std::size_t row_size = slot_count / 2;

    seal::Plaintext pt;
    decryptor->decrypt(ct, pt);

    std::vector<uint64_t> decoded;
    batch_encoder->decode(pt, decoded);

    std::cout << "ciphertext slots:" << std::endl;
    for (std::size_t j = 0; j < std::min(print_count, decoded.size()); j++)
    {
        std::cout << decoded[j] << " ";
        if ((j + 1) % row_size == 0)
        {
            std::cout << "\n";
        }
    }
    std::cout << std::endl;
}


// Returns every chunk's decoded slots (decoded[c][slot]) so the caller can
// hand them to verify_pir_result.
std::vector<std::vector<uint64_t>> decode_pir_compressed_result(
    std::vector<Ciphertext> &loaded_columns)
{
    Plaintext chunk_pt;
    uint32_t chunk_count = pir_compressed_output_count(); // result ciphertexts: one per chunk, or per pair of chunks
    std::vector<std::vector<uint64_t>> decoded(chunk_count);
    for (uint32_t c = 0; c < chunk_count; c++)
    {
        std::vector<uint64_t> &chunk_decoded = decoded[c];
        decryptor->decrypt(loaded_columns[c], chunk_pt);
        batch_encoder->decode(chunk_pt, chunk_decoded);
    }
    return decoded;
}

// Prints every slot of every chunk decode_pir_compressed_result decoded.
// Kept separate so client.cpp can call it after the decode timing instead of
// inside it.
void print_pir_compressed_result(const std::vector<std::vector<uint64_t>> &decoded)
{
    for (size_t c = 0; c < decoded.size(); c++)
    {
        for (size_t slot = 0; slot < decoded[c].size(); slot++)
        {
            std::cout << "chunk " << c << " slot " << slot << " value=" << decoded[c][slot] << std::endl;
        }
    }
}

// Data-file cells -> the 16-bit value chunks the PIR database holds, packed
// exactly the way the Python pipeline packs them (TPCH_reformat.py's
// string_to_chunks): the cell's bytes MSB-first, two bytes per chunk, the
// last chunk zero-padded on the right - "$" -> 9216, "ad" -> 0x6164.
// pad_to_bytes > len first zero-pads the cell itself on the right (a key
// inside a bucket row, which build_bucket_pipeline.py packs at
// key_size_org/8 bytes).
void append_text_chunks(const char *s, size_t len, size_t pad_to_bytes, std::vector<uint64_t> &out)
{
    size_t total = std::max(len, pad_to_bytes);
    for (size_t i = 0; i < total; i += 2)
    {
        uint64_t hi = i < len ? (unsigned char)s[i] : 0;
        uint64_t lo = i + 1 < len ? (unsigned char)s[i + 1] : 0;
        out.push_back((hi << 8) | lo);
    }
}

bool cell_is_number(const char *s, size_t len)
{
    if (len == 0)
    {
        return false;
    }
    for (size_t i = 0; i < len; i++)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
    }
    return true;
}

uint64_t synthetic_value_chunk(uint64_t row, uint32_t idx); // defined with populate_db_synthetic_values

// set once a row of numbers or value counts has been read (row_cells_to_chunks)
// - the client then writes its retrieved row as numbers, not text
bool values_as_numbers = false;

// The values part of one data-file row (everything from `start`, just past
// the row's first field) -> its 16-bit chunks, in order. Two file shapes:
//   - raw text cells (current YCSB/TPC-H files: $,ad,yQ,... and, in bucket
//     files, !,<key>,$,<values>,!,<key>,...): every cell is packed with
//     append_text_chunks, and the cell right after each "!" is a key, packed
//     zero-padded to key_pad_bytes;
//   - numeric cells (older files, "$" already packed as 9216,...): every
//     cell is taken as the chunk it already is.
// Which shape a row is in is decided by its first value cell: the "$"/"!"
// marker in the raw shape, a number in the numeric one.
// In the raw shape, "$" followed by ONE number that ends the row or comes
// right before "!" is a value COUNT (key,$,count / ...,!,key,$,count,...):
// it becomes that many values synthetic_value_chunk(row_index, 1, 2, ...) -
// the same seeded values as the synthetic data, for file row row_index, the
// index running on across the row's counts (bucket rows). Stops at
// max_chunks (the server keeps no more than its column count).
void row_cells_to_chunks(const std::string &line, size_t start, size_t key_pad_bytes, std::vector<uint64_t> &chunks,
                         size_t max_chunks = SIZE_MAX, uint64_t row_index = 0)
{
    chunks.clear();
    const char *s = line.c_str();
    size_t n = line.size();
    while (n > start && s[n - 1] == '\r')
    {
        n--; // tolerate CRLF line endings
    }
    bool raw = true, first = true, next_is_key = false, prev_is_dollar = false;
    uint32_t value_idx = 1; // synthetic_value_chunk's idx 0 is the "$" chunk
    size_t pos = start;
    while (pos <= n && chunks.size() < max_chunks)
    {
        size_t comma = line.find(',', pos);
        size_t end = (comma == std::string::npos || comma > n) ? n : comma;
        const char *cell = s + pos;
        size_t len = end - pos;
        if (first)
        {
            raw = !cell_is_number(cell, len);
            first = false;
            values_as_numbers = values_as_numbers || !raw;
        }
        bool is_count = false;
        if (raw && prev_is_dollar && cell_is_number(cell, len))
        {
            // a count only if it ends the row or "!" comes next
            is_count = end >= n || (end + 2 <= n && s[end + 1] == '!' && (end + 2 == n || s[end + 2] == ','));
        }
        if (!raw)
        {
            chunks.push_back(static_cast<uint64_t>(std::strtoull(cell, nullptr, 10)));
        }
        else if (is_count)
        {
            uint64_t count = std::strtoull(cell, nullptr, 10);
            for (uint64_t i = 0; i < count && chunks.size() < max_chunks; i++)
            {
                chunks.push_back(synthetic_value_chunk(row_index, value_idx + (uint32_t)i));
            }
            value_idx += (uint32_t)count;
            values_as_numbers = true;
        }
        else if (len == 1 && cell[0] == '!')
        {
            append_text_chunks(cell, 1, 0, chunks);
            next_is_key = true;
        }
        else
        {
            append_text_chunks(cell, len, next_is_key ? key_pad_bytes : 0, chunks);
            next_is_key = false;
        }
        prev_is_dollar = raw && len == 1 && cell[0] == '$';
        if (end >= n)
        {
            break;
        }
        pos = end + 1;
    }
    if (chunks.size() > max_chunks)
    {
        chunks.resize(max_chunks);
    }
}

// The values part of one YCSB data-file row (everything from `start`) ->
// its 16-bit chunks, in order:
//   - each marker ("#", "!", "$") is one chunk;
//   - the cell right after "!" is a key (YCSB text, e.g. "user0000..."), its
//     own bytes zero-padded on the RIGHT to key_bytes, 2 bytes per chunk (same
//     as key_text_to_digits and make_expected_row.py);
//   - the cell right after "$" is a value SIZE in bytes: ceil(size/2) chunks
//     synthetic_value_chunk(row_index, 1, 2, ...), the index running on across
//     the row's sizes (bucket rows).
// Stops at max_chunks (the server keeps no more than its column count).
void ycsb_row_to_chunks(const std::string &line, size_t start, size_t key_bytes, std::vector<uint64_t> &chunks,
                        size_t max_chunks = SIZE_MAX, uint64_t row_index = 0)
{
    chunks.clear();
    size_t n = line.size();
    while (n > start && line[n - 1] == '\r')
    {
        n--; // tolerate CRLF line endings
    }
    bool next_is_key = false, next_is_size = false;
    uint32_t value_idx = 1; // synthetic_value_chunk's idx 0 is the "$" chunk
    size_t pos = start;
    while (pos <= n && chunks.size() < max_chunks)
    {
        size_t comma = line.find(',', pos);
        size_t end = (comma == std::string::npos || comma > n) ? n : comma;
        std::string cell = line.substr(pos, end - pos);
        if (next_is_key)
        {
            append_text_chunks(cell.data(), cell.size(), key_bytes, chunks);
            next_is_key = false;
        }
        else if (next_is_size)
        {
            uint64_t size_chunks = (std::strtoull(cell.c_str(), nullptr, 10) + 1) / 2;
            for (uint64_t i = 0; i < size_chunks && chunks.size() < max_chunks; i++)
            {
                chunks.push_back(synthetic_value_chunk(row_index, value_idx + (uint32_t)i));
            }
            value_idx += (uint32_t)size_chunks;
            next_is_size = false;
        }
        else
        {
            append_text_chunks(cell.data(), cell.size(), 0, chunks); // "#", "!", "$"
            next_is_key = cell == "!";
            next_is_size = cell == "$";
        }
        if (end >= n)
        {
            break;
        }
        pos = end + 1;
    }
    if (chunks.size() > max_chunks)
    {
        chunks.resize(max_chunks);
    }
}

// Client-side sanity check, step 1: reads the expected value row out of
// `path` - a file in the server's data file format (metadata line, header
// line, then one key,value_1,value_2,... row). Only the VALUES part of that
// row is used, converted to chunks the same way the server's populate
// functions convert theirs (row_cells_to_chunks), so the row can be copied
// as-is from a raw-text data file or hold already-packed numbers.
// key_pad_bytes: see row_cells_to_chunks (domain_size/8 for bucket rows).
// Returns the row's values in file order; empty if the file has no row.
std::vector<uint64_t> load_expected_row(const std::string &path, size_t key_pad_bytes = 0)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open expected row file: " + path);
    }

    std::vector<uint64_t> values;
    std::string line;
    std::getline(file, line); // metadata line
    std::getline(file, line); // column header line
    while (std::getline(file, line))
    {
        size_t pos1 = line.find(',');
        if (pos1 == std::string::npos)
        {
            continue;
        }
        row_cells_to_chunks(line, pos1 + 1, key_pad_bytes, values);
        break;
    }
    return values;
}

// Client-side sanity check, step 2: compares everything the client decoded
// against expected_row (see load_expected_row). decoded is one N-slot vector
// per result ciphertext - decode_pir_compressed_result's return value when
// pir_compression is on, client.cpp's decoded_columns when it's off.
//
// The client doesn't know which slot the server matched the key in, so the
// slot is recovered from the result itself: every slot holding the row's
// first value (the "$" marker chunk for datasets generated with one) is
// tried as the key's slot, and the result is correct if, for one of them,
// EVERY slot of EVERY ciphertext holds exactly what the server's layout puts
// there (and 0 everywhere else):
//   - compression off: column j is its own ciphertext, value at the key's slot
//   - compression on:  column j of chunk c is rotated to (key's slot + j)
//                      within its row, wrapping around the row's end
//                      (process_pir/get_sum)
//   - fold on:         a column holds two consecutive values of the row, the
//                      second one in the mirrored slot of the other row
//                      (populate_db)
bool verify_pir_result(const std::vector<std::vector<uint64_t>> &decoded, const std::vector<uint64_t> &expected_row,
                       uint32_t *found_key_slot = nullptr)
{
    uint32_t row_size = (uint32_t)batch_row_size;
    uint32_t values_per_column = fold_data ? 2 : 1;
    size_t ct_count = pir_compression ? (size_t)pir_compressed_output_count() : (size_t)pir_num_columns_per_obj;
    if (decoded.size() != ct_count)
    {
        std::cout << "Sanity check: expected " << ct_count << " decoded ciphertexts, got " << decoded.size() << std::endl;
        return false;
    }

    // value `part` (0, or 1 for the mirrored half under fold) of column col;
    // the server zero-fills whatever the file's row doesn't cover
    auto expected_value = [&](uint32_t col, uint32_t part) -> uint64_t
    {
        size_t idx = (size_t)col * values_per_column + part;
        return idx < expected_row.size() ? expected_row[idx] : 0ULL;
    };

    // what the server's layout puts in `slot` of ciphertext `ct` if the key
    // sits in key_slot
    auto expected_slot = [&](size_t ct, uint32_t slot, uint32_t key_slot) -> uint64_t
    {
        uint32_t slot_row = slot / row_size;
        uint32_t slot_pos = slot % row_size;
        uint32_t key_row = key_slot / row_size;
        uint32_t key_pos = key_slot % row_size;
        uint32_t chunk = (uint32_t)ct;
        if (pir_pair_merge_active())
        {
            // merge_pir_chunk_pairs: ciphertext ct holds chunk 2*ct in the key's
            // row and chunk 2*ct+1, column-rotated, in the other row
            chunk = 2 * (uint32_t)ct + (slot_row != key_row ? 1 : 0);
            if (chunk >= pir_num_chunks())
            {
                return 0ULL; // unpaired last chunk: its other row stays empty
            }
        }
        else if (!fold_data && slot_row != key_row)
        {
            return 0ULL;
        }
        uint32_t part = fold_data ? slot_row : 0;
        if (!pir_compression)
        {
            return slot_pos == key_pos ? expected_value((uint32_t)ct, part) : 0ULL;
        }
        uint32_t chunk_col_start = chunk * row_size;
        uint32_t chunk_len = std::min<uint32_t>(row_size, pir_num_columns_per_obj - chunk_col_start);
        uint32_t local_col = (slot_pos + row_size - key_pos) % row_size;
        return local_col < chunk_len ? expected_value(chunk_col_start + local_col, part) : 0ULL;
    };

    size_t compared_values = std::min<size_t>(expected_row.size(), (size_t)pir_num_columns_per_obj * values_per_column);
    uint32_t candidate_count = fold_data ? row_size : (uint32_t)N;
    uint32_t candidates_tried = 0;
    bool have_mismatch = false;
    size_t mismatch_ct = 0;
    uint32_t mismatch_slot = 0, mismatch_key_slot = 0;
    for (uint32_t key_slot = 0; key_slot < candidate_count; key_slot++)
    {
        if (decoded[0][key_slot] != expected_value(0, 0))
        {
            continue;
        }
        candidates_tried++;
        bool match = true;
        for (size_t ct = 0; ct < ct_count && match; ct++)
        {
            for (uint32_t slot = 0; slot < (uint32_t)N; slot++)
            {
                if (decoded[ct][slot] != expected_slot(ct, slot, key_slot))
                {
                    match = false;
                    if (!have_mismatch)
                    {
                        have_mismatch = true;
                        mismatch_ct = ct;
                        mismatch_slot = slot;
                        mismatch_key_slot = key_slot;
                    }
                    break;
                }
            }
        }
        if (match)
        {
            std::cout << "Sanity check: key found in slot " << key_slot << ", all " << compared_values
                      << " values of its row match (" << expected_row.size() << " in the expected row file)" << std::endl;
            if (found_key_slot)
            {
                *found_key_slot = key_slot;
            }
            return true;
        }
    }

    if (candidates_tried == 0)
    {
        std::cout << "Sanity check: the row's first value (" << expected_value(0, 0) << ") is not anywhere in the result" << std::endl;
    }
    else
    {
        std::cout << "Sanity check: mismatch in ciphertext " << mismatch_ct << " slot " << mismatch_slot
                  << " (assuming the key is in slot " << mismatch_key_slot << "): got " << decoded[mismatch_ct][mismatch_slot]
                  << ", expected " << expected_slot(mismatch_ct, mismatch_slot, mismatch_key_slot) << std::endl;
    }
    return false;
}

// The retrieved row's chunks, in row order, read out of the decoded result
// given the slot the key sits in (from verify_pir_result) - the inverse of
// the layout verify_pir_result's expected_slot describes.
std::vector<uint64_t> retrieved_row_chunks(const std::vector<std::vector<uint64_t>> &decoded, uint32_t key_slot)
{
    uint32_t row_size = (uint32_t)batch_row_size;
    uint32_t values_per_column = fold_data ? 2 : 1;
    uint32_t key_row = key_slot / row_size;
    uint32_t key_pos = key_slot % row_size;
    std::vector<uint64_t> row;
    row.reserve((size_t)pir_num_columns_per_obj * values_per_column);
    for (uint32_t col = 0; col < (uint32_t)pir_num_columns_per_obj; col++)
    {
        for (uint32_t part = 0; part < values_per_column; part++)
        {
            size_t ct;
            uint32_t slot;
            if (!pir_compression)
            {
                ct = col;
                slot = fold_data ? part * row_size + key_pos : key_slot;
            }
            else
            {
                uint32_t chunk = col / row_size;
                uint32_t pos = (key_pos + col % row_size) % row_size;
                uint32_t slot_row;
                if (pir_pair_merge_active())
                {
                    ct = chunk / 2;
                    slot_row = chunk % 2 == 0 ? key_row : 1 - key_row;
                }
                else
                {
                    ct = chunk;
                    slot_row = fold_data ? part : key_row;
                }
                slot = slot_row * row_size + pos;
            }
            row.push_back(decoded[ct][slot]);
        }
    }
    return row;
}

// One line of the client's retrieved row file: the chunks either as numbers
// (synthetic values) or as text the way the data file holds it - each chunk
// back to its 2-byte string ("ad,yQ,u7"), NUL padding dropped, the "$"/"!"
// markers their own cells and, in bucket rows, the key after each "!" (packed
// at key_pad_bytes) one cell. Trailing zero chunks (the server's zero-fill
// past the end of the row) are left out.
std::string format_retrieved_row(const std::vector<uint64_t> &chunks, bool as_text, size_t key_pad_bytes = 0)
{
    size_t n = chunks.size();
    while (n > 0 && chunks[n - 1] == 0)
    {
        n--;
    }
    std::string out;
    size_t key_chunks = (key_pad_bytes + 1) / 2;
    for (size_t i = 0; i < n;)
    {
        if (i > 0)
        {
            out += ',';
        }
        size_t take = 1;
        if (as_text && i > 0 && chunks[i - 1] == ('!' << 8) && key_chunks > 0)
        {
            take = std::min(key_chunks, n - i); // bucket row: the key after "!"
        }
        for (size_t j = i; j < i + take; j++)
        {
            if (!as_text)
            {
                out += std::to_string(chunks[j]);
                continue;
            }
            char hi = (char)((chunks[j] >> 8) & 0xFF);
            char lo = (char)(chunks[j] & 0xFF);
            if (hi)
            {
                out += hi;
            }
            if (lo)
            {
                out += lo;
            }
        }
        i += take;
    }
    return out;
}

// Server-side one-time setup for query compression: computes the fixed
// query_chunk_plan/query_chunk_offset and builds masks[m][local_i], which
// expand_query (this file) uses every round to rebuild expanded_query[]
// (one ciphertext per real digit) from the compact server_query_ct[] the
// client actually sends. Always sets expanded_slot_count (needed for
// sizing expanded_query regardless of whether query_expansion is on);
// only builds the chunk plan/masks themselves when it is.
// The chunk plan both sides use: the default one ciphertext per power of two (Strategy D), or with -p 1 a single
// ciphertext padded to the next power of two holding every real digit.
static QueryChunkPlan make_query_chunk_plan(int expanded_slot_count)
{
    if (single_query_ciphertext)
    {
        QueryChunkPlan plan;
        plan.real.push_back(expanded_slot_count);
        plan.capacity.push_back(get_next_power_of_two(expanded_slot_count));
        return plan;
    }
    int greedy_x = count_set_bits(expanded_slot_count);
    return build_greedy_chunk_plan(expanded_slot_count, greedy_x > 0 ? greedy_x : 1);
}

void setup_query_expansion()
{
    expanded_slot_count = unary_encoding ? encoding_size : (encoding_size + 1);
    if (!query_expansion)
    {
        return;
    }
    query_chunk_plan = make_query_chunk_plan(expanded_slot_count);
    std::cout << "Query chunk plan: ";
    for (int c : query_chunk_plan.capacity)
        std::cout << c << " ";
    std::cout << std::endl;
    actual_ciphertext_count = (int)query_chunk_plan.capacity.size();
    query_chunk_offset.resize(actual_ciphertext_count);
    int running = 0;
    for (int m = 0; m < actual_ciphertext_count; m++)
    {
        query_chunk_offset[m] = running;
        running += query_chunk_plan.real[m];
    }
    server_query_ct = new Ciphertext[actual_ciphertext_count];

    // preparing mask
    masks.assign(actual_ciphertext_count, {});
    for (int m = 0; m < actual_ciphertext_count; m++)
    {
        int capacity = query_chunk_plan.capacity[m];
        for (int local_i = 0; local_i < capacity; local_i++)
        {
            vector<uint64_t> mat(N, 0ULL);
            Plaintext pt;
            for (int j = local_i * (N / (2 * capacity)); j < (local_i + 1) * (N / (2 * capacity)); j++)
            {
                mat[j] = mat[j + (N / 2)] = 1;
            }
            batch_encoder->encode(mat, pt);
            evaluator->transform_to_ntt_inplace(pt, pid);
            masks[m].push_back(pt);
        }
    }
}

// Client-side counterpart to setup_query_expansion(): computes the same
// fixed query_chunk_plan (no masks - the client packs digit_indices
// directly in build_compressed_query, it doesn't need them) plus
// digit_offset/total_capacity, which the caller uses to size digit_indices
// before the run loop. Only called when query_expansion is on; leaves
// total_capacity at its default (encoding_size) otherwise.
void setup_query_expansion_client()
{
    int expanded_slot_count_local = unary_encoding ? encoding_size : (encoding_size + 1);
    query_chunk_plan = make_query_chunk_plan(expanded_slot_count_local);

    std::cout << "Query chunk plan:\n ";
    for (int c : query_chunk_plan.capacity)
        std::cout << c << " ";
    std::cout << std::endl;
    total_capacity = 0;
    for (int c : query_chunk_plan.capacity)
        total_capacity += c;
    digit_offset.resize(query_chunk_plan.capacity.size());
    int running_offset = 0;
    for (size_t m = 0; m < query_chunk_plan.capacity.size(); m++)
    {
        digit_offset[m] = running_offset;
        running_offset += query_chunk_plan.capacity[m];
    }
}

// Server-side per-round query expansion for the query_expansion path only:
// runs expand_query on the packed ciphertexts server.cpp has already loaded
// into server_query_ct[] - spawned across
// NUM_ENCODING_THREAD threads, mirroring process_rows' own thread-budget
// pattern - to rebuild expanded_query[]/expanded_query_sum from them, the
// same shape the plain (non-compressed) path produces directly. The caller
// is responsible for branching on query_expansion; this function assumes
// it's on.
void expand_query_call()
{
    std::cout << "expanded_slot_count: " << expanded_slot_count << std::endl;
    NUM_ENCODING_THREAD = std::min(expanded_slot_count, NUM_THREAD);
    NUM_EXPANSION_THREAD = std::max(1, NUM_THREAD / NUM_ENCODING_THREAD);
    std::cout << "Number of encoding threads (query expansion): " << NUM_ENCODING_THREAD << std::endl;
    std::cout << "Number of expansion threads (query expansion): " << NUM_EXPANSION_THREAD << std::endl;
    std::cout << "Number of spare threads (query expansion): " << NUM_THREAD - NUM_ENCODING_THREAD * NUM_EXPANSION_THREAD << std::endl;

    if (NUM_ENCODING_THREAD > query_expansion_thread_capacity)
    {
        delete[] query_expansion_thread;
        delete[] expansion_thread_id;
        query_expansion_thread = new pthread_t[NUM_ENCODING_THREAD];
        expansion_thread_id = new int[NUM_ENCODING_THREAD];
        for (int i = 0; i < NUM_ENCODING_THREAD; i++)
        {
            expansion_thread_id[i] = i;
        }
        query_expansion_thread_capacity = NUM_ENCODING_THREAD;
    }
    for (int i = 0; i < NUM_ENCODING_THREAD; i++)
    {
        if (pthread_create(&(query_expansion_thread[i]), NULL, expand_query, (void *)&(expansion_thread_id[i])))
        {
            printf("Error creating expansion thread");
        }
    }
    for (int i = 0; i < NUM_ENCODING_THREAD; i++)
    {
        pthread_join(query_expansion_thread[i], NULL);
    }

    if (!unary_encoding)
    {
        *expanded_query_sum = expanded_query[encoding_size];
        my_transform_from_ntt_inplace(*context, *expanded_query_sum, NUM_THREAD);
    }
}

//**************Populate Database********************/

struct DataDistRecord
{
    uint64_t key;
    std::vector<uint64_t> values;
};
std::vector<DataDistRecord> load_data_dist_file(const std::string &path)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open data distribution file: " + path);
    }

    std::vector<DataDistRecord> records;
    std::string line;

    std::getline(file, line); // metadata line: max_row_size,<N>,num_keys,<M>
    std::getline(file, line); // header line: key,num_orders,value_chunks...

    while (std::getline(file, line))
    {
        if (line.empty())
        {
            continue;
        }

        std::vector<uint64_t> fields;
        std::stringstream line_ss(line);
        std::string field;
        while (std::getline(line_ss, field, ','))
        {
            fields.push_back(static_cast<uint64_t>(std::stoull(field)));
        }

        if (fields.size() < 2)
        {
            continue;
        }

        DataDistRecord record;
        record.key = fields[0];
        record.values.assign(fields.begin() + 2, fields.end());
        records.push_back(std::move(record));
    }

    if (records.empty())
    {
        throw std::runtime_error("No records found in data distribution file: " + path);
    }

    std::cout << "Loaded " << records.size() << " key-value records from " << path << std::endl;
    return records;
}

void init_pir_params()
{
    pir_plain_bit_count = 16;                                                            // number of bits in each plaintext slot for PIR
    pir_num_obj = ((fold_data ? N / 2 : N) * batch_count_for_keys);                      // total number of keys in the database
    pir_num_columns_per_obj = (ceil(((value_size) * 8) / (float)(pir_plain_bit_count))); // number of columns associated with each key in the database
    if (fold_data)
    {
        pir_num_columns_per_obj = (uint32_t)ceil(pir_num_columns_per_obj / 2.0);
    }
    pir_db_rows = batch_count_for_keys * pir_num_columns_per_obj; // number of batches made only from values                      // FHE batches formed from value part

    std::cout << "PIR params: " << std::endl;
    std::cout << "Number of keys batches: " << batch_count_for_keys << std::endl;
    std::cout << "Number of columns (for values) per key: " << (fold_data ? pir_num_columns_per_obj * 2 : pir_num_columns_per_obj) << std::endl;
    std::cout << "Size of PIR DB (number of FHE batches * number of columns): " << pir_db_rows << std::endl;
    return;
}

std::vector<int> selected_bit;
// Actual key size in bits when using bucketization (client's -o / server's
// -o) - shared here like the other bucketization globals above instead of
// each of client.cpp/server.cpp declaring their own separate copy.
int domain_size = 0;

struct DataDistMetadata
{
    uint64_t num_buckets = 0;
    uint64_t max_bucket_size = 0;
    int key_size = 0;
    std::vector<int> selected_bit;
};

// Parses a data distribution file's metadata line: comma-separated
// key=value pairs, e.g. "key_size=15,num_buckets=32768,num_distinct_keys=
// 100000,N=86673659,max_bucket_size=5181,selected_bit=[16, 18, 19, ..., 31]".
// A naive comma split breaks on selected_bit=[...]'s internal commas, so
// this tracks bracket depth and only splits on top-level commas.
DataDistMetadata parse_data_dist_metadata(const std::string &line)
{
    std::vector<std::string> kv_pairs;
    {
        int depth = 0;
        std::string current;
        for (char c : line)
        {
            if (c == '[')
            {
                depth++;
            }
            if (c == ']')
            {
                depth--;
            }
            if (c == ',' && depth == 0)
            {
                kv_pairs.push_back(current);
                current.clear();
            }
            else
            {
                current += c;
            }
        }
        if (!current.empty())
        {
            kv_pairs.push_back(current);
        }
    }

    DataDistMetadata meta;
    for (const std::string &kv : kv_pairs)
    {
        size_t eq = kv.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        std::string field_name = kv.substr(0, eq);
        std::string field_value = kv.substr(eq + 1);
        // Trim leading/trailing whitespace - fields after the first one can
        // have a leading space (e.g. "max_bucket_size=5181, selected_bit=[...]").
        auto trim = [](std::string &s)
        {
            size_t start = s.find_first_not_of(" \t");
            if (start == std::string::npos)
            {
                s.clear();
                return;
            }
            size_t end = s.find_last_not_of(" \t");
            s = s.substr(start, end - start + 1);
        };
        trim(field_name);
        trim(field_value);
        if (field_name == "num_buckets")
        {
            meta.num_buckets = std::stoull(field_value);
        }
        else if (field_name == "max_bucket_size")
        {
            meta.max_bucket_size = std::stoull(field_value);
        }
        else if (field_name == "key_size")
        {
            meta.key_size = std::stoi(field_value);
        }
        else if (field_name == "selected_bit")
        {
            size_t lb = field_value.find('[');
            size_t rb = field_value.find(']');
            std::string inner = (lb != std::string::npos && rb != std::string::npos)
                                    ? field_value.substr(lb + 1, rb - lb - 1)
                                    : field_value;
            std::stringstream bits_ss(inner);
            std::string bit_str;
            while (std::getline(bits_ss, bit_str, ','))
            {
                size_t start = bit_str.find_first_not_of(" \t");
                if (start == std::string::npos)
                {
                    continue;
                }
                size_t end = bit_str.find_last_not_of(" \t");
                meta.selected_bit.push_back(std::stoi(bit_str.substr(start, end - start + 1)));
            }
        }
    }

    if (meta.num_buckets == 0 || meta.max_bucket_size == 0 || meta.key_size == 0 || meta.selected_bit.empty())
    {
        throw std::runtime_error(
            "Data distribution file metadata line missing a required field "
            "(num_buckets/max_bucket_size/key_size/selected_bit): " +
            line);
    }
    if ((int)meta.selected_bit.size() != meta.key_size)
    {
        throw std::runtime_error(
            "Data distribution file metadata: selected_bit length (" + std::to_string(meta.selected_bit.size()) +
            ") does not match key_size (" + std::to_string(meta.key_size) + ")");
    }
    return meta;
}

uint64_t digit_at_position(uint64_t key, uint32_t base, int position)
{
    uint64_t divisor = 1;
    for (int i = 0; i < position; i++)
    {
        divisor *= base;
    }
    return (key / divisor) % base;
}

// Decodes a hex-digit string (2 hex chars per byte, e.g. "1C80317FA3B1799D")
// into the raw byte values it encodes, returned as a std::string where each
// character holds one decoded byte value - the same "raw bytes" convention
// string_to_base_digits expects as input.
std::string hex_string_to_bytes(const std::string &hex)
{
    std::string bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
        bytes.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::vector<int> string_to_base_digits(const std::string &input, int base, int num_digits)
{
    std::vector<uint8_t> num(input.begin(), input.end());
    std::vector<int> digits; // collected least-significant-digit-first

    while (!(num.size() == 1 && num[0] == 0))
    {
        uint64_t remainder = 0;
        std::vector<uint8_t> quotient;
        quotient.reserve(num.size());
        bool leading_zero = true;
        for (uint8_t byte : num)
        {
            uint64_t acc = remainder * 256 + byte;
            uint8_t q_digit = static_cast<uint8_t>(acc / base);
            remainder = acc % base;
            if (leading_zero && q_digit == 0)
            {
                continue; // drop leading zero bytes from the quotient
            }
            leading_zero = false;
            quotient.push_back(q_digit);
        }
        digits.push_back(static_cast<int>(remainder));
        if (quotient.empty())
        {
            num.assign(1, 0);
        }
        else
        {
            num = std::move(quotient);
        }
    }

    std::reverse(digits.begin(), digits.end()); // now most-significant-digit-first

    if ((int)digits.size() < num_digits)
    {
        digits.insert(digits.begin(), num_digits - digits.size(), 0);
    }
    else if ((int)digits.size() > num_digits)
    {
        // Keep the least-significant num_digits digits (drop overflow from the top).
        digits.erase(digits.begin(), digits.begin() + (digits.size() - num_digits));
    }
    return digits;
}

// A decimal digit string -> the big-endian bytes of the same number.
std::string decimal_string_to_bytes(const std::string &dec)
{
    std::vector<uint8_t> num(1, 0);
    for (char ch : dec)
    {
        uint32_t carry = (uint32_t)(ch - '0');
        for (int i = (int)num.size() - 1; i >= 0; i--)
        {
            uint32_t v = num[i] * 10u + carry;
            num[i] = (uint8_t)(v & 0xFF);
            carry = v >> 8;
        }
        while (carry)
        {
            num.insert(num.begin(), (uint8_t)(carry & 0xFF));
            carry >>= 8;
        }
    }
    return std::string(num.begin(), num.end());
}

// A key (or bucket id) as it appears in a data file -> num_digits base-`base`
// digits, most significant first - the same conversion the Python pipeline
// uses (build_bucket_pipeline.py's key_field_to_int + key_to_bits), so the
// server, the client and the pipeline's bucket ids all agree:
//   - a key made only of decimal digits (TPC-H's custkey, a bucket id) is
//     that number;
//   - any other key (YCSB's "user-6284781860667377211", the synthetic keys)
//     is its own bytes, big-endian, zero-padded on the RIGHT to key_bits/8
//     bytes.
std::vector<int> key_text_to_digits(const std::string &key, int key_bits, int base, int num_digits)
{
    if (cell_is_number(key.c_str(), key.size()))
    {
        return string_to_base_digits(decimal_string_to_bytes(key), base, num_digits);
    }
    std::string padded = key;
    if ((int)padded.size() < key_bits / 8)
    {
        padded.append(key_bits / 8 - padded.size(), '\0');
    }
    return string_to_base_digits(padded, base, num_digits);
}

uint32_t extract_query_digits_from_digits(const std::vector<int> &key_digits, std::vector<uint64_t> &out)
{
    uint32_t sum = 0;
    std::vector<int> selected_digits;
    const std::vector<int> *digits_ptr = &key_digits;
    if (bucketization)
    {
        // key_digits are the key's BASE-2 bits; the selected bits, in order,
        // are the bucket id (a key_size-bit number), which is then written as
        // digits_in_power_of_two(key_size, base) base-`base` digits - the same
        // as the server's populate_db does with the bucket id it reads from
        // the file
        size_t bit_count = selected_bit.size();
        std::string id_bytes((bit_count + 7) / 8, '\0');
        for (size_t c = 0; c < bit_count; c++)
        {
            if (selected_bit[c] < 0 || selected_bit[c] >= (int)key_digits.size())
            {
                throw std::runtime_error("selected bit " + std::to_string(selected_bit[c]) + " is outside the key's " +
                                         std::to_string(key_digits.size()) + " bits");
            }
            if (key_digits[selected_bit[c]])
            {
                size_t pos = bit_count - 1 - c; // bit position from the right
                id_bytes[id_bytes.size() - 1 - pos / 8] |= (char)(1 << (pos % 8));
            }
        }
        selected_digits = string_to_base_digits(id_bytes, base, digits_in_power_of_two(key_size, base));
        digits_ptr = &selected_digits;
    }
    const std::vector<int> &digits = *digits_ptr;
    int digits_len = (int)digits.size();
    if (unary_encoding)
    {
        for (int c = 0; c < digits_len; c++)
        {
            int pos = digits_len - 1 - c;
            uint32_t digit = static_cast<uint32_t>(digits[c]);
            for (uint32_t d = 0; d < base; d++)
            {
                out[pos * base + d] = (d == digit) ? 1 : 0;
            }
        }
    }
    else
    {
        for (int c = 0; c < digits_len; c++)
        {
            int pos = digits_len - 1 - c;
            uint64_t digit = static_cast<uint64_t>(digits[c]);
            out[pos] = digit;
            sum += digit * digit;
        }
    }
    return sum;
}

void save_query_ciphertext(Plaintext &pt, std::ostream &out)
{
    if (seeded_serialization)
    {
        Serializable<Ciphertext> ser_query = encryptor->encrypt_symmetric(pt);
        ser_query.save(out);
    }
    else
    {
        Ciphertext ct;
        encryptor->encrypt_symmetric(pt, ct);
        ct.save(out);
    }
}

// Client-side per-round query build for the query_expansion path: packs
// digit_indices into query_chunk_plan.capacity.size() ciphertexts instead
// of one ciphertext per digit like the plain path - chunk m's real digit
// values go into narrow per-position slot-blocks (both BFV row-halves),
// mirroring masks[m][local_i]'s layout server-side (setup_query_expansion/
// expand_query in this file) so the server can reconstruct the per-digit
// ciphertexts expand_query on the server side needs. The caller is
// responsible for branching on query_expansion; this function assumes
// it's on.
std::string build_compressed_query(const std::vector<uint64_t> &digit_indices, const std::vector<int> &digit_offset)
{
    std::string query_bytes;
    size_t chunk_count = query_chunk_plan.capacity.size();
    if (NUM_THREAD <= 1)
    {
        std::ostringstream qout;
        for (size_t m = 0; m < chunk_count; m++)
        {
            int capacity = query_chunk_plan.capacity[m];
            std::vector<uint64_t> local_mat(N, 0ULL);
            for (int i = 0; i < capacity; ++i)
            {
                int digit_idx = digit_offset[m] + i;
                int start = i * batch_row_size / capacity;
                int end = (i + 1) * batch_row_size / capacity;
                for (int j = start; j < end; ++j)
                {
                    local_mat[j] = digit_indices[digit_idx];
                    local_mat[j + batch_row_size] = digit_indices[digit_idx];
                }
            }
            Plaintext local_pt;
            batch_encoder->encode(local_mat, local_pt);
            save_query_ciphertext(local_pt, qout);
        }
        query_bytes = qout.str();
    }
    else
    {
        std::vector<std::string> expansion_ciphertext_bytes(chunk_count);
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
        for (size_t m = 0; m < chunk_count; m++)
        {
            int capacity = query_chunk_plan.capacity[m];
            std::vector<uint64_t> local_mat(N, 0ULL);
            for (int i = 0; i < capacity; ++i)
            {
                int digit_idx = digit_offset[m] + i;
                int start = i * batch_row_size / capacity;
                int end = (i + 1) * batch_row_size / capacity;
                for (int j = start; j < end; ++j)
                {
                    local_mat[j] = digit_indices[digit_idx];
                    local_mat[j + batch_row_size] = digit_indices[digit_idx];
                }
            }
            Plaintext local_pt;
            batch_encoder->encode(local_mat, local_pt);
            std::ostringstream local_out;
            save_query_ciphertext(local_pt, local_out);
            expansion_ciphertext_bytes[m] = local_out.str();
        }
        for (size_t m = 0; m < chunk_count; m++)
        {
            query_bytes += expansion_ciphertext_bytes[m];
        }
    }
    return query_bytes;
}

// Client-side counterpart to populate_db()'s file reading, but far cheaper:
// reads only the metadata line (populating the selected_bit/key_size/
// pir_num_columns_per_obj globals as a side effect - the same values
// populate_db() derives server-side, so the two sides agree on ciphertext
// shapes without the client needing a matching -k/-v) and the first data
// row, then reconstructs that row's original integer key from its digit
// string via the inverse of the selected_bit extraction (see
// extract_query_digits in client.cpp): key = sum over c of
// (digit_string[c]-'0') * base^selected_bit[c]. Stops reading immediately
// after the first data row - never scans the rest of the (potentially
// multi-hundred-MB) file.
uint64_t read_first_query_key_from_file(const std::string &path, uint32_t base)
{
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open data distribution file: " + path);
    }
    std::string line;
    std::getline(file, line); // metadata line
    DataDistMetadata meta = parse_data_dist_metadata(line);
    key_size = meta.key_size;
    selected_bit = meta.selected_bit;
    pir_num_columns_per_obj = static_cast<uint32_t>(meta.max_bucket_size);

    std::getline(file, line); // column header line, skipped
    std::getline(file, line); // first data row
    std::stringstream row_ss(line);
    std::string digit_string;
    std::getline(row_ss, digit_string, ',');
    if ((int)digit_string.size() != meta.key_size)
    {
        throw std::runtime_error(
            "Data distribution file: first row's key digit-string length (" + std::to_string(digit_string.size()) +
            ") does not match metadata key_size (" + std::to_string(meta.key_size) + ")");
    }

    uint64_t key = 0;
    for (int c = 0; c < meta.key_size; c++)
    {
        uint64_t digit = digit_string[c] - '0';
        uint64_t place = 1;
        for (int i = 0; i < meta.selected_bit[c]; i++)
        {
            place *= base;
        }
        key += digit * place;
    }
    return key;
}
// Old version - keys[row] was a uint64_t magnitude, decomposed into base-B
// digits via tmp%base/tmp/=base. Superseded below by the version taking
// keys[row] as a pre-computed vector<int> digit array (from
// string_to_base_digits), matching how file_key_digits already works.
// void encode_key_batches(const std::vector<uint64_t> &keys)
// {
//     int digits_len = unary_encoding ? (encoding_size / base) : encoding_size;
//     int digits_power_two = (!read_from_file && unary_encoding) ? digits_in_power_of_two(key_size, base) : 0;
//
//     for (int br = 0; br < batch_count_for_keys; br++)
//     {
//         vector<vector<uint64_t>> mat_db_batch(encoding_size, vector<uint64_t>(N, 0ULL));
//         vector<uint64_t> mat_db_sum_batch;
//         if (!unary_encoding)
//         {
//             mat_db_sum_batch.assign(N, 0ULL);
//         }
//
//         uint32_t row_start = (uint32_t)br * N;
//         uint32_t row_end = row_start + N;
//
//         if (read_from_file)
//         {
//             for (uint32_t row = row_start; row < row_end; row++)
//             {
//                 uint32_t col = row - row_start;
//                 const std::vector<int> &digit_string = file_key_digits[row];
//                 uint64_t sum = 0;
//                 for (int c = 0; c < digits_len; c++)
//                 {
//                     int pos = digits_len - 1 - c;
//                     uint64_t digit = digit_string[c];
//                     if (unary_encoding)
//                     {
//                         mat_db_batch[pos * base + digit][col] = 1;
//                     }
//                     else
//                     {
//                         mat_db_batch[pos][col] = digit * 2;
//                         sum += digit * digit;
//                     }
//                 }
//                 if (!unary_encoding)
//                 {
//                     mat_db_sum_batch[col] = sum;
//                 }
//             }
//         }
//         else if (unary_encoding)
//         {
//             for (uint32_t row = row_start; row < row_end; row++)
//             {
//                 uint32_t col = row - row_start;
//                 uint64_t tmp = keys[row];
//                 for (int pos = 0; pos < digits_power_two; pos++)
//                 {
//                     uint64_t digit = tmp % base;
//                     tmp /= base;
//                     mat_db_batch[pos * base + digit][col] = 1;
//                 }
//             }
//         }
//         else
//         {
//             std::vector<uint64_t> digits(encoding_size, 0);
//             for (uint32_t row = row_start; row < row_end; row++)
//             {
//                 uint32_t col = row - row_start;
//                 uint64_t tmp = keys[row];
//                 uint64_t sum = 0;
//                 for (int i = 0; i < encoding_size; i++)
//                 {
//                     digits[i] = (tmp % base) * 2;
//                     sum += (tmp % base) * (tmp % base);
//                     tmp /= base;
//                 }
//                 mat_db_sum_batch[col] = sum;
//                 for (int c = 0; c < encoding_size; c++)
//                 {
//                     mat_db_batch[c][col] = digits[c];
//                 }
//             }
//         }
//
//         // std::cout << "Encoding batch " << br << " of " << batch_count_for_keys << std::endl;
//         vector<Plaintext> row_partition;
//         row_partition.reserve(encoding_size);
//         for (int j = 0; j < encoding_size; j++)
//         {
//             Plaintext pt;
//             batch_encoder->encode(mat_db_batch[j], pt);
//             // std::cout << "Batch " << br << ", row " << j << ": ";
//             // print_plaintext_slots(pt, 10);
//             evaluator->transform_to_ntt_inplace(pt, pid);
//             row_partition.push_back(std::move(pt));
//         }
//         db.push_back(std::move(row_partition));
//
//         if (!unary_encoding)
//         {
//             Plaintext pt_sum;
//             batch_encoder->encode(mat_db_sum_batch, pt_sum);
//             db_sum.push_back(std::move(pt_sum));
//         }
//     }
// }

void encode_key_batches(const std::vector<std::vector<int>> &keys)
{
    int digits_len = unary_encoding ? (encoding_size / base) : encoding_size;

    for (int br = 0; br < batch_count_for_keys; br++)
    {
        vector<vector<uint64_t>> mat_db_batch(encoding_size, vector<uint64_t>(N, 0ULL));
        vector<uint64_t> mat_db_sum_batch;
        if (!unary_encoding)
        {
            mat_db_sum_batch.assign(N, 0ULL);
        }

        uint32_t row_start = (uint32_t)br * N;
        uint32_t row_end = row_start + N;

        const std::vector<std::vector<int>> &digit_source = file_key_digits;
        for (uint32_t row = row_start; row < row_end; row++)
        {
            uint32_t col = row - row_start;
            const std::vector<int> &digit_string = digit_source[row];
            uint64_t sum = 0;
            for (int c = 0; c < digits_len; c++)
            {
                int pos = digits_len - 1 - c;
                uint64_t digit = digit_string[c];
                if (unary_encoding)
                {
                    mat_db_batch[pos * base + digit][col] = 1;
                }
                else
                {
                    mat_db_batch[pos][col] = digit * 2;
                    sum += digit * digit;
                }
            }
            if (!unary_encoding)
            {
                mat_db_sum_batch[col] = sum;
            }
        }

        // std::cout << "Encoding batch " << br << " of " << batch_count_for_keys << std::endl;
        vector<Plaintext> row_partition;
        row_partition.reserve(encoding_size);
        for (int j = 0; j < encoding_size; j++)
        {
            Plaintext pt;
            batch_encoder->encode(mat_db_batch[j], pt);
            // std::cout << "Batch " << br << ", row " << j << ": ";
            // print_plaintext_slots(pt, 10);
            // evaluator->transform_to_ntt_inplace(pt, pid);
            row_partition.push_back(std::move(pt));
        }
        db.push_back(std::move(row_partition));

        if (!unary_encoding)
        {
            Plaintext pt_sum;
            batch_encoder->encode(mat_db_sum_batch, pt_sum);
            db_sum.push_back(std::move(pt_sum));
        }
    }
}

void set_pir_db(const std::vector<std::vector<uint64_t>> &db)
{
    pir_encoded_db = std::vector<seal::Plaintext>(pir_db_rows);
    std::vector<uint64_t> row_vec(N, 1ULL);
    for (uint32_t row = 0; row < pir_db_rows; row++)
    {
        uint32_t br = row % batch_count_for_keys;
        uint32_t j = row / batch_count_for_keys;
        for (uint32_t col = 0; col < (uint32_t)N; col++)
        {
            row_vec[col] = db[br * N + col][j];
        }

        // std::cout << "Encoding PIR DB row " << row << " of " << pir_db_rows << std::endl;
        batch_encoder->encode(row_vec, pir_encoded_db[row]);
        // print_plaintext_slots(pir_encoded_db[row], 10);
        evaluator->transform_to_ntt_inplace(pir_encoded_db[row], compact_pid);
    }
}

// Windowed counterpart to set_pir_db: encodes pir_encoded_db entries for
// just the real-column range [col_start, col_start+num_cols) from
// group_vals[obj][local_col] (obj = global object index 0..batch_count_for_keys*N-1,
// local_col in [0,num_cols) - the same content set_pir_db's full-matrix `db`
// would hold at db[obj][col_start+local_col]). Exists so
// populate_db_synthetic can generate+encode a few columns at a time instead
// of materializing the whole batch_count_for_keys*N x pir_num_columns_per_obj
// matrix in memory at once (that matrix alone is 4x the size of the actual
// value data, since it stores each 16-bit value chunk in a full uint64_t).
// pir_encoded_db must already be sized (pir_db_rows) by the caller.
void encode_pir_columns(uint32_t col_start, uint32_t num_cols, const std::vector<std::vector<uint64_t>> &group_vals)
{
    std::vector<uint64_t> row_vec(N, 0ULL);
    for (uint32_t local_col = 0; local_col < num_cols; local_col++)
    {
        uint32_t col = col_start + local_col;
        for (uint32_t br = 0; br < (uint32_t)batch_count_for_keys; br++)
        {
            uint32_t row = col * (uint32_t)batch_count_for_keys + br;
            for (uint32_t obj = 0; obj < (uint32_t)N; obj++)
            {
                row_vec[obj] = group_vals[br * N + obj][local_col];
            }
            batch_encoder->encode(row_vec, pir_encoded_db[row]);
            evaluator->transform_to_ntt_inplace(pir_encoded_db[row], compact_pid);
        }
    }
}

// Old version: builds the full batch_count_for_keys*N key-digit (file_key_digits)
// and value (pir_db) matrices before encoding anything.
// void populate_db()
// {
//     std::vector<std::vector<int>> keys(batch_count_for_keys * N);
//     std::vector<std::vector<uint64_t>> pir_db((size_t)batch_count_for_keys * N);
//
//     std::cout << "Populating keys and values from file...\n";
//     std::ifstream file(data_dist_file);
//     if (!file.is_open())
//     {
//         throw std::runtime_error("Could not open data distribution file: " + data_dist_file);
//     }
//
//     std::string line;
//     std::getline(file, line); // metadata line, not parsed (see file_key_digits' comment)
//     std::getline(file, line); // column header line, skipped
//
//     file_key_digits.resize(keys.size());
//     int file_key_digit_count = bucketization ? key_size : digits_in_power_of_two(key_size, base);
//     std::vector<int> row_digits(file_key_digit_count);
//     uint32_t half_batch = fold_data ? (uint32_t)(N / 2) : (uint32_t)N;
//     uint32_t logical_rows_needed = batch_count_for_keys * half_batch;
//     uint32_t rows_loaded = 0;
//     while (rows_loaded < logical_rows_needed && std::getline(file, line))
//     {
//         if (line.empty())
//         {
//             continue;
//         }
//         size_t pos1 = line.find(',');
//         size_t pos2 = (pos1 == std::string::npos) ? std::string::npos : line.find(',', pos1 + 1);
//         size_t pos3 = (pos2 == std::string::npos) ? std::string::npos : line.find(',', pos2 + 1);
//         size_t pos4 = (pos3 == std::string::npos) ? std::string::npos : line.find(',', pos3 + 1);
//         if (pos4 == std::string::npos)
//         {
//             continue;
//         }
//         size_t key_start = pos1 + 1;
//         size_t key_len = pos2 - key_start;
//
//         if (bucketization)
//         {
//             row_digits.clear();
//             size_t start = key_start;
//             while (start <= pos2)
//             {
//                 size_t dash = line.find('-', start);
//                 if (dash == std::string::npos || dash >= pos2)
//                 {
//                     row_digits.push_back(std::stoi(line.substr(start, pos2 - start)));
//                     break;
//                 }
//                 row_digits.push_back(std::stoi(line.substr(start, dash - start)));
//                 start = dash + 1;
//             }
//         }
//         else
//         {
//             row_digits = string_to_base_digits(hex_string_to_bytes(line.substr(key_start, key_len)), base, file_key_digit_count);
//         }
//         uint32_t batch_idx = rows_loaded / half_batch;
//         uint32_t col_in_half = rows_loaded % half_batch;
//         uint32_t i = batch_idx * (uint32_t)N + col_in_half;
//
//         file_key_digits[i] = row_digits;
//
//         size_t vpos = pos4 + 1;
//         if (!fold_data)
//         {
//             std::vector<uint64_t> &v = pir_db[i];
//             v.assign(pir_num_columns_per_obj, 0ULL);
//             uint32_t col = 0;
//             while (col < pir_num_columns_per_obj && vpos < line.size())
//             {
//                 size_t comma = line.find(',', vpos);
//                 size_t len = (comma == std::string::npos) ? std::string::npos : comma - vpos;
//                 if (len == 0)
//                 {
//                     break;
//                 }
//                 v[col++] = static_cast<uint64_t>(std::stoull(line.substr(vpos, len)));
//                 if (comma == std::string::npos)
//                 {
//                     break;
//                 }
//                 vpos = comma + 1;
//             }
//         }
//         else
//         {
//             uint32_t second_i = i + (uint32_t)(N / 2);
//             file_key_digits[second_i] = row_digits; // duplicate key into the mirrored slot
//
//             std::vector<uint64_t> &v_first = pir_db[i];
//             std::vector<uint64_t> &v_second = pir_db[second_i];
//             v_first.assign(pir_num_columns_per_obj, 0ULL);
//             v_second.assign(pir_num_columns_per_obj, 0ULL);
//             uint32_t col = 0;
//             uint32_t total_cols = pir_num_columns_per_obj * 2;
//             while (col < total_cols && vpos < line.size())
//             {
//                 size_t comma = line.find(',', vpos);
//                 size_t len = (comma == std::string::npos) ? std::string::npos : comma - vpos;
//                 if (len == 0)
//                 {
//                     break;
//                 }
//                 uint64_t val = static_cast<uint64_t>(std::stoull(line.substr(vpos, len)));
//                 if (col % 2 == 0)
//                 {
//                     v_first[col / 2] = val;
//                 }
//                 else
//                 {
//                     v_second[col / 2] = val;
//                 }
//                 col++;
//                 if (comma == std::string::npos)
//                 {
//                     break;
//                 }
//                 vpos = comma + 1;
//             }
//         }
//
//         rows_loaded++;
//     }
//     if (rows_loaded == 0)
//     {
//         throw std::runtime_error("No records found in data distribution file: " + data_dist_file);
//     }
//     std::cout << "Loaded " << rows_loaded << " key-value records from " << data_dist_file << std::endl;
//
//     for (uint32_t row = 0; row < (uint32_t)keys.size(); row++)
//     {
//         if (file_key_digits[row].empty())
//         {
//             file_key_digits[row].assign(file_key_digit_count, 0);
//         }
//         if (pir_db[row].empty())
//         {
//             pir_db[row].assign(pir_num_columns_per_obj, 0ULL);
//         }
//     }
//
//     // // display the first few loaded keys and values for sanity-checking
//     // std::cout << "First few loaded keys and values:\n";
//     // for (uint32_t row = 0; row < std::min((uint32_t)5, (uint32_t)keys.size()); row++)
//     // {
//     //     std::cout << "Row " << row << ": key_digits=[";;
//     //     for (size_t c = 0; c < file_key_digits[row].size(); c++)
//     //     {
//     //         std::cout << file_key_digits[row][c];
//     //         if (c + 1 < file_key_digits[row].size())
//     //         {
//     //             std::cout << ",";
//     //         }
//     //     }
//     //     std::cout << "], values=[";
//     //     for (size_t c = 0; c < pir_db[row].size(); c++)
//     //     {
//     //         std::cout << pir_db[row][c];
//     //         if (c + 1 < pir_db[row].size())
//     //         {
//     //             std::cout << ",";
//     //         }
//     //     }
//     //     std::cout << "]\n";
//     // }
//
//     encode_key_batches(keys);
//     set_pir_db(pir_db);
//
//     // for display of db sizes
//     {
//         auto plaintext_bytes = [](const Plaintext &pt)
//         { return pt.coeff_count() * sizeof(std::uint64_t); };
//         size_t db_bytes = 0;
//         for (auto &row : db)
//             for (auto &pt : row)
//                 db_bytes += plaintext_bytes(pt);
//         size_t db_sum_bytes = 0;
//         for (auto &pt : db_sum)
//             db_sum_bytes += plaintext_bytes(pt);
//         size_t pir_db_bytes = 0;
//         for (auto &pt : pir_encoded_db)
//             pir_db_bytes += plaintext_bytes(pt);
//         std::cout << "[DIAG] db: " << db.size() << " x " << (db.empty() ? 0 : db[0].size())
//                   << " plaintexts, " << db_bytes / 1e6 << " MB\n";
//         std::cout << "[DIAG] db_sum: " << db_sum.size() << " plaintexts, "
//                   << db_sum_bytes / 1e6 << " MB\n";
//         std::cout << "[DIAG] pir_encoded_db: " << pir_encoded_db.size() << " plaintexts, "
//                   << pir_db_bytes / 1e6 << " MB\n";
//     }
//
//     return;
// }

// // Reads data_dist_file one FHE batch at a time: parses that batch's
// // half_batch lines, encodes its keys (db/db_sum, same layout as
// // encode_key_batches) and its value columns (pir_encoded_db, same layout as
// // set_pir_db), then reuses the same buffers for the next batch - so only one
// // batch of keys/values is in RAM instead of the whole batch_count_for_keys*N
// // key-digit and value matrices. Plaintext encoding within a batch runs on
// // NUM_THREAD threads. Numbers are parsed in place (strtol/strtoull) instead
// // of through substr() copies.
// void populate_db()
// {
//     std::cout << "Populating keys and values from file...\n";
//     std::ifstream file(data_dist_file);
//     if (!file.is_open())
//     {
//         throw std::runtime_error("Could not open data distribution file: " + data_dist_file);
//     }
//
//     std::string line;
//     std::getline(file, line); // metadata line, not parsed
//     std::getline(file, line); // column header line, skipped
//
//     // with bucketization key_size is the bucket id's bit count; either way the
//     // key is stored as the base-b digits of a key_size-bit number
//     int file_key_digit_count = digits_in_power_of_two(key_size, base);
//     uint32_t half_batch = fold_data ? (uint32_t)(N / 2) : (uint32_t)N;
//     uint32_t total_cols = fold_data ? pir_num_columns_per_obj * 2 : pir_num_columns_per_obj;
//     // keys inside bucket rows are packed at key_size_org/8 bytes by build_bucket_pipeline.py
//     size_t bucket_key_pad_bytes = bucketization ? (size_t)domain_size / 8 : 0;
//
//     // one batch of key digits and lines, reused for every batch; values need no
//     // buffer - they're written straight into their pir_encoded_db plaintexts
//     std::vector<std::vector<int>> batch_digits(N, std::vector<int>(file_key_digit_count, 0));
//     std::vector<std::string> batch_lines;
//     batch_lines.reserve(half_batch);
//     vector<vector<uint64_t>> mat_db_batch(encoding_size, vector<uint64_t>(N, 0ULL));
//     vector<uint64_t> mat_db_sum_batch(N, 0ULL);
//
//     pir_encoded_db = std::vector<seal::Plaintext>(pir_db_rows);
//     batch_value_cols.clear();
//     size_t plaintexts_kept = 0;
//     uint32_t rows_loaded = 0;
//     bool file_done = false;
//
//     for (int br = 0; br < batch_count_for_keys; br++)
//     {
//         // rows the file doesn't fill stay as all-zero keys/values, as before
//         for (auto &d : batch_digits)
//             d.assign(file_key_digit_count, 0);
//         // this batch's value plaintexts hold the raw slot values while the rows are
//         // converted (N slots each), and are encoded in place once the batch is complete
// #pragma omp parallel for schedule(static) num_threads(TOTAL_MACHINE_THREAD)
//         for (uint32_t j = 0; j < pir_num_columns_per_obj; j++)
//         {
//             Plaintext &p = pir_encoded_db[j * batch_count_for_keys + br];
//             p.resize(N);
//             p.set_zero();
//         }
//
//         // 1a. read this batch's lines (rows without a value part are skipped)
//         batch_lines.clear();
//         while (!file_done && batch_lines.size() < half_batch)
//         {
//             if (!std::getline(file, line))
//             {
//                 file_done = true;
//                 break;
//             }
//             if (line.find(',') == std::string::npos)
//             {
//                 continue;
//             }
//             batch_lines.push_back(std::move(line));
//         }
//         uint32_t rows_in_batch = (uint32_t)batch_lines.size();
//         uint64_t batch_first_row = rows_loaded; // file row of this batch's first line (value counts are seeded by it)
//         rows_loaded += rows_in_batch;
//
//         // 1b. convert them on the go, in parallel - every row writes only its own
//         //     slot(s): line format <key>,<value cells...>
//         //       - <key>: without bucketization the key itself, with it the bucket id
//         //         (the decimal value of the key's selected digits); either way
//         //         key_text_to_digits gives its digits
//         //       - value cells: raw text or already-packed numbers -> 16-bit chunks
//         //         (row_cells_to_chunks), one per PIR column (with fold: chunk 2j in
//         //         the row's slot, 2j+1 in the mirrored slot), cut off at the column
//         //         count and zero past the row's end
//         uint32_t batch_max_cols = 0; // longest row of this batch, in value plaintexts
// #pragma omp parallel num_threads(TOTAL_MACHINE_THREAD)
//         {
//             std::vector<uint64_t> chunks;
// #pragma omp for schedule(dynamic, 64) reduction(max : batch_max_cols)
//             for (uint32_t r = 0; r < rows_in_batch; r++)
//             {
//                 const std::string &row = batch_lines[r];
//                 size_t pos1 = row.find(',');
//                 batch_digits[r] = key_text_to_digits(row.substr(0, pos1), key_size, base, file_key_digit_count);
//                 if (fold_data)
//                 {
//                     batch_digits[r + N / 2] = batch_digits[r]; // duplicate key into the mirrored slot
//                 }
//                 row_cells_to_chunks(row, pos1 + 1, bucket_key_pad_bytes, chunks, total_cols, batch_first_row + r);
//                 uint32_t cols = (uint32_t)std::min<size_t>(chunks.size(), total_cols);
//                 batch_max_cols = std::max(batch_max_cols, fold_data ? (cols + 1) / 2 : cols);
//                 for (uint32_t col = 0; col < cols; col++)
//                 {
//                     if (!fold_data)
//                     {
//                         pir_encoded_db[col * batch_count_for_keys + br].data()[r] = chunks[col];
//                     }
//                     else if (col % 2 == 0)
//                     {
//                         pir_encoded_db[(col / 2) * batch_count_for_keys + br].data()[r] = chunks[col]; // even columns: first half
//                     }
//                     else
//                     {
//                         pir_encoded_db[(col / 2) * batch_count_for_keys + br].data()[r + N / 2] = chunks[col]; // odd columns: mirrored slot
//                     }
//                 }
//             }
//         }
//         // 2. keys of this batch -> db/db_sum (same layout as encode_key_batches)
//         for (auto &v : mat_db_batch)
//             std::fill(v.begin(), v.end(), 0ULL);
//         for (uint32_t c_col = 0; c_col < (uint32_t)N; c_col++)
//         {
//             const std::vector<int> &digit_string = batch_digits[c_col];
//             uint64_t sum = 0;
//             for (int c = 0; c < file_key_digit_count; c++)
//             {
//                 int pos = file_key_digit_count - 1 - c;
//                 uint64_t digit = digit_string[c];
//                 if (unary_encoding)
//                 {
//                     mat_db_batch[pos * base + digit][c_col] = 1;
//                 }
//                 else
//                 {
//                     mat_db_batch[pos][c_col] = digit * 2;
//                     sum += digit * digit;
//                 }
//             }
//             mat_db_sum_batch[c_col] = sum;
//         }
//         vector<Plaintext> row_partition(encoding_size);
// #pragma omp parallel for schedule(static) num_threads(TOTAL_MACHINE_THREAD)
//         for (int j = 0; j < encoding_size; j++)
//         {
//             batch_encoder->encode(mat_db_batch[j], row_partition[j]);
//         }
//         db.push_back(std::move(row_partition));
//         if (!unary_encoding)
//         {
//             Plaintext pt_sum;
//             batch_encoder->encode(mat_db_sum_batch, pt_sum);
//             db_sum.push_back(std::move(pt_sum));
//         }
//
//         // 3. values of this batch: encode each plaintext in place from the raw slot
//         //    values it holds (same layout as set_pir_db); one N-slot copy per thread.
//         //    Only the first batch_cols columns are kept (all of them for batch 0, so
//         //    every PIR column has at least one product); the rest are all zero and
//         //    are freed - PIR skips them (pir_plain_used)
//         uint32_t batch_cols = br == 0 ? pir_num_columns_per_obj : std::min(batch_max_cols, pir_num_columns_per_obj);
//         batch_value_cols.push_back(batch_cols);
//         plaintexts_kept += batch_cols;
// #pragma omp parallel num_threads(TOTAL_MACHINE_THREAD)
//         {
//             std::vector<uint64_t> slot_vals(N);
// #pragma omp for schedule(static)
//             for (uint32_t j = 0; j < pir_num_columns_per_obj; j++)
//             {
//                 Plaintext &p = pir_encoded_db[j * batch_count_for_keys + br];
//                 if (j >= batch_cols)
//                 {
//                     p = Plaintext(); // all zero - not stored
//                     continue;
//                 }
//                 std::copy(p.data(), p.data() + N, slot_vals.begin());
//                 batch_encoder->encode(slot_vals, p);
//                 evaluator->transform_to_ntt_inplace(p, compact_pid);
//             }
//         }
//     }
//     std::cout << "Loaded " << rows_loaded << " key-value records from " << data_dist_file << std::endl;
//     std::cout << "PIR value plaintexts kept: " << plaintexts_kept << " of " << pir_db_rows
//               << " (the rest are all zero and skipped)" << std::endl;
//
//     // for display of db sizes
//     {
//         auto plaintext_bytes = [](const Plaintext &pt)
//         { return pt.coeff_count() * sizeof(std::uint64_t); };
//         size_t db_bytes = 0;
//         for (auto &row : db)
//             for (auto &pt : row)
//                 db_bytes += plaintext_bytes(pt);
//         size_t db_sum_bytes = 0;
//         for (auto &pt : db_sum)
//             db_sum_bytes += plaintext_bytes(pt);
//         size_t pir_db_bytes = 0;
//         for (auto &pt : pir_encoded_db)
//             pir_db_bytes += plaintext_bytes(pt);
//         std::cout << "[DIAG] db: " << db.size() << " x " << (db.empty() ? 0 : db[0].size())
//                   << " plaintexts, " << db_bytes / 1e6 << " MB\n";
//         std::cout << "[DIAG] db_sum: " << db_sum.size() << " plaintexts, "
//                   << db_sum_bytes / 1e6 << " MB\n";
//         std::cout << "[DIAG] pir_encoded_db: " << pir_encoded_db.size() << " plaintexts, "
//                   << pir_db_bytes / 1e6 << " MB\n";
//     }
//
//     return;
// }

// YCSB files (ycsb_k<bits>_n2p<n>_skew<s>_vmax<v>_no_bucket.csv / _gamma<g>_bucket.csv):
// keys are text ("user" + digits), values are given only as their SIZE in bytes.
// Reads data_dist_file one FHE batch at a time: parses that batch's
// half_batch lines, encodes its keys (db/db_sum, same layout as
// encode_key_batches) and its value columns (pir_encoded_db, same layout as
// set_pir_db), then reuses the same buffers for the next batch - so only one
// batch of keys/values is in RAM instead of the whole batch_count_for_keys*N
// key-digit and value matrices. Plaintext encoding within a batch runs on
// NUM_THREAD threads. Numbers are parsed in place (strtol/strtoull) instead
// of through substr() copies.
void populate_db()
{
    std::cout << "Populating keys and values from file...\n";
    std::ifstream file(data_dist_file);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open data distribution file: " + data_dist_file);
    }

    std::string line;
    std::getline(file, line); // metadata line, not parsed
    std::getline(file, line); // column header line, skipped

    // with bucketization key_size is the bucket id's bit count; either way the
    // key is stored as the base-b digits of a key_size-bit number
    int file_key_digit_count = digits_in_power_of_two(key_size, base);
    uint32_t half_batch = fold_data ? (uint32_t)(N / 2) : (uint32_t)N;
    uint32_t total_cols = fold_data ? pir_num_columns_per_obj * 2 : pir_num_columns_per_obj;
    // keys inside bucket rows are text, zero-padded on the right to key_size_org/8 bytes
    size_t bucket_key_pad_bytes = bucketization ? (size_t)domain_size / 8 : 0;

    // one batch of key digits and lines, reused for every batch; values need no
    // buffer - they're written straight into their pir_encoded_db plaintexts
    std::vector<std::vector<int>> batch_digits(N, std::vector<int>(file_key_digit_count, 0));
    std::vector<std::string> batch_lines;
    batch_lines.reserve(half_batch);
    vector<vector<uint64_t>> mat_db_batch(encoding_size, vector<uint64_t>(N, 0ULL));
    vector<uint64_t> mat_db_sum_batch(N, 0ULL);

    pir_encoded_db = std::vector<seal::Plaintext>(pir_db_rows);
    batch_value_cols.clear();
    size_t plaintexts_kept = 0;
    uint32_t rows_loaded = 0;
    bool file_done = false;

    for (int br = 0; br < batch_count_for_keys; br++)
    {
        // rows the file doesn't fill stay as all-zero keys/values, as before
        for (auto &d : batch_digits)
            d.assign(file_key_digit_count, 0);
        // this batch's value plaintexts hold the raw slot values while the rows are
        // converted (N slots each), and are encoded in place once the batch is complete
#pragma omp parallel for schedule(static) num_threads(TOTAL_MACHINE_THREAD)
        for (uint32_t j = 0; j < pir_num_columns_per_obj; j++)
        {
            Plaintext &p = pir_encoded_db[j * batch_count_for_keys + br];
            p.resize(N);
            p.set_zero();
        }

        // 1a. read this batch's lines (rows without a value part are skipped)
        batch_lines.clear();
        while (!file_done && batch_lines.size() < half_batch)
        {
            if (!std::getline(file, line))
            {
                file_done = true;
                break;
            }
            if (line.find(',') == std::string::npos)
            {
                continue;
            }
            batch_lines.push_back(std::move(line));
        }
        uint32_t rows_in_batch = (uint32_t)batch_lines.size();
        uint64_t batch_first_row = rows_loaded; // file row of this batch's first line (value counts are seeded by it)
        rows_loaded += rows_in_batch;

        // 1b. convert them on the go, in parallel - every row writes only its own
        //     slot(s): line format <key>,$,<size>  /  <bucket_id>,#,!,<key>,$,<size>,!,...
        //       - <key>/<bucket_id>: key text or a decimal bucket id;
        //         key_text_to_digits gives its digits
        //       - value cells -> 16-bit chunks (ycsb_row_to_chunks), one per PIR
        //         column (with fold: chunk 2j in the row's slot, 2j+1 in the
        //         mirrored slot), cut off at the column count and zero past the
        //         row's end
        uint32_t batch_max_cols = 0; // longest row of this batch, in value plaintexts
#pragma omp parallel num_threads(TOTAL_MACHINE_THREAD)
        {
            std::vector<uint64_t> chunks;
#pragma omp for schedule(dynamic, 64) reduction(max : batch_max_cols)
            for (uint32_t r = 0; r < rows_in_batch; r++)
            {
                const std::string &row = batch_lines[r];
                size_t pos1 = row.find(',');
                batch_digits[r] = key_text_to_digits(row.substr(0, pos1), key_size, base, file_key_digit_count);
                if (fold_data)
                {
                    batch_digits[r + N / 2] = batch_digits[r]; // duplicate key into the mirrored slot
                }
                ycsb_row_to_chunks(row, pos1 + 1, bucket_key_pad_bytes, chunks, total_cols, batch_first_row + r);
                uint32_t cols = (uint32_t)std::min<size_t>(chunks.size(), total_cols);
                batch_max_cols = std::max(batch_max_cols, fold_data ? (cols + 1) / 2 : cols);
                for (uint32_t col = 0; col < cols; col++)
                {
                    if (!fold_data)
                    {
                        pir_encoded_db[col * batch_count_for_keys + br].data()[r] = chunks[col];
                    }
                    else if (col % 2 == 0)
                    {
                        pir_encoded_db[(col / 2) * batch_count_for_keys + br].data()[r] = chunks[col]; // even columns: first half
                    }
                    else
                    {
                        pir_encoded_db[(col / 2) * batch_count_for_keys + br].data()[r + N / 2] = chunks[col]; // odd columns: mirrored slot
                    }
                }
            }
        }
        // 2. keys of this batch -> db/db_sum (same layout as encode_key_batches)
        for (auto &v : mat_db_batch)
            std::fill(v.begin(), v.end(), 0ULL);
        for (uint32_t c_col = 0; c_col < (uint32_t)N; c_col++)
        {
            const std::vector<int> &digit_string = batch_digits[c_col];
            uint64_t sum = 0;
            for (int c = 0; c < file_key_digit_count; c++)
            {
                int pos = file_key_digit_count - 1 - c;
                uint64_t digit = digit_string[c];
                if (unary_encoding)
                {
                    mat_db_batch[pos * base + digit][c_col] = 1;
                }
                else
                {
                    mat_db_batch[pos][c_col] = digit * 2;
                    sum += digit * digit;
                }
            }
            mat_db_sum_batch[c_col] = sum;
        }
        vector<Plaintext> row_partition(encoding_size);
#pragma omp parallel for schedule(static) num_threads(TOTAL_MACHINE_THREAD)
        for (int j = 0; j < encoding_size; j++)
        {
            batch_encoder->encode(mat_db_batch[j], row_partition[j]);
        }
        db.push_back(std::move(row_partition));
        if (!unary_encoding)
        {
            Plaintext pt_sum;
            batch_encoder->encode(mat_db_sum_batch, pt_sum);
            db_sum.push_back(std::move(pt_sum));
        }

        // 3. values of this batch: encode each plaintext in place from the raw slot
        //    values it holds (same layout as set_pir_db); one N-slot copy per thread.
        //    Only the first batch_cols columns are kept (all of them for batch 0, so
        //    every PIR column has at least one product); the rest are all zero and
        //    are freed - PIR skips them (pir_plain_used)
        uint32_t batch_cols = br == 0 ? pir_num_columns_per_obj : std::min(batch_max_cols, pir_num_columns_per_obj);
        batch_value_cols.push_back(batch_cols);
        plaintexts_kept += batch_cols;
#pragma omp parallel num_threads(TOTAL_MACHINE_THREAD)
        {
            std::vector<uint64_t> slot_vals(N);
#pragma omp for schedule(static)
            for (uint32_t j = 0; j < pir_num_columns_per_obj; j++)
            {
                Plaintext &p = pir_encoded_db[j * batch_count_for_keys + br];
                if (j >= batch_cols)
                {
                    p = Plaintext(); // all zero - not stored
                    continue;
                }
                std::copy(p.data(), p.data() + N, slot_vals.begin());
                batch_encoder->encode(slot_vals, p);
                evaluator->transform_to_ntt_inplace(p, compact_pid);
            }
        }
    }
    std::cout << "Loaded " << rows_loaded << " key-value records from " << data_dist_file << std::endl;
    std::cout << "PIR value plaintexts kept: " << plaintexts_kept << " of " << pir_db_rows
              << " (the rest are all zero and skipped)" << std::endl;

    // for display of db sizes
    {
        auto plaintext_bytes = [](const Plaintext &pt)
        { return pt.coeff_count() * sizeof(std::uint64_t); };
        size_t db_bytes = 0;
        for (auto &row : db)
            for (auto &pt : row)
                db_bytes += plaintext_bytes(pt);
        size_t db_sum_bytes = 0;
        for (auto &pt : db_sum)
            db_sum_bytes += plaintext_bytes(pt);
        size_t pir_db_bytes = 0;
        for (auto &pt : pir_encoded_db)
            pir_db_bytes += plaintext_bytes(pt);
        std::cout << "[DIAG] db: " << db.size() << " x " << (db.empty() ? 0 : db[0].size())
                  << " plaintexts, " << db_bytes / 1e6 << " MB\n";
        std::cout << "[DIAG] db_sum: " << db_sum.size() << " plaintexts, "
                  << db_sum_bytes / 1e6 << " MB\n";
        std::cout << "[DIAG] pir_encoded_db: " << pir_encoded_db.size() << " plaintexts, "
                  << pir_db_bytes / 1e6 << " MB\n";
    }

    return;
}

// Synthetic values for populate_db_synthetic_values, laid out the way
// generate_uniform_dataset.py writes a row: the "$" marker chunk first, then
// uniform values in [0, PLAIN_MODULUS), from a generator seeded with 42.
// The values depend on the row's POSITION in the data file (row 0, 1, 2, ...),
// not on the key's text or size: different rows get different values, but
// row r holds the same values in every dataset (64-bit keys, 256-bit keys,
// ...). So the row in client/expected_row.csv - the values of the row the
// client's key sits in - is valid for every key size, and a shorter value
// size is just a prefix of a longer one.
// Value chunk `idx` (0-based) of row `row`: chunk 0 is the "$" marker chunk
// (9216), every other chunk the splitmix64 mix of (42, row, idx) reduced to
// [0, PLAIN_MODULUS).
uint64_t synthetic_value_chunk(uint64_t row, uint32_t idx)
{
    if (idx == 0)
    {
        return 9216;
    }
    uint64_t h = 42 + (row + 1) * 0xD1B54A32D192ED03ULL;
    h = (h ^ (h >> 30)) * 0xBF58476D1CE4E5B9ULL;
    h = (h ^ (h >> 27)) * 0x94D049BB133111EBULL;
    h ^= h >> 31;
    uint64_t z = h + ((uint64_t)idx + 1) * 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z ^= z >> 31;
    return z % PLAIN_MODULUS;
}

// Same as populate_db(), except that only the KEY of each line is read from
// data_dist_file (a keys-only file, or a key,values file whose values are
// ignored) and the values are generated on the go (synthetic_value_chunk)
// instead of being parsed. No bucketization. The layout of
// db/db_sum/pir_encoded_db is identical to populate_db()'s. The values never
// exist as text or as a row-major buffer: each value plaintext is filled
// inside the same threaded loop that encodes it, from the row's position in
// the file (see synthetic_value_chunk).
void populate_db_synthetic_values()
{
    std::cout << "Populating keys from file, generating values...\n";
    std::ifstream file(data_dist_file);
    if (!file.is_open())
    {
        throw std::runtime_error("Could not open data distribution file: " + data_dist_file);
    }

    std::string line;
    std::getline(file, line); // metadata line, not parsed
    std::getline(file, line); // column header line, skipped

    int file_key_digit_count = digits_in_power_of_two(key_size, base);
    uint32_t half_batch = fold_data ? (uint32_t)(N / 2) : (uint32_t)N;

    // one batch of key digits and key strings, reused for every batch
    std::vector<std::vector<int>> batch_digits(N, std::vector<int>(file_key_digit_count, 0));
    std::vector<std::string> batch_keys;
    batch_keys.reserve(half_batch);
    vector<vector<uint64_t>> mat_db_batch(encoding_size, vector<uint64_t>(N, 0ULL));
    vector<uint64_t> mat_db_sum_batch(N, 0ULL);

    pir_encoded_db = std::vector<seal::Plaintext>(pir_db_rows);
    uint32_t rows_loaded = 0;
    bool file_done = false;

    for (int br = 0; br < batch_count_for_keys; br++)
    {
        // rows the file doesn't fill stay as all-zero keys/values, as in populate_db()
        for (auto &d : batch_digits)
            d.assign(file_key_digit_count, 0);

        // 1a. read this batch's keys (one thread - a file is read in order)
        uint64_t batch_first_row = rows_loaded; // file position of this batch's first row
        batch_keys.clear();
        while (!file_done && batch_keys.size() < half_batch)
        {
            if (!std::getline(file, line))
            {
                file_done = true;
                break;
            }
            // line format: key[,anything] - only the key is used
            size_t pos1 = line.find(',');
            if (pos1 == std::string::npos)
            {
                pos1 = line.size();
            }
            if (pos1 == 0)
            {
                continue;
            }
            batch_keys.push_back(line.substr(0, pos1));
        }
        uint32_t rows_in_batch = (uint32_t)batch_keys.size();
        rows_loaded += rows_in_batch;

        // 1b. convert them to digits in parallel - row r always lands in slot r
        //     (and r + N/2 with fold), whichever thread converts it
#pragma omp parallel for schedule(dynamic, 64) num_threads(TOTAL_MACHINE_THREAD)
        for (uint32_t r = 0; r < rows_in_batch; r++)
        {
            batch_digits[r] = key_text_to_digits(batch_keys[r], key_size, base, file_key_digit_count);
            if (fold_data)
            {
                batch_digits[r + N / 2] = batch_digits[r]; // duplicate key into the mirrored slot
            }
        }

        // 2. keys of this batch -> db/db_sum (same layout as populate_db)
        for (auto &v : mat_db_batch)
            std::fill(v.begin(), v.end(), 0ULL);
        for (uint32_t c_col = 0; c_col < (uint32_t)N; c_col++)
        {
            const std::vector<int> &digit_string = batch_digits[c_col];
            uint64_t sum = 0;
            for (int c = 0; c < file_key_digit_count; c++)
            {
                int pos = file_key_digit_count - 1 - c;
                uint64_t digit = digit_string[c];
                if (unary_encoding)
                {
                    mat_db_batch[pos * base + digit][c_col] = 1;
                }
                else
                {
                    mat_db_batch[pos][c_col] = digit * 2;
                    sum += digit * digit;
                }
            }
            mat_db_sum_batch[c_col] = sum;
        }
        vector<Plaintext> row_partition(encoding_size);
#pragma omp parallel for schedule(static) num_threads(TOTAL_MACHINE_THREAD)
        for (int j = 0; j < encoding_size; j++)
        {
            batch_encoder->encode(mat_db_batch[j], row_partition[j]);
        }
        db.push_back(std::move(row_partition));
        if (!unary_encoding)
        {
            Plaintext pt_sum;
            batch_encoder->encode(mat_db_sum_batch, pt_sum);
            db_sum.push_back(std::move(pt_sum));
        }

        // 3. values of this batch: generate each plaintext's slot values and
        //    encode it (same layout as populate_db: without fold, column j
        //    holds value chunk j in the row's slot; with fold, chunk 2j in the
        //    row's slot and chunk 2j+1 in the mirrored slot)
#pragma omp parallel num_threads(TOTAL_MACHINE_THREAD)
        {
            std::vector<uint64_t> slot_vals(N);
#pragma omp for schedule(static)
            for (uint32_t j = 0; j < pir_num_columns_per_obj; j++)
            {
                std::fill(slot_vals.begin(), slot_vals.end(), 0ULL);
                for (uint32_t r = 0; r < rows_in_batch; r++)
                {
                    if (!fold_data)
                    {
                        slot_vals[r] = synthetic_value_chunk(batch_first_row + r, j);
                    }
                    else
                    {
                        slot_vals[r] = synthetic_value_chunk(batch_first_row + r, 2 * j);
                        slot_vals[r + N / 2] = synthetic_value_chunk(batch_first_row + r, 2 * j + 1);
                    }
                }
                Plaintext &p = pir_encoded_db[j * batch_count_for_keys + br];
                batch_encoder->encode(slot_vals, p);
                evaluator->transform_to_ntt_inplace(p, compact_pid);
            }
        }
    }
    std::cout << "Loaded " << rows_loaded << " keys from " << data_dist_file << ", values generated" << std::endl;

    // for display of db sizes
    {
        auto plaintext_bytes = [](const Plaintext &pt)
        { return pt.coeff_count() * sizeof(std::uint64_t); };
        size_t db_bytes = 0;
        for (auto &row : db)
            for (auto &pt : row)
                db_bytes += plaintext_bytes(pt);
        size_t db_sum_bytes = 0;
        for (auto &pt : db_sum)
            db_sum_bytes += plaintext_bytes(pt);
        size_t pir_db_bytes = 0;
        for (auto &pt : pir_encoded_db)
            pir_db_bytes += plaintext_bytes(pt);
        std::cout << "[DIAG] db: " << db.size() << " x " << (db.empty() ? 0 : db[0].size())
                  << " plaintexts, " << db_bytes / 1e6 << " MB\n";
        std::cout << "[DIAG] db_sum: " << db_sum.size() << " plaintexts, "
                  << db_sum_bytes / 1e6 << " MB\n";
        std::cout << "[DIAG] pir_encoded_db: " << pir_encoded_db.size() << " plaintexts, "
                  << pir_db_bytes / 1e6 << " MB\n";
    }

    return;
}

//============================================================================="

void *expand_query(void *arg)
{
    int thread_id = *((int *)arg);
    int expanded_slot_count = unary_encoding ? encoding_size : (encoding_size + 1);
    int start_col = (thread_id * expanded_slot_count) / NUM_ENCODING_THREAD;
    int end_col = ((thread_id + 1) * expanded_slot_count) / NUM_ENCODING_THREAD;
    // std::cout << "Thread " << thread_id << " expanding encoding from " << start_col << " to " << end_col - 1 << std::endl;
    int actual_ciphertext_count = (int)query_chunk_plan.capacity.size();
    Ciphertext temp_ct;

    int m = 0;
    for (int col = start_col; col < end_col; col++)
    {
        while (m + 1 < actual_ciphertext_count && col >= query_chunk_offset[m + 1])
            m++;
        int local_i = col - query_chunk_offset[m];
        int capacity = query_chunk_plan.capacity[m];
        uint32_t temp = batch_row_size / capacity;
        expanded_query[col] = server_query_ct[m];
        my_multiply_plain_ntt(*context, expanded_query[col], masks[m][local_i], NUM_EXPANSION_THREAD);
        my_transform_from_ntt_inplace(*context, expanded_query[col], NUM_EXPANSION_THREAD);
        for (int i = temp; i < batch_row_size; i *= 2)
        {
            temp_ct = expanded_query[col];
            my_rotate_internal(*context, temp_ct, i, *galois_keys, column_pools[col], NUM_EXPANSION_THREAD);
            my_add_inplace(*context, expanded_query[col], temp_ct, NUM_EXPANSION_THREAD);
        }
        my_transform_to_ntt_inplace(*context, expanded_query[col], NUM_EXPANSION_THREAD);
    }
    return nullptr;
}

//**************Query expansion, shared-rotation layout********************/
// Alternative to expand_query/expand_query_call (both left untouched): same
// inputs (server_query_ct[], masks[][], query_chunk_plan, query_chunk_offset,
// galois_keys) and same outputs (expanded_query[] in NTT form,
// expanded_query_sum), so server.cpp can call either one.
//
// expand_query masks each digit first and then spreads it over the row with
// log2(capacity) rotate-and-adds of its own - capacity * log2(capacity)
// rotations per query ciphertext. Here the packed ciphertext itself is
// rotated once per block position (capacity - 1 rotations, shared by every
// digit), and each digit is then assembled from those rotated copies with
// mask multiplies only: block position p of digit d comes from the copy
// rotated by (d - p) blocks.
// The copies are built from one another - copy k is copy (k - b) rotated by
// b blocks, b being k's highest set bit - so only the power-of-two block
// steps are used, the same Galois keys expand_query needs.
std::vector<Ciphertext> shared_rotated; // shared_rotated[k] = the query ciphertext being expanded, rotated by k blocks

struct shared_expand_arg
{
    int id;    // this thread's index within the phase
    int outer; // number of threads running the phase
    int inner; // threads each of them may use inside the my_* calls
    int phase; // 0: one level of rotations, 1: copies to NTT form, 2: assemble digits
    int m;     // query ciphertext being expanded
    int level; // phase 0 only: the level's power of two (builds copies level .. 2*level-1)
};

void *expand_query_shared(void *arg)
{
    shared_expand_arg a = *((shared_expand_arg *)arg);
    int capacity = query_chunk_plan.capacity[a.m];
    int count = a.phase == 0 ? a.level : (a.phase == 1 ? capacity : query_chunk_plan.real[a.m]);
    int start = (a.id * count) / a.outer;
    int end = ((a.id + 1) * count) / a.outer;

    if (a.phase == 0)
    {
        // copies level .. 2*level-1, each one rotation away from a copy that
        // already exists (0 .. level-1)
        uint32_t block = batch_row_size / capacity;
        for (int i = start; i < end; i++)
        {
            int k = a.level + i;
            shared_rotated[k] = shared_rotated[k - a.level];
            my_rotate_internal(*context, shared_rotated[k], a.level * block, *galois_keys, MemoryManager::GetPool(), a.inner);
        }
    }
    else if (a.phase == 1)
    {
        // the masks are NTT-form plaintexts, so the copies have to be too
        for (int k = start; k < end; k++)
        {
            my_transform_to_ntt_inplace(*context, shared_rotated[k], a.inner);
        }
    }
    else
    {
        // digit d = sum over block positions p of copy[(d - p) mod capacity] * mask[p],
        // accumulated unreduced per coefficient and reduced once at the end
        auto &coeff_modulus = context->first_context_data()->parms().coeff_modulus();
        std::vector<unsigned __int128> acc(N);
        uint64_t wide[2];
        for (int d = start; d < end; d++)
        {
            Ciphertext &dst = expanded_query[query_chunk_offset[a.m] + d];
            dst = shared_rotated[0]; // right size, parms and NTT flag; every coefficient is overwritten below
            for (size_t poly = 0; poly < dst.size(); poly++)
            {
                for (size_t mi = 0; mi < coeff_modulus.size(); mi++)
                {
                    std::fill(acc.begin(), acc.end(), (unsigned __int128)0);
                    for (int p = 0; p < capacity; p++)
                    {
                        const uint64_t *rot = shared_rotated[(d - p + capacity) % capacity].data(poly) + mi * N;
                        const uint64_t *mask = masks[a.m][p].data() + mi * N;
                        for (int j = 0; j < N; j++)
                        {
                            acc[j] += (unsigned __int128)rot[j] * mask[j];
                        }
                        // 60-bit primes: every product is below 2^120, so
                        // reduce before 128 of them can overflow 128 bits
                        if ((p & 127) == 127)
                        {
                            for (int j = 0; j < N; j++)
                            {
                                wide[0] = (uint64_t)acc[j];
                                wide[1] = (uint64_t)(acc[j] >> 64);
                                acc[j] = util::barrett_reduce_128(wide, coeff_modulus[mi]);
                            }
                        }
                    }
                    uint64_t *out = dst.data(poly) + mi * N;
                    for (int j = 0; j < N; j++)
                    {
                        wide[0] = (uint64_t)acc[j];
                        wide[1] = (uint64_t)(acc[j] >> 64);
                        out[j] = util::barrett_reduce_128(wide, coeff_modulus[mi]);
                    }
                }
            }
        }
    }
    return nullptr;
}

// Runs one phase of expand_query_shared over `count` items: as many threads
// as there are items (up to NUM_THREAD), the rest of NUM_THREAD shared out
// as each one's inner thread count.
void run_expand_query_shared_phase(int phase, int m, int level, int count)
{
    int outer = std::max(1, std::min(count, NUM_THREAD));
    int inner = std::max(1, NUM_THREAD / outer);
    std::vector<shared_expand_arg> args(outer);
    for (int i = 0; i < outer; i++)
    {
        args[i] = {i, outer, inner, phase, m, level};
    }
    if (outer == 1)
    {
        expand_query_shared((void *)&(args[0]));
        return;
    }
    std::vector<pthread_t> threads(outer);
    for (int i = 0; i < outer; i++)
    {
        if (pthread_create(&(threads[i]), NULL, expand_query_shared, (void *)&(args[i])))
        {
            printf("Error creating expansion thread");
        }
    }
    for (int i = 0; i < outer; i++)
    {
        pthread_join(threads[i], NULL);
    }
}

// Drop-in replacement for expand_query_call(): rebuilds
// expanded_query[]/expanded_query_sum from server_query_ct[] with the
// shared-rotation layout described above.
void expand_query_shared_call()
{
    std::cout << "expanded_slot_count: " << expanded_slot_count << " (shared-rotation expansion)" << std::endl;
    int chunk_count = (int)query_chunk_plan.capacity.size();
    for (int m = 0; m < chunk_count; m++)
    {
        int capacity = query_chunk_plan.capacity[m];
        shared_rotated.assign(capacity, Ciphertext());
        shared_rotated[0] = server_query_ct[m];
        my_transform_from_ntt_inplace(*context, shared_rotated[0], NUM_THREAD); // rotations need non-NTT form
        for (int level = 1; level < capacity; level *= 2)
        {
            run_expand_query_shared_phase(0, m, level, level);
        }
        run_expand_query_shared_phase(1, m, 0, capacity);
        run_expand_query_shared_phase(2, m, 0, query_chunk_plan.real[m]);
    }
    std::vector<Ciphertext>().swap(shared_rotated); // the copies are only needed while assembling

    if (!unary_encoding)
    {
        *expanded_query_sum = expanded_query[encoding_size];
        my_transform_from_ntt_inplace(*context, *expanded_query_sum, NUM_THREAD);
    }
}

void *combine_partial_sums_range(void *arg)
{
    final_combine_thread_arg *a = static_cast<final_combine_thread_arg *>(arg);

    int worker_id = a->worker_id;
    int diff = a->diff;
    int num_pairs = a->num_pairs;
    int num_workers = a->num_workers;
    int count = a->count;
    Ciphertext *column_results = a->column_result;

    int half = diff / 2;

    // block partition of pair indices
    int start_pair = (worker_id * num_pairs) / num_workers;
    int end_pair = ((worker_id + 1) * num_pairs) / num_workers;

    for (int p = start_pair; p < end_pair; ++p)
    {
        int id = p * diff;
        int partner = id + half;

        if (partner >= count)
        {
            continue;
        }

        int num_threads_inside = NUM_EXPANSION_THREAD;

        my_add_inplace(*context,
                       column_results[id],
                       column_results[partner],
                       num_threads_inside);
    }

    return NULL;
}

void *process_columns_non_unary(void *arg)
{
    column_thread_arg col_arg = *((column_thread_arg *)arg);
    int start_idx = (col_arg.col_id * encoding_size) / NUM_ENCODING_THREAD;
    int end_idx = ((col_arg.col_id + 1) * encoding_size) / NUM_ENCODING_THREAD;

    if (start_idx >= end_idx)
    {
        return NULL;
    }

    Ciphertext partial_sum;
    // iterating over each encoding column
    for (int i = start_idx; i < end_idx; i++)
    {
        // e2c*
        Ciphertext temp_ct = expanded_query[i];
        // my_multiply_plain_ntt(*context, temp_ct, db[col_arg.row_idx][i], NUM_EXPANSION_THREAD);
        // evaluator->multiply_plain_inplace(temp_ct, db[col_arg.row_idx][i], column_pools[col_arg.col_id]);
        Plaintext db_ntt_temp = db[col_arg.row_idx][i];
        my_transform_plain_to_ntt_inplace(*context, db_ntt_temp, pid, NUM_EXPANSION_THREAD);
        my_multiply_plain_ntt(*context, temp_ct, db_ntt_temp, NUM_EXPANSION_THREAD);
        if (i == start_idx)
        {
            partial_sum = temp_ct;
        }
        else
        {
            my_add_inplace(*context, partial_sum, temp_ct, NUM_EXPANSION_THREAD);
        }
    }
    my_transform_from_ntt_inplace(*context, partial_sum, NUM_EXPANSION_THREAD);
    // print_ciphertext_slots(partial_sum, 10);
    (col_arg.column_result)[col_arg.col_id] = partial_sum;
    return NULL;
}

void *multiply_columns(void *arg)
{
    mult_thread_arg mult_arg = *((mult_thread_arg *)arg);
    Ciphertext *column_results = mult_arg.column_result;
    int id = mult_arg.id;
    int diff = mult_arg.diff;
    int num_threads = NUM_EXPANSION_THREAD;

    my_bfv_multiply(*context, column_results[id], column_results[id + (diff / 2)], column_pools[id], num_threads);
    my_relinearize_internal(*context, column_results[id], *relin_keys, 2, column_pools[id], num_threads);
    return nullptr;
}

// Unary multiply tree, one worker thread's share of a round: pairs
// [start_pair, end_pair) of the round's num_pairs, pair p multiplying column
// p*diff with column p*diff + diff/2 - the same work multiply_columns does
// for a single pair.
void *multiply_columns_range(void *arg)
{
    mult_range_thread_arg a = *((mult_range_thread_arg *)arg);
    int start_pair = (a.worker_id * a.num_pairs) / a.num_workers;
    int end_pair = ((a.worker_id + 1) * a.num_pairs) / a.num_workers;
    for (int p = start_pair; p < end_pair; p++)
    {
        int id = p * a.diff;
        my_bfv_multiply(*context, a.column_result[id], a.column_result[id + (a.diff / 2)], column_pools[id], a.num_threads);
        my_relinearize_internal(*context, a.column_result[id], *relin_keys, 2, column_pools[id], a.num_threads);
    }
    return nullptr;
}

void *process_columns_unary(void *arg)
{
    column_thread_arg col_arg = *((column_thread_arg *)arg);
    int digits_power_two = encoding_size / base;
    int active_position_threads = std::min(NUM_ENCODING_THREAD, digits_power_two);
    int start_pos = (col_arg.col_id * digits_power_two) / active_position_threads;
    int end_pos = ((col_arg.col_id + 1) * digits_power_two) / active_position_threads;

    for (int pos = start_pos; pos < end_pos; pos++)
    {
        int col_start = pos * base;
        Ciphertext position_sum;
        for (uint32_t b = 0; b < base; b++)
        {
            int i = col_start + b;
            Ciphertext temp_ct = expanded_query[i];
            // my_multiply_plain_ntt(*context, temp_ct, db[col_arg.row_idx][i], NUM_EXPANSION_THREAD);
            // evaluator->multiply_plain_inplace(temp_ct, db[col_arg.row_idx][i]);
            Plaintext db_ntt_temp = db[col_arg.row_idx][i];
            my_transform_plain_to_ntt_inplace(*context, db_ntt_temp, pid, NUM_EXPANSION_THREAD);
            my_multiply_plain_ntt(*context, temp_ct, db_ntt_temp, NUM_EXPANSION_THREAD);
            if (b == 0)
            {
                position_sum = temp_ct;
            }
            else
            {
                my_add_inplace(*context, position_sum, temp_ct, NUM_EXPANSION_THREAD);
            }
        }
        my_transform_from_ntt_inplace(*context, position_sum, NUM_EXPANSION_THREAD);
        for (int k = 0; k < unary_pre_drop; k++) // primes dropped before the multiply tree (unary_early_mod_switch)
        {
            my_mod_switch_scale_to_next(*context, position_sum, position_sum, column_pools[pos], NUM_EXPANSION_THREAD);
        }
        (col_arg.column_result)[pos] = position_sum;
    }
    return NULL;
}

void *process_rows(void *arg)
{
    int id = *((int *)arg);

    int start_idx = (id * batch_count_for_keys) / NUM_BATCH_KEY_THREAD;
    int end_idx = ((id + 1) * batch_count_for_keys) / NUM_BATCH_KEY_THREAD;

    Ciphertext db_query_sum;

    pthread_t col_process_thread[NUM_ENCODING_THREAD];
    std::vector<Ciphertext> column_results(encoding_size);
    vector<column_thread_arg> column_args;
    column_args.reserve(NUM_ENCODING_THREAD);
    for (int i = 0; i < NUM_ENCODING_THREAD; i++)
    {
        column_args.push_back(column_thread_arg(i, id, column_results.data()));
    }

    int digits_power_two = encoding_size / base;
    vector<mult_thread_arg> mult_args;
    std::vector<pthread_t> col_mult_thread;
    if (unary_encoding)
    {
        mult_args.reserve(digits_power_two);
        for (int i = 0; i < digits_power_two; i++)
        {
            mult_args.push_back(mult_thread_arg(i, 1, column_results.data()));
        }
        col_mult_thread.resize(std::max(NUM_ENCODING_THREAD, digits_power_two));
    }

    chrono::high_resolution_clock::time_point time_start, time_end;
    double thread_base_wise_total = 0.0;
    double thread_fermat_total = 0.0;
    double thread_unary_base_wise_total = 0.0;
    double thread_unary_multiply_total = 0.0;

    // loop over key batches
    for (int row_idx = start_idx; row_idx < end_idx; row_idx++)
    {
        if (!unary_encoding)
        {
            // time_start = chrono::high_resolution_clock::now();
            db_query_sum = *expanded_query_sum;
            evaluator->add_plain_inplace(db_query_sum, db_sum[row_idx]);
            // std::cout << "Adding db_sum to expanded_query_sum from row " << start_idx << "to " << end_idx - 1 << std::endl;
            // print_ciphertext_slots(db_query_sum,32768);
            // time_end = chrono::high_resolution_clock::now();
            // uint64_t time_add = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            // std::cout << "time for add: " << time_add / 1000000.0 << std::endl;

            time_start = chrono::high_resolution_clock::now();
            if (NUM_ENCODING_THREAD == 1)
            {
                column_args[0].row_idx = row_idx;
                process_columns_non_unary((void *)&(column_args[0]));
            }
            else
            {
                for (int i = 0; i < NUM_ENCODING_THREAD; i++)
                {
                    column_args[i].row_idx = row_idx;
                    if (pthread_create(&(col_process_thread[i]), NULL, process_columns_non_unary, (void *)&(column_args[i])))
                    {
                        printf("Error creating column processing thread");
                    }
                }
                for (int i = 0; i < NUM_ENCODING_THREAD; i++)
                {
                    pthread_join(col_process_thread[i], NULL);
                }
            }

            // adding thread results
            for (int i = 1; i < NUM_ENCODING_THREAD; i++)
            {
                my_add_inplace(*context, column_results[0], column_results[i], NUM_EXPANSION_THREAD);
            }
            time_end = chrono::high_resolution_clock::now();
            uint64_t time_base_e2c_e2e = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            // std::cout << "time for base computation e2c* and e2e+: " << time_base_e2c_e2e / 1000000.0 << std::endl;
            thread_base_wise_total += time_base_e2c_e2e / 1000000.0;
            // print_ciphertext_slots(column_results[0]);

            // subtracting the db_query_sum from the column_results[0] for the current row
            // time_start = chrono::high_resolution_clock::now();
            evaluator->sub_inplace(column_results[0], db_query_sum);
            // std::cout << "Subtraction db_query_sum from column_results[0] for row " << row_idx << std::endl;
            // print_ciphertext_slots(column_results[0], 10);
            // time_end = chrono::high_resolution_clock::now();
            // uint64_t time_sub = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            // std::cout << "time for sub: " << time_sub / 1000000.0 << std::endl;

            // execute Fermat's little theorem to check for equality
            time_start = chrono::high_resolution_clock::now();
            // Gradual mod switching: each squaring uses ~31 bits of noise budget, so
            // after every 2nd squaring the budget fits in one fewer 60-bit prime and
            // a prime can be dropped at no cost. One switch after squarings 1, 3, ..., 15,
            // the rest after the loop - ends at the same level as one_ct (compact_pid).
            // x^(p-1) by squaring: one squaring per bit of p - 1 below its top bit,
            // keeping x^(2^b) for every other set bit b and multiplying it in.
            // p = 65537 (p - 1 = 2^16) -> 16 squarings, nothing kept.
            // LARGE_PLAIN_MODULUS (2^19 + 2^18) -> 19 squarings keeping x^(2^18)
            // after the 18th, then x^(2^19) * x^(2^18). XL_PLAIN_MODULUS
            // (2^20 + 2^18 + 2^16) -> 20 squarings; x^(2^16) is kept, multiplied
            // by x^(2^18) when that is reached, and the product multiplied in at
            // the end. The final multiply comes last, at a low level, where it
            // is cheapest
            uint64_t fermat_exponent = plain_modulus_value - 1;
            int fermat_squarings = 63 - __builtin_clzll(fermat_exponent);
            Ciphertext fermat_keep;
            bool fermat_kept = false;
            int switches_done = 0;
            for (int k = 0; k < fermat_squarings; k++)
            {
                my_bfv_square(*context, column_results[0], column_pools[0], NUM_EXPONENT_THREAD);
                my_relinearize_internal(*context, column_results[0], *relin_keys, 2, column_pools[0], NUM_EXPONENT_THREAD);
                // now x^(2^(k+1)): keep it if that power is one of p - 1's lower bits
                if (k + 1 < fermat_squarings && ((fermat_exponent >> (k + 1)) & 1))
                {
                    if (!fermat_kept)
                    {
                        fermat_keep = column_results[0];
                        fermat_kept = true;
                    }
                    else
                    {
                        // bring the kept product down to this level, then multiply this power in
                        while (fermat_keep.parms_id() != column_results[0].parms_id())
                        {
                            my_mod_switch_scale_to_next(*context, fermat_keep, fermat_keep, column_pools[0], NUM_EXPONENT_THREAD);
                        }
                        my_bfv_multiply(*context, fermat_keep, column_results[0], column_pools[0], NUM_EXPONENT_THREAD);
                        my_relinearize_internal(*context, fermat_keep, *relin_keys, 2, column_pools[0], NUM_EXPONENT_THREAD);
                    }
                }
                if (non_unary_early_mod_switch && k % 2 == 0 && switches_done < MOD_SWITCH_COUNT)
                {
                    my_mod_switch_scale_to_next(*context, column_results[0], column_results[0], column_pools[0], NUM_EXPONENT_THREAD);
                    switches_done++;
                }
            }
            if (fermat_kept)
            {
                // bring the kept powers' product down to x^(2^top)'s level, then multiply
                while (fermat_keep.parms_id() != column_results[0].parms_id())
                {
                    my_mod_switch_scale_to_next(*context, fermat_keep, fermat_keep, column_pools[0], NUM_EXPONENT_THREAD);
                }
                my_bfv_multiply(*context, column_results[0], fermat_keep, column_pools[0], NUM_EXPONENT_THREAD);
                my_relinearize_internal(*context, column_results[0], *relin_keys, 2, column_pools[0], NUM_EXPONENT_THREAD);
            }
            for (; switches_done < MOD_SWITCH_COUNT; switches_done++)
            {
                my_mod_switch_scale_to_next(*context, column_results[0], column_results[0], column_pools[0], NUM_EXPONENT_THREAD);
            }
            evaluator->sub(*one_ct, column_results[0], column_results[0]);
            time_end = chrono::high_resolution_clock::now();
            uint64_t time_e2e_mult = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            // std::cout << "Fermat e2e*: " << time_e2e_mult / 1000000.0 << std::endl;
            thread_fermat_total += time_e2e_mult / 1000000.0;
            // print_ciphertext_slots(column_results[0], 10);

            my_transform_to_ntt_inplace(*context, column_results[0], NUM_EXPONENT_THREAD);
            row_result[row_idx] = column_results[0];
        }
        else
        {
            time_start = chrono::high_resolution_clock::now();
            if (NUM_ENCODING_THREAD == 1)
            {
                column_args[0].row_idx = row_idx;
                process_columns_unary((void *)&(column_args[0]));
            }
            else
            {
                for (int i = 0; i < NUM_ENCODING_THREAD; i++)
                {
                    column_args[i].row_idx = row_idx;
                    if (pthread_create(&(col_process_thread[i]), NULL, process_columns_unary, (void *)&(column_args[i])))
                    {
                        printf("Error creating column processing thread");
                    }
                }
                for (int i = 0; i < NUM_ENCODING_THREAD; i++)
                {
                    pthread_join(col_process_thread[i], NULL);
                }
            }
            time_end = chrono::high_resolution_clock::now();
            uint64_t time_unary_base_wise = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            thread_unary_base_wise_total += time_unary_base_wise / 1000000.0;

            time_start = chrono::high_resolution_clock::now();
            // std::cout<<"digits power two: "<<digits_power_two<<std::endl;
            for (int diff = 2; diff / 2 < digits_power_two; diff *= 2)
            {
                int num_pairs_this_round = 0;
                for (int i = 0; i < digits_power_two; i += diff)
                {
                    if (i + diff / 2 >= digits_power_two)
                    {
                        continue;
                    }
                    num_pairs_this_round++;
                }

                int threads_per_batch = NUM_THREAD / NUM_BATCH_KEY_THREAD;
                int num_workers = std::min(num_pairs_this_round, threads_per_batch);
                int threads_inside = std::max(1, threads_per_batch / num_workers);
                std::vector<mult_range_thread_arg> range_args(num_workers);
                for (int w = 0; w < num_workers; w++)
                {
                    range_args[w] = {w, num_workers, diff, num_pairs_this_round, threads_inside, column_results.data()};
                }
                if (num_workers == 1)
                {
                    multiply_columns_range((void *)&(range_args[0]));
                }
                else
                {
                    for (int w = 0; w < num_workers; w++)
                    {
                        if (pthread_create(&(col_mult_thread[w]), NULL, multiply_columns_range, (void *)&(range_args[w])))
                        {
                            printf("Error creating column processing thread");
                        }
                    }
                    for (int w = 0; w < num_workers; w++)
                    {
                        pthread_join(col_mult_thread[w], NULL);
                    }
                }
            }
            time_end = chrono::high_resolution_clock::now();
            uint64_t time_unary_multiply = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
            thread_unary_multiply_total += time_unary_multiply / 1000000.0;
            // print_ciphertext_slots(column_results[0], 10);
            // the switches process_columns_unary already did before the tree (unary_early_mod_switch) count towards the total
            for (int k = unary_pre_drop; k < MOD_SWITCH_COUNT; k++)
            {
                my_mod_switch_scale_to_next(*context, column_results[0], column_results[0], column_pools[0], NUM_EXPONENT_THREAD);
            }

            my_transform_to_ntt_inplace(*context, column_results[0], NUM_EXPONENT_THREAD);
            row_result[row_idx] = column_results[0];
        }
    }
    if (!unary_encoding)
    {
        std::lock_guard<std::mutex> lock(row_computation_times_mutex);
        base_wise_computation_thread_totals.push_back(thread_base_wise_total);
        fermat_computation_thread_totals.push_back(thread_fermat_total);
    }
    else
    {
        std::lock_guard<std::mutex> lock(row_computation_times_mutex);
        unary_base_wise_computation_thread_totals.push_back(thread_unary_base_wise_total);
        unary_multiply_computation_thread_totals.push_back(thread_unary_multiply_total);
    }
    return nullptr;
}

void *add_columns_range(void *arg)
{
    reduce_thread_arg *a = static_cast<reduce_thread_arg *>(arg);

    int worker_id = a->worker_id;
    int diff = a->diff;
    int num_pairs = a->num_pairs;
    int num_workers = a->num_workers;
    Ciphertext *column_results = a->column_result;

    int half = diff / 2;

    // block partition of pair indices
    int start_pair = (worker_id * num_pairs) / num_workers;
    int end_pair = ((worker_id + 1) * num_pairs) / num_workers;

    for (int p = start_pair; p < end_pair; ++p)
    {
        int id = p * diff;
        int partner = id + half;

        if (partner >= encoding_size)
        {
            continue;
        }

        int denom = std::max(1, num_pairs);
        int num_threads_inside = std::max(1, NUM_THREAD / denom);

        my_add_inplace(*context,
                       column_results[id],
                       column_results[partner],
                       num_threads_inside);

        my_relinearize_internal(*context,
                                column_results[id],
                                *relin_keys,
                                2,
                                column_pools[id],
                                num_threads_inside);
    }

    return NULL;
}

void *process_columns(void *arg)
{

    column_thread_arg col_arg = *((column_thread_arg *)arg);
    int num_col_per_thread = encoding_size / NUM_ENCODING_THREAD;
    int start_idx = num_col_per_thread * col_arg.col_id;
    // Last thread also takes the remainder (encoding_size %
    // NUM_ENCODING_THREAD) - see process_rows' num_row_per_thread fix for
    // why floor division here would otherwise silently drop trailing
    // columns from every thread's range.
    int end_idx = (col_arg.col_id == NUM_ENCODING_THREAD - 1) ? encoding_size : start_idx + num_col_per_thread;

    for (int i = start_idx; i < end_idx; i++)
    {
        Ciphertext temp_ct = expanded_query[i];
        // NON-NTT DB EXPERIMENT: stock SEAL multiply_plain (coefficient-form
        // path) instead of the NTT-cached fast path - see encode_key_batches().
        // my_multiply_plain_ntt(*context, temp_ct, db[col_arg.row_idx][i], NUM_EXPANSION_THREAD);
        // my_transform_from_ntt_inplace(*context, temp_ct, NUM_EXPANSION_THREAD);
        evaluator->multiply_plain_inplace(temp_ct, db[col_arg.row_idx][i]);
        (col_arg.column_result)[i] = temp_ct;
        // print_ciphertext_slots((col_arg.column_result)[i]);
    }
    return nullptr;
}

/*****************************PIR functions ************************************/
/******************************************************************************/
// Max columns that can be rotate-and-packed into a single ciphertext's
// slots: a BFV/BGV row only has batch_row_size (= slot_count/2) usable
// positions, and get_sum's rotate-and-add tree needs its rotation amounts
// to stay under that (SEAL's GaloisTool::get_elt_from_step throws
// "step count too large" past N/2). Recomputed from pir_num_columns_per_obj
// and batch_row_size on every call, rather than cached, because
// pir_num_columns_per_obj can still change after init_pir_params() runs
// (e.g. read_first_query_key_from_file's bucketization path overwrites it) -
// a cached value could go stale.
uint32_t pir_num_chunks()
{
    return (uint32_t)((pir_num_columns_per_obj + batch_row_size - 1) / batch_row_size);
}

// Final compressed-mode output ciphertext count: exactly one per chunk.
// Each chunk's NUM_PIR_THREAD per-thread partial results (process_pir) get
// merged into a single ciphertext by merge_pir_chunk_results before being
// sent - matching PANTHEON's Code.cpp (its post-join
// `my_add_inplace(*context, pir_results[0], pir_results[i])` loop), which
// this mirrors. Client-side counterpart: decode_pir_compressed_result.
uint32_t pir_compressed_output_count()
{
    uint32_t chunk_count = pir_num_chunks();
    return pir_pair_merge_active() ? (chunk_count + 1) / 2 : chunk_count; // one per pair of chunks when pairs are merged
}

// Scratch space needed in pir_results for process_pir's per-thread partial
// results before they're merged: NUM_PIR_THREAD per chunk, except possibly
// the last chunk, which gets fewer threads (min(NUM_PIR_THREAD, its own
// column count)) if it has fewer columns than NUM_PIR_THREAD - see
// process_pir's effective_threads. Every chunk before the last always has
// exactly batch_row_size columns, which in any realistic configuration
// (batch_row_size = N/2, e.g. 16384) vastly exceeds NUM_PIR_THREAD, so
// only the last chunk can ever be short; that keeps scratch indexing
// (chunk_index * NUM_PIR_THREAD + thread_id) dense with no gaps to track.
// Used only to size the pir_results array in server.cpp - the final,
// merged, per-chunk results this scratch space collapses into are what
// pir_compressed_output_count() counts.
uint32_t pir_scratch_ct_count()
{
    uint32_t chunk_count = pir_num_chunks();
    if (chunk_count == 0)
    {
        return 0;
    }
    uint32_t last_chunk_col_start = (chunk_count - 1) * (uint32_t)batch_row_size;
    uint32_t last_chunk_len = pir_num_columns_per_obj - last_chunk_col_start;
    uint32_t last_chunk_threads = std::min<uint32_t>((uint32_t)NUM_PIR_THREAD, last_chunk_len);
    return (chunk_count - 1) * (uint32_t)NUM_PIR_THREAD + last_chunk_threads;
}

// Set by server.cpp before each chunk's thread round (its pir_compression
// branch loops over chunks serially, calling process_pir once per chunk) -
// the column range [pir_current_chunk_col_start, pir_current_chunk_col_end]
// this round packs into this chunk's ciphertexts, and that chunk's own
// index (for pir_results addressing).
uint32_t pir_current_chunk_index;
uint32_t pir_current_chunk_col_start;
uint32_t pir_current_chunk_col_end; // inclusive

// Packs ONE chunk (<= batch_row_size columns, set by the caller via
// pir_current_chunk_col_start/col_end) across NUM_PIR_THREAD threads,
// exactly like the original (pre-chunking) version of this function did
// for the whole of pir_num_columns_per_obj: each thread gets a sub-range
// of the chunk, computes get_sum on it, then rotates its result by its
// offset WITHIN THE CHUNK (local_start) rather than the chunk's absolute
// column position - bounded by chunk length <= batch_row_size, so this
// rotation always stays within SEAL's valid range. The original version
// shifted to the ABSOLUTE column position instead, which broke once
// pir_num_columns_per_obj (and so a thread's start_idx) exceeded
// batch_row_size; a chunk's own column range never does, by construction.
// If this chunk has fewer columns than NUM_PIR_THREAD (only possible for
// the last, short chunk - see pir_compressed_output_count), the extra
// threads simply have nothing to do for this round. Client-side
// counterpart: decode_pir_compressed_result.
void *process_pir(void *arg)
{
    int my_id = *((int *)arg);
    uint32_t chunk_len = pir_current_chunk_col_end - pir_current_chunk_col_start + 1;
    uint32_t effective_threads = std::min<uint32_t>((uint32_t)NUM_PIR_THREAD, chunk_len);
    if ((uint32_t)my_id >= effective_threads)
    {
        return nullptr;
    }
    uint32_t local_start = ((uint32_t)my_id * chunk_len) / effective_threads;
    uint32_t local_end = ((uint32_t)(my_id + 1) * chunk_len) / effective_threads - 1; // inclusive
    uint32_t start_idx = pir_current_chunk_col_start + local_start;
    uint32_t end_idx = pir_current_chunk_col_start + local_end;
    uint32_t out_idx = pir_current_chunk_index * (uint32_t)NUM_PIR_THREAD + (uint32_t)my_id;
    pir_results[out_idx] = get_sum(row_result, start_idx, end_idx);
    uint32_t mask = 1;
    while (mask <= local_start)
    {
        if (local_start & mask)
        {
            my_rotate_internal(*context, pir_results[out_idx], -(int)mask, *galois_keys, MemoryManager::GetPool(), NUM_THREAD / NUM_PIR_THREAD);
        }
        mask <<= 1;
    }
    return nullptr;
}

// Sums the effective_threads separate per-thread scratch ciphertexts
// process_pir wrote for chunk `chunk_index` (at
// pir_results[chunk_index * NUM_PIR_THREAD .. + effective_threads - 1],
// each already rotated by its own local_start - see process_pir) into ONE
// final ciphertext for that chunk, stored back at pir_results[chunk_index]
// - mirrors PANTHEON's Code.cpp post-join merge loop
// (`my_add_inplace(*context, pir_results[0], pir_results[i])`). Safe to
// overwrite pir_results[chunk_index] in place: the scratch entry at that
// same array index (aliased when chunk_index == 0, since chunk 0's own
// final slot and its first thread's scratch slot are both index 0) is read
// into a local copy before the final write. Must be called once per chunk
// from server.cpp, strictly after that chunk's process_pir threads have
// joined - every thread's scratch result must already be written.
void merge_pir_chunk_results(uint32_t chunk_index)
{
    uint32_t chunk_col_start = chunk_index * (uint32_t)batch_row_size;
    uint32_t chunk_col_end = std::min<uint32_t>(chunk_col_start + (uint32_t)batch_row_size, pir_num_columns_per_obj) - 1;
    uint32_t chunk_len = chunk_col_end - chunk_col_start + 1;
    uint32_t effective_threads = std::min<uint32_t>((uint32_t)NUM_PIR_THREAD, chunk_len);

    uint32_t base = chunk_index * (uint32_t)NUM_PIR_THREAD;
    Ciphertext merged = pir_results[base];
    for (uint32_t t = 1; t < effective_threads; t++)
    {
        my_add_inplace(*context, merged, pir_results[base + t], NUM_THREAD / NUM_PIR_THREAD);
    }
    pir_results[chunk_index] = merged;
}

// Only used when pir_pair_merge_active(): collapses each pair of merged chunk
// results (pir_results[2p], pir_results[2p+1]) into pir_results[p]. With fold
// off, a chunk's values all sit in the batching row the matched key is in and
// the other row is all zeros, so the pair's second chunk is column-rotated
// (its two rows swapped) into that empty row and added to the first. A last,
// unpaired chunk is carried over as is. Must be called once per run, after
// every chunk's merge_pir_chunk_results. Client-side counterpart:
// verify_pir_result.
void merge_pir_chunk_pairs()
{
    uint32_t chunk_count = pir_num_chunks();
    for (uint32_t p = 0; 2 * p < chunk_count; p++)
    {
        Ciphertext merged = pir_results[2 * p];
        if (2 * p + 1 < chunk_count)
        {
            my_conjugate_internal(*context, pir_results[2 * p + 1], *galois_keys, MemoryManager::GetPool(), NUM_THREAD);
            my_add_inplace(*context, merged, pir_results[2 * p + 1], NUM_THREAD);
        }
        pir_results[p] = merged;
    }
}

void *process_pir_no_compression(void *arg)
{
    int my_id = *((int *)arg);
    int start_idx = (my_id * pir_num_columns_per_obj) / NUM_PIR_THREAD;
    int end_idx = ((my_id + 1) * pir_num_columns_per_obj) / NUM_PIR_THREAD;
    int num_threads_inside = 1;

    seal::Ciphertext column_sum;
    seal::Ciphertext temp_ct;
    for (int col = start_idx; col < end_idx; col++)
    {
        column_sum = row_result[0];
        my_multiply_plain_ntt(*context, column_sum, pir_encoded_db[batch_count_for_keys * col], num_threads_inside);
        for (int j = 1; j < batch_count_for_keys; j++)
        {
            if (!pir_plain_used(col, j))
            {
                continue; // all zero - not stored
            }
            temp_ct = row_result[j];
            my_multiply_plain_ntt(*context, temp_ct, pir_encoded_db[batch_count_for_keys * col + j], num_threads_inside);
            my_add_inplace(*context, column_sum, temp_ct, num_threads_inside);
        }
        my_transform_from_ntt_inplace(*context, column_sum, num_threads_inside);
        pir_results[col] = column_sum;
    }
    return NULL;
}

Ciphertext get_sum(Ciphertext *query, uint32_t start, uint32_t end)
{
    seal::Ciphertext result;

    if (start != end)
    {
        int count = (end - start) + 1;
        int next_power_of_two = get_next_power_of_two(count);
        int mid = next_power_of_two / 2;
        seal::Ciphertext left_sum = get_sum(query, start, start + mid - 1);
        seal::Ciphertext right_sum = get_sum(query, start + mid, end);
        my_rotate_internal(*context, right_sum, -mid, *galois_keys, column_pools[0], NUM_THREAD / NUM_PIR_THREAD);
        my_add_inplace(*context, left_sum, right_sum, NUM_THREAD / NUM_PIR_THREAD);
        return left_sum;
    }
    else
    {
        seal::Ciphertext column_sum = query[0];
        seal::Ciphertext temp_ct;
        my_multiply_plain_ntt(*context, column_sum, pir_encoded_db[batch_count_for_keys * start], NUM_THREAD / NUM_PIR_THREAD);
        for (int j = 1; j < batch_count_for_keys; j++)
        {
            if (!pir_plain_used(start, j))
            {
                continue; // all zero - not stored
            }
            temp_ct = query[j];
            my_multiply_plain_ntt(*context, temp_ct, pir_encoded_db[batch_count_for_keys * start + j], NUM_THREAD / NUM_PIR_THREAD);
            my_add_inplace(*context, column_sum, temp_ct, NUM_THREAD / NUM_PIR_THREAD);
        }
        my_transform_from_ntt_inplace(*context, column_sum, NUM_THREAD / NUM_PIR_THREAD);
        return column_sum;
    }
}

uint32_t get_next_power_of_two(uint32_t number)
{
    if (!(number & (number - 1)))
    {
        return number;
    }

    uint32_t number_of_bits = get_number_of_bits(number);
    return (1 << number_of_bits);
}

uint32_t get_number_of_bits(uint64_t number)
{
    uint32_t count = 0;
    while (number)
    {
        count++;
        number /= 2;
    }
    return count;
}

vector<uint64_t> rotate_plain(const std::vector<uint64_t> &original, int index)
{
    int sz = original.size();
    int row_count = sz / 2;
    std::vector<uint64_t> result(sz);
    for (int i = 0; i < row_count; i++)
    {
        result[i] = original[(index + i) % row_count];
        result[row_count + i] = original[row_count + ((index + i) % row_count)];
    }

    return result;
}

void sha256(const char *str, int len, unsigned char *dest)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, len);
    SHA256_Final(dest, &sha256);
}