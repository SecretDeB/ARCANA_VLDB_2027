#include "helper.hpp"
#include <atomic>

// Set once main() has finished populate_db and the rest of the pre-loop
// setup; the client polls it through the "isDbReady" RPC and only sends its
// first query once it's true.
static std::atomic<bool> db_ready{false};

void init_seal_context_and_keys()
{
    std::cout << "Initializing SEALContext and other parameters\n";
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(N);
    parms.set_coeff_modulus(CoeffModulus::Create(N, CT_PRIMES));
    parms.set_plain_modulus(plain_modulus_value); // PLAIN_MODULUS, or LARGE_PLAIN_MODULUS - see apply_plain_modulus_choice()
    context = new SEALContext(parms);
    pid = context->first_parms_id();
    uint64_t plain_modulus = parms.plain_modulus().value();
    std::cout << "Coefficient modulus bits: " << context->key_context_data()->total_coeff_modulus_bit_count()
              << " (" << parms.coeff_modulus().size() << " primes)" << std::endl;
    relin_keys = new RelinKeys();
    galois_keys = new GaloisKeys();

    rpc_server_conn = new rpc::server(SERVER_PORT);

    std::promise<std::string> keys_promise;
    std::future<std::string> keys_future = keys_promise.get_future();
    rpc_server_conn->bind("sendKeys", [&keys_promise](std::string const &key_bytes)
                          {
        keys_promise.set_value(key_bytes);
        return true; });

    static std::promise<std::string> one_ct_promise;
    one_ct_future = one_ct_promise.get_future();
    rpc_server_conn->bind("sendOneCt", [](std::string const &ct_bytes)
                          {
        one_ct_promise.set_value(ct_bytes);
        return true; });

    query_future = query_promise.get_future();
    rpc_server_conn->bind("sendQuery", [](std::string const &query_bytes)
                          {
        std::lock_guard<std::mutex> lock(query_mutex);
        query_promise.set_value(query_bytes);
        return true; });

    query_loaded_future = query_loaded_promise.get_future();
    rpc_server_conn->bind("waitForQueryLoaded", []() -> double
                          {
        std::future<double> local_future;
        {
            std::lock_guard<std::mutex> lock(query_loaded_mutex);
            local_future = std::move(query_loaded_future);
        }
        return local_future.get(); });

    result_future = result_promise.get_future();
    rpc_server_conn->bind("getResult", []() -> std::string
                          {
        std::future<std::string> local_future;
        {
            std::lock_guard<std::mutex> lock(result_mutex);
            local_future = std::move(result_future);
        }
        return local_future.get(); });

    rpc_server_conn->bind("getResultChunk", [](int idx) -> std::string
                          { return result_chunks[idx]; });

    done_future = done_promise.get_future();
    rpc_server_conn->bind("clientDone", []() -> bool
                          {
        std::lock_guard<std::mutex> lock(done_mutex);
        done_promise.set_value(true);
        return true; });

    rpc_server_conn->bind("isDbReady", []() -> bool
                          { return db_ready.load(); });

    rpc_server_conn->async_run(1);
    std::cout << "Listening on port " << SERVER_PORT << " (staying up for the rest of the session)...\n";

    SecretKey secret_key;
    {
        std::cout << "Waiting for client to send the keys (secret, relin, Galois)...\n";
        std::string keys_bytes = keys_future.get();
        std::istringstream keys_in(std::move(keys_bytes));
        secret_key.load(*context, keys_in);
        relin_keys->load(*context, keys_in);
        galois_keys->load(*context, keys_in);
        std::cout << "Received secret key, relin keys, and Galois keys from client\n";
    }

    encryptor = new Encryptor(*context, secret_key);
    evaluator = new Evaluator(*context);
    decryptor = new Decryptor(*context, secret_key);
    batch_encoder = new BatchEncoder(*context);
    size_t slot_count = batch_encoder->slot_count();
    batch_row_size = slot_count / 2;
    std::cout << "Batch slot count: " << slot_count << std::endl;
    std::cout << "Plaintext matrix row size: " << batch_row_size << std::endl;
}

int main(int argc, char **argv)
{
    std::cout << std::unitbuf;                       // to flush std::cout after every output operation, so the client can see progress in real time
    std::cout << std::fixed << std::setprecision(6); // to print floating point numbers with 6 decimal places
    std::cout << "Server starting...\n";
    std::cout << "Reading inputs parameters\n";
    int option;
    bool u_seen = false;
    bool s_seen = false;
    bool d_seen = false;
    const char *optstring = "n:s:k:t:b:v:u:r:d:a:o:e:f:c:y:l:g:p:";
    while ((option = getopt(argc, argv, optstring)) != -1)
    {
        switch (option)
        {
        case 'n':
            number_of_keys = stoi(optarg);
            break;
        case 'k':
            key_size = stoi(optarg);
            break;
        case 'b':
            base = stoi(optarg);
            break;
        case 'v':
            value_size = stoi(optarg);
            break;
        case 't':
            NUM_THREAD = stoi(optarg);
            break;
        case 's':
            seeded_serialization = stoi(optarg) != 0;
            s_seen = true;
            break;
        case 'u':
            unary_encoding = stoi(optarg) != 0;
            u_seen = true;
            break;
        case 'r':
            num_runs = stoi(optarg);
            break;
        case 'e':
            fold_data = stoi(optarg) != 0; // duplicate enteries of a key within a batch
            break;
        case 'y':
            query_expansion = stoi(optarg) != 0; // client sends a packed/compressed query; server expands it via expand_query
            break;
        case 'p':
            single_query_ciphertext = stoi(optarg) != 0; // pack the query into one padded ciphertext; must match the client's -p
            break;
        case 'l':
            large_plain_modulus = stoi(optarg) != 0; // must match the client's -l setting (see helper.hpp)
            break;
        case 'g':
            batch_thread_override = stoi(optarg); // key batches processed at once in the equality step; 0 = auto (see helper.hpp)
            break;
        case 'c':
            pir_compression = stoi(optarg) != 0; // use process_pir's compressed output instead of process_pir_no_compression
            break;
        case 'f':
            data_dist_file = optarg;
            break;
        case 'd':
            bucketization = stoi(optarg) != 0;
            d_seen = true;
            break;
        case 'a':
        {
            selected_bit.clear();
            std::stringstream bits_ss(optarg);
            std::string bit_str;
            while (std::getline(bits_ss, bit_str, ','))
            {
                selected_bit.push_back(std::stoi(bit_str));
            }
            break;
        }
        case 'o':
            domain_size = stoi(optarg); // actual key size when using bucktization
            break;
        case '?':
            cout << "error optopt: " << optopt << endl;
            cout << "error opterr: " << opterr << endl;
            return 1;
        }
    }
    if (!number_of_keys)
    {
        cout << "Missing -n\n";
        return 0;
    }
    if (!key_size)
    {
        cout << "Missing -k\n";
        return 0;
    }
    if (!base)
    {
        cout << "Missing -b\n";
        return 0;
    }
    if (!value_size)
    {
        cout << "Missing -v\n";
        return 0;
    }
    if (!NUM_THREAD)
    {
        cout << "Missing -t\n";
        return 0;
    }
    if (!u_seen)
    {
        cout << "Missing -u\n";
        return 0;
    }
    if (!s_seen)
    {
        cout << "Missing -s\n";
        return 0;
    }
    if (!num_runs)
    {
        cout << "Missing -r\n";
        return 0;
    }
    if (!d_seen)
    {
        cout << "Missing -d\n";
        return 0;
    }
    if (bucketization && selected_bit.empty())
    {
        cout << "Missing -a (required when -d is true)\n";
        return 0;
    }
    if (bucketization && !domain_size)
    {
        cout << "Missing -o (required when -d is true)\n";
        return 0;
    }
    if (data_dist_file.empty())
    {
        std::cout << "Missing data distribution file\n";
        return 0;
    }
    std::cout << "Number of keys: " << number_of_keys << std::endl;
    std::cout << "Key size in bits: " << key_size << std::endl;
    std::cout << "Base of keys: " << base << std::endl;
    std::cout << "Value size in bytes: " << value_size << std::endl;
    std::cout << "Number of threads: " << NUM_THREAD << std::endl;
    std::cout << "Number of runs: " << num_runs << std::endl;
    std::cout << "Data file: " << data_dist_file << std::endl;
    if (!selected_bit.empty())
    {
        std::cout << "Domain size: " << domain_size << std::endl;
        std::cout << " Selected bits: ";
        for (size_t i = 0; i < selected_bit.size(); ++i)
        {
            std::cout << selected_bit[i] << " ";
        }
        std::cout << std::endl;
    }
    std::cout << " Seeded query serialization: " << (seeded_serialization ? "enabled" : "disabled") << std::endl;
    std::cout << "===================================================================" << std::endl;
    std::cout << " Unary encoding: " << (unary_encoding ? "enabled" : "disabled") << std::endl;
    std::cout << " Bucketization: " << (bucketization ? "enabled" : "disabled") << std::endl;
    std::cout << " Fold data: " << (fold_data ? "enabled" : "disabled") << std::endl;
    std::cout << " PIR compression: " << (pir_compression ? "enabled" : "disabled") << std::endl;
    std::cout << " Query expansion: " << (query_expansion ? "enabled" : "disabled") << std::endl;
    std::cout << " Database values: " << (synthetic_values ? "uniform" : "skewed") << std::endl;
    std::cout << " PIR chunk pair merge: " << (pir_merge_chunk_pairs ? "enabled" : "disabled") << std::endl;
    std::cout << " Non-unary early mod switch: " << (non_unary_early_mod_switch ? "enabled" : "disabled") << std::endl;
    std::cout << " Unary early mod switch: " << (unary_early_mod_switch ? "enabled" : "disabled") << std::endl;
    std::cout << " Large plaintext modulus: " << (large_plain_modulus ? "enabled" : "disabled") << std::endl;
    std::cout << "===================================================================" << std::endl;

    // setting encoding size
    int digits_power_two;
    if (!bucketization)
    {
        digits_power_two = digits_in_power_of_two(key_size, base);
        encoding_size = digits_power_two;
    }
    else
    {
        digits_power_two = digits_in_power_of_two(domain_size, base);
        encoding_size = digits_in_power_of_two(key_size, base); // bucket id (key_size bits) in base-b digits
    }
    std::cout << "Number of digits in 2^" << (bucketization ? domain_size : key_size) << "-1 in base " << base << " is: " << digits_power_two << std::endl;
    if (unary_encoding)
    {
        encoding_size = encoding_size * base;
    }
    std::cout << "Encoding size: " << encoding_size << std::endl;

    // Calculate the number of FHE batches needed for the keys
    int key_batch_capacity = fold_data ? (N / 2) : N;
    batch_count_for_keys = (int)ceil(number_of_keys / ((double)(key_batch_capacity)));
    std::cout << "Number of FHE batches needed for " << number_of_keys << " keys: " << batch_count_for_keys << std::endl;

    // intialize PIR parameters
    init_pir_params();

    // plaintext modulus / primes / mod switches (large_plain_modulus switch) - same choice as the client's
    apply_plain_modulus_choice();

    // intializing the SEALContext
    init_seal_context_and_keys();

    // preparing the ciphertext that will hold the encrypted value of 1 for subtraction during Feramt's little theorem application
    one_ct = new Ciphertext();
    std::cout << "Waiting for client to send batch of ones as ciphertext...\n";
    std::string one_ct_bytes = one_ct_future.get();
    std::istringstream one_ct_in(std::move(one_ct_bytes));
    one_ct->load(*context, one_ct_in);
    compact_pid = one_ct->parms_id();
    // print_ciphertext_slots(*one_ct, 32768);
    std::cout << "Received one_ct from client\n";

    // Populate the database
    std::cout << "Populating the database...\n";
    std::cout << "============================================================\n";
    time_start = chrono::high_resolution_clock::now();
    srand(42);
    // synthetic_values (helper.hpp switch block) picks the loader
    if (synthetic_values)
    {
        populate_db_synthetic_values(); // reads only the keys from data_dist_file, generates the values
    }
    else
    {
        populate_db(); // reads keys AND values from data_dist_file
    }
    time_end = chrono::high_resolution_clock::now();
    auto populate_time = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
    std::cout << "Database populated in " << populate_time / 1000000.0 << " seconds\n";

    // for query expansion
    setup_query_expansion();
    expanded_query = new Ciphertext[query_expansion ? expanded_slot_count : encoding_size];
    if (!unary_encoding)
    {
        expanded_query_sum = new Ciphertext;
    }
    query_expansion_thread_capacity = 0;

    // for equality
    column_pools = new MemoryPoolHandle[encoding_size + 1];
    for (int i = 0; i < encoding_size + 1; i++)
    {
        column_pools[i] = MemoryPoolHandle::New();
    }
    row_result = new Ciphertext[batch_count_for_keys];
    int row_thread_capacity = 0;
    if (unary_encoding && unary_early_mod_switch)
    {
        unary_pre_drop = unary_pre_drop_count(encoding_size / (int)base);
        std::cout << "Unary: primes dropped before the multiply tree: " << unary_pre_drop << std::endl;
    }

    // for PIR
    NUM_PIR_THREAD = NUM_THREAD;
    pir_thread = new pthread_t[NUM_PIR_THREAD];
    pir_thread_id = new int[NUM_PIR_THREAD];
    for (int i = 0; i < NUM_PIR_THREAD; i++)
    {
        pir_thread_id[i] = i;
    }
    pir_results = new Ciphertext[pir_compression ? pir_scratch_ct_count() : pir_num_columns_per_obj];

    db_ready = true; 
    std::cout << "Database ready, accepting queries\n";

    std::vector<double> query_expansion_time, row_processing_times, pir_processing_times;
    for (int run_idx = 0; run_idx < num_runs; run_idx++)
    {
        std::cout << "===== Run " << (run_idx + 1) << " of " << num_runs << " =====\n";

        std::cout << "Waiting for client to send the query...\n";
        std::cout << "============================================================\n";
        std::future<std::string> local_query_future;
        {
            std::lock_guard<std::mutex> lock(query_mutex);
            local_query_future = std::move(query_future);
        }
        std::string query_bytes = local_query_future.get();
        std::istringstream query_in(std::move(query_bytes));
        std::cout << "Received query from client, loading it in\n";
        // resetting
        {
            std::lock_guard<std::mutex> lock(query_mutex);
            query_promise = std::promise<std::string>();
            query_future = query_promise.get_future();
        }

        std::cout << "Loading client query\n";
        std::cout << "============================================================\n";
        time_start = chrono::high_resolution_clock::now();
        if (!query_expansion)
        {
            for (int i = 0; i < encoding_size; i++)
            {
                expanded_query[i].load(*context, query_in);
                // print_ciphertext_slots(expanded_query[i], 32768);
            }
            if (!unary_encoding)
            {
                expanded_query_sum->load(*context, query_in);
            }
            if (NUM_THREAD == 1)
            {
                for (int i = 0; i < encoding_size; i++)
                {
                    my_transform_to_ntt_inplace(*context, expanded_query[i], NUM_THREAD);
                }
            }
            else
            {
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
                for (int i = 0; i < encoding_size; i++)
                {
                    my_transform_to_ntt_inplace(*context, expanded_query[i], 1);
                }
            }
        }
        else
        {
            for (int m = 0; m < actual_ciphertext_count; m++)
            {
                server_query_ct[m].load(*context, query_in);
            }
            if (NUM_THREAD == 1)
            {
                for (int m = 0; m < actual_ciphertext_count; m++)
                {
                    my_transform_to_ntt_inplace(*context, server_query_ct[m], NUM_THREAD);
                }
            }
            else
            {
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
                for (int m = 0; m < actual_ciphertext_count; m++)
                {
                    my_transform_to_ntt_inplace(*context, server_query_ct[m], 1);
                }
            }
           
        }
        time_end = chrono::high_resolution_clock::now();
        double query_load_time = chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() / 1000000.0;
        {
            std::lock_guard<std::mutex> lock(query_loaded_mutex);
            query_loaded_promise.set_value(query_load_time);
            query_loaded_promise = std::promise<double>();
            query_loaded_future = query_loaded_promise.get_future();
        }

        // query expansion
        time_start = chrono::high_resolution_clock::now();
        if(query_expansion)
        {
            expand_query_call(); // original layout: mask each digit, then log2(capacity) rotations per digit
            // expand_query_shared_call(); // shared-rotation layout: capacity-1 rotations per query ciphertext, then mask multiplies
        }
        time_end = chrono::high_resolution_clock::now();
        expansion_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        std::cout << "Query expansion time(s): " << expansion_time / 1000000.0 << std::endl;
        query_expansion_time.push_back(expansion_time / 1000000.0);

        // equality operation
        std::cout << "Processing the rows of the database at the server...\n";
        std::cout << "============================================================\n";
        NUM_BATCH_KEY_THREAD = std::min(batch_count_for_keys, batch_thread_override > 0 ? std::min(batch_thread_override, NUM_THREAD) : NUM_THREAD);
        int threads_per_batch = NUM_THREAD / NUM_BATCH_KEY_THREAD;
        int max_encoding_threads = unary_encoding ? encoding_size / (int)base : encoding_size;
        NUM_ENCODING_THREAD = std::min(threads_per_batch, max_encoding_threads);
        NUM_EXPANSION_THREAD = std::max(1, threads_per_batch / NUM_ENCODING_THREAD);
        NUM_EXPONENT_THREAD = threads_per_batch;
        if (NUM_BATCH_KEY_THREAD > row_thread_capacity)
        {
            delete[] row_process_thread;
            delete[] row_thread_id;
            row_process_thread = new pthread_t[NUM_BATCH_KEY_THREAD];
            row_thread_id = new int[NUM_BATCH_KEY_THREAD];
            for (int i = 0; i < NUM_BATCH_KEY_THREAD; i++)
            {
                row_thread_id[i] = i;
            }
            row_thread_capacity = NUM_BATCH_KEY_THREAD;
        }
        std::cout << "Number of batch key threads: " << NUM_BATCH_KEY_THREAD << std::endl;
        std::cout << "Number of encoding threads: " << NUM_ENCODING_THREAD << std::endl;
        std::cout << "Number of expansion threads: " << NUM_EXPANSION_THREAD << std::endl;
        std::cout << "Number of exponent threads: " << NUM_EXPONENT_THREAD << std::endl;
        std::cout << "Number of spare threads: " << NUM_THREAD - NUM_BATCH_KEY_THREAD * threads_per_batch << std::endl;
        time_start = chrono::high_resolution_clock::now();
        if (NUM_BATCH_KEY_THREAD == 1)
        {
            process_rows((void *)&(row_thread_id[0]));
        }
        else
        {
            for (int i = 0; i < NUM_BATCH_KEY_THREAD; i++)
            {
                if (pthread_create(&(row_process_thread[i]), NULL, process_rows, (void *)&(row_thread_id[i])))
                {
                    printf("Error creating processing thread");
                }
            }
            for (int i = 0; i < NUM_BATCH_KEY_THREAD; i++)
            {
                pthread_join(row_process_thread[i], NULL);
            }
        }

        // display row results
        // for (int i = 0; i < batch_count_for_keys; i++)
        // {
        //     std::cout << "Row result for batch " << i << std::endl;
        //     Ciphertext row_result_display_copy = row_result[i];
        //     my_transform_from_ntt_inplace(*context, row_result_display_copy, NUM_THREAD);
        //     print_ciphertext_slots(row_result_display_copy, 10);
        //     if (fold_data)
        //     {
        //         Plaintext debug_pt;
        //         decryptor->decrypt(row_result_display_copy, debug_pt);
        //         std::vector<uint64_t> debug_decoded;
        //         batch_encoder->decode(debug_pt, debug_decoded);
        //         std::cout << "[DEBUG-FOLD] batch " << i << " slots 16382..16392: ";
        //         for (int s = 16382; s <= 16392; s++)
        //         {
        //             std::cout << debug_decoded[s] << " ";
        //         }
        //         std::cout << std::endl;
        //     }
        // }
        time_end = chrono::high_resolution_clock::now();
        equality_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        std::cout << "Row processing wall time (s): " << equality_time / 1000000.0 << std::endl;
        row_processing_times.push_back(equality_time / 1000000.0);

        // PIR operation
        std::cout << "Processing the PIR operation at the server...\n";
        std::cout << "============================================================\n";
        time_start = chrono::high_resolution_clock::now();
        auto spawn_and_join_pir_threads = [&](void *(*fn)(void *))
        {
            if (NUM_PIR_THREAD == 1)
            {
                fn((void *)&(pir_thread_id[0]));
            }
            else
            {
                for (int i = 0; i < NUM_PIR_THREAD; i++)
                {
                    if (pthread_create(&(pir_thread[i]), NULL, fn, (void *)&(pir_thread_id[i])))
                    {
                        printf("Error creating PIR processing thread");
                    }
                }
                for (int i = 0; i < NUM_PIR_THREAD; i++)
                {
                    pthread_join(pir_thread[i], NULL);
                }
            }
        };

        if (pir_compression)
        {
            uint32_t chunk_count = pir_num_chunks();
            for (pir_current_chunk_index = 0; pir_current_chunk_index < chunk_count; pir_current_chunk_index++)
            {
                pir_current_chunk_col_start = pir_current_chunk_index * (uint32_t)batch_row_size;
                pir_current_chunk_col_end = std::min<uint32_t>(pir_current_chunk_col_start + (uint32_t)batch_row_size, pir_num_columns_per_obj) - 1;
                spawn_and_join_pir_threads(process_pir);
                merge_pir_chunk_results(pir_current_chunk_index);
            }
            if (pir_pair_merge_active())
            {
                merge_pir_chunk_pairs(); // off unless pir_merge_chunk_pairs is set to true in helper.hpp
            }
        }
        else
        {
            spawn_and_join_pir_threads(process_pir_no_compression);
        }

        // chunking to send to client
        uint32_t pir_output_ct_count = pir_compression ? pir_compressed_output_count() : pir_num_columns_per_obj;
        constexpr size_t RESULT_CHUNK_BYTE_BUDGET = 256ULL * 1024 * 1024;
        std::vector<std::string> serialized(pir_output_ct_count);
        if (NUM_THREAD == 1)
        {
            for (uint32_t i = 0; i < pir_output_ct_count; i++)
            {
                std::ostringstream oss;
                pir_results[i].save(oss);
                serialized[i] = std::move(oss).str();
            }
        }
        else
        {
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
            for (uint32_t i = 0; i < pir_output_ct_count; i++)
            {
                std::ostringstream oss;
                pir_results[i].save(oss);
                serialized[i] = std::move(oss).str();
            }
        }
        result_chunks.clear();
        size_t result_total_bytes = 0;
        std::string current_chunk;
        for (uint32_t i = 0; i < pir_output_ct_count; i++)
        {
            current_chunk += serialized[i];
            if (current_chunk.size() >= RESULT_CHUNK_BYTE_BUDGET)
            {
                result_total_bytes += current_chunk.size();
                result_chunks.push_back(std::move(current_chunk));
                current_chunk.clear();
            }
        }
        if (!current_chunk.empty())
        {
            result_total_bytes += current_chunk.size();
            result_chunks.push_back(std::move(current_chunk));
        }
        time_end = chrono::high_resolution_clock::now();
        auto pir_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        std::cout << "PIR processing wall time (s): " << pir_time / 1000000.0 << std::endl;
        pir_processing_times.push_back(pir_time / 1000000.0);
        {
            std::lock_guard<std::mutex> lock(result_mutex);
            result_promise.set_value(std::to_string(result_chunks.size()));
        }
        printf("result size (MByte): %lf\n", result_total_bytes / 1000000.0);
        cout << "Result noise budget (column 0) " << decryptor->invariant_noise_budget(pir_results[0]) << endl;

        std::cout << "Waiting for client to confirm result receipt...\n";
        std::future<bool> local_done_future;
        {
            std::lock_guard<std::mutex> lock(done_mutex);
            local_done_future = std::move(done_future);
        }
        local_done_future.get();
        std::cout << "Client confirmed result receipt\n";

        std::vector<std::string>().swap(serialized);
        {
            std::lock_guard<std::mutex> lock(result_mutex);
            result_promise = std::promise<std::string>();
            result_future = result_promise.get_future();
        }
        {
            std::lock_guard<std::mutex> lock(done_mutex);
            done_promise = std::promise<bool>();
            done_future = done_promise.get_future();
        }
    }

    std::cout << "===== Averages over " << num_runs << " run(s) =====\n";
    std::cout << "Average Query expansion time(s): " << average(query_expansion_time) << std::endl;
    std::cout << "Average Row processing wall time (s): " << average(row_processing_times) << std::endl;
    if (unary_encoding)
    {
        std::cout << "Average slowest-thread equality check e2c*/e2e+ computation time (s): " << average_max_thread_total_per_run(unary_base_wise_computation_thread_totals, NUM_BATCH_KEY_THREAD) << std::endl;
        std::cout << "Average slowest-thread equality check e2e* computation time (s): " << average_max_thread_total_per_run(unary_multiply_computation_thread_totals, NUM_BATCH_KEY_THREAD) << std::endl;
    }
    else
    {
        std::cout << "Average slowest-thread equality check e2c*/e2e+ computation time (s): " << average_max_thread_total_per_run(base_wise_computation_thread_totals, NUM_BATCH_KEY_THREAD) << std::endl;
        std::cout << "Average slowest-thread equality check e2e* computation time (s): " << average_max_thread_total_per_run(fermat_computation_thread_totals, NUM_BATCH_KEY_THREAD) << std::endl;
    }
    std::cout << "Average PIR processing wall time (s): " << average(pir_processing_times) << std::endl;
    std::cout << "Shutting down\n";

    return 0;
}
