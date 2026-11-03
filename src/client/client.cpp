#include "helper.hpp"

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
    KeyGenerator local_keygen(*context);

    SecretKey secret_key = local_keygen.secret_key();
    encryptor = new Encryptor(*context, secret_key);
    evaluator = new Evaluator(*context);
    decryptor = new Decryptor(*context, secret_key);
    batch_encoder = new BatchEncoder(*context);
    size_t slot_count = batch_encoder->slot_count();
    batch_row_size = slot_count / 2;
    std::cout << "Batch slot count: " << slot_count << std::endl;
    std::cout << "Plaintext matrix row size: " << batch_row_size << std::endl;
    rpc_client_conn = new rpc::client(SERVER_IP, SERVER_PORT);

    RelinKeys local_relin_keys;
    local_keygen.create_relin_keys(local_relin_keys);

    set<int> rotation_steps;
    rotation_steps.insert(0);
    if (query_expansion)
    {
        int expanded_slot_count = unary_encoding ? encoding_size : (encoding_size + 1);
        int rounded_expanded_slot_count = get_next_power_of_two(expanded_slot_count);
        for (int i = (N / 2) / rounded_expanded_slot_count; i < N / 2; i *= 2)
        {
            rotation_steps.insert(i);
        }
    }
    if (pir_compression)
    {
        for (int i = 1; i <= (pir_num_columns_per_obj); i *= 2)
        {
            if (i >= N / 2)
                break;
            rotation_steps.insert(-i);
        }
    }
    GaloisKeys local_galois_keys;
    local_keygen.create_galois_keys(vector<int>(rotation_steps.begin(), rotation_steps.end()), local_galois_keys);

    std::ostringstream keys_out;
    secret_key.save(keys_out);
    local_relin_keys.save(keys_out);
    local_galois_keys.save(keys_out);
    rpc_client_conn->call("sendKeys", std::move(keys_out).str());
    std::cout << "Sent secret key, relin keys, and Galois keys to server at " << SERVER_IP << ":" << SERVER_PORT << std::endl;
}

int main(int argc, char **argv)
{
    std::cout << std::unitbuf;                       // to flush std::cout after every output operation, so the server can see progress in real time
    std::cout << std::fixed << std::setprecision(6); // to print floating point numbers with 6 decimal places
    std::cout << "Client starting...\n";
    std::cout << "Reading inputs parameters\n";
    int option;
    bool u_seen = false;
    bool s_seen = false;
    bool d_seen = false;
    std::string query_key_arg; // -q: key to query (real-value data files): row 1's key of the no-bucket file
    const char *optstring = "n:s:k:t:b:v:u:r:d:a:o:e:c:y:q:l:p:";
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
            query_expansion = stoi(optarg) != 0; // must match the server's -y setting
            break;
        case 'p':
            single_query_ciphertext = stoi(optarg) != 0; // pack the query into one padded ciphertext; must match the server's -p
            break;
        case 'l':
            large_plain_modulus = stoi(optarg) != 0; // must match the server's -l setting (see helper.hpp)
            break;
        case 'c':
            pir_compression = stoi(optarg) != 0; // must match the server's -c setting
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
        case 'q':
            query_key_arg = optarg;
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
    std::cout << "Number of keys: " << number_of_keys << std::endl;
    std::cout << "Key size in bits: " << key_size << std::endl;
    std::cout << "Base of keys: " << base << std::endl;
    std::cout << "Value size in bytes: " << value_size << std::endl;
    std::cout << "Number of threads: " << NUM_THREAD << std::endl;
    std::cout << "Number of runs: " << num_runs << std::endl;
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

    // plaintext modulus / primes / mod switches (large_plain_modulus switch) - same choice as the server's
    apply_plain_modulus_choice();

    // Initialize SEALContext and other parameters
    init_seal_context_and_keys();

    // prepare the encrypted value of 1 for subtraction during Fermat's little theorem application
    one_ct = new Ciphertext();
    vector<uint64_t> one_mat;
    for (int i = 0; i < N; i++)
    {
        one_mat.push_back(1);
    }
    Plaintext one_pt;
    batch_encoder->encode(one_mat, one_pt);
    encryptor->encrypt_symmetric(one_pt, *one_ct);
    for (int k = 0; k < MOD_SWITCH_COUNT; k++)
    {
        evaluator->mod_switch_to_next_inplace(*one_ct);
    }
    std::ostringstream one_ct_out;
    one_ct->save(one_ct_out);
    rpc_client_conn->call("sendOneCt", one_ct_out.str());
    std::cout << "Sent one_ct to server at " << SERVER_IP << ":" << SERVER_PORT << std::endl;

    std::cout << "Waiting for the server to finish populating the database...\n";
    while (!rpc_client_conn->call("isDbReady").as<bool>())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    std::cout << "Server is ready\n";

    // for calculating average times
    std::vector<double> query_gen_times, query_send_times, result_send_times, result_decode_times;

    // for PIR
    std::vector<std::vector<uint64_t>> decoded_columns; // only used when compression is off
    if (!pir_compression)
    {
        decoded_columns.resize(pir_num_columns_per_obj);
    }
    std::string result_bytes;
    std::istringstream result_in;
    Ciphertext column_ct;
    Plaintext column_pt;
    std::vector<std::vector<uint64_t>> decoded_chunks; // decode_pir_compressed_result's output, only used when compression is on

    // prepare the plaintexts for each digit value in the base
    std::vector<Plaintext> digit_plaintexts;
    digit_plaintexts.resize(base);
    std::vector<uint64_t> digit_value_vec(N);
    for (uint32_t d = 0; d < base; d++)
    {
        std::fill(digit_value_vec.begin(), digit_value_vec.end(), d);
        batch_encoder->encode(digit_value_vec, digit_plaintexts[d]);
    }

    // for non-unary encoding prepare the plaintext for the sum of squares of the digits
    std::vector<uint64_t> client_query_sum;
    if (!unary_encoding)
    {
        client_query_sum.assign(N, 0ULL);
    }

    // for query expansion
    if (query_expansion)
    {
        setup_query_expansion_client();
    }
    std::vector<uint64_t> digit_indices(query_expansion ? total_capacity : encoding_size); // to store the digit indices as unary /non-unary/ bucketized of the desired key in the base
    std::vector<int> desired_string_digits(digits_power_two);                              // to store the digits of the desired key in the base
    uint32_t sum = 0;                                                                      // to store the sum of squares of the digits of the desired key in the base
    std::vector<std::string> ciphertext_bytes(encoding_size);                              // only stores the ciphertexts of the digits of the desired key in the base, not the sum-of-squares ciphertext
    Plaintext client_query_pt_sum;
    std::string query_bytes;

    // query key + expected row for the sanity check, picked from the run's
    // parameters so no edit is needed between runs. The key is always the
    // row-1 key for the key size (bucket mode: the original key size, -o) -
    // the synthetic and YCSB files come from the same key generator (seed 42),
    // so row 1 has the same key in both. The expected row (made by
    // scripts/python/make_expected_row.py, <k> = that key size):
    //   synthetic         -> client/expected_row_synthetic.csv (row 1's values, the same for every k)
    //   YCSB no bucket    -> client/expected_row_ycsb_nobucket.csv (row 1 of the no-bucket file)
    //   YCSB bucket       -> client/expected_row_ycsb_bucket.csv (the bucket holding row 1's key)
    // YCSB keys are text; the query key (-q) is row 1's key of the dataset's no-bucket file.
    int query_key_bits = bucketization ? domain_size : key_size;
    std::string desired_string;
    std::string expected_row_file;
    if (!synthetic_values && bucketization)
    {
        expected_row_file = "client/expected_row_ycsb_bucket.csv";
    }
    else if (!synthetic_values)
    {
        expected_row_file = "client/expected_row_ycsb_nobucket.csv";
    }
    else
    {
        expected_row_file = "client/expected_row_synthetic.csv"; // synthetic values of row 1 - the same for every key size
    }
    if (!synthetic_values)
    {
        if (query_key_arg.empty())
        {
            std::cout << "Missing -q <key> (needed with real-value YCSB data files)" << std::endl;
            return 1;
        }
        desired_string = query_key_arg;
    }
    else
    {
        // row 1 of the key files (uniform/n33554432_k<k>_keysonly.csv, uniform/n524288_k<k>_keysonly.csv for
        // 24-56 bits, YCSB/data/bitsize_<k>/...)
        int key_size = query_key_bits;
        if (key_size == 24)
            desired_string = "k'!";
        else if (key_size == 32)
            desired_string = "'![7";
        else if (key_size == 40)
            desired_string = "![7C2";
        else if (key_size == 48)
            desired_string = "[7C2kK";
        else if (key_size == 56)
            desired_string = "7C2kK2i";
        else if (key_size == 64)
            desired_string = "C2kK2iXO";
        else if (key_size == 128)
            desired_string = "kS/0/$ve{u88<T/'";
        else if (key_size == 256)
            desired_string = "N|yO;U>R$4kq7l9pWxyjo_XUf'fy~WP!";
        else if (key_size == 384)
            desired_string = "PoR[Ak~K84aV-C5z~M|>1&!NoWaDF`?oKg\\?rWUe*N+M0t1^"; // last 48 bytes of the 512-bit row-1 key (server keeps the low 384 bits of the k512 file's keys)
        else if (key_size == 512)
            desired_string = "<+l2toj_?sYA]GomPoR[Ak~K84aV-C5z~M|>1&!NoWaDF`?oKg\\?rWUe*N+M0t1^";
        else
        {
            std::cout << "No query key for " << key_size << "-bit keys" << std::endl;
            return 1;
        }
    }
    std::cout << "Desired index: " << desired_string << std::endl;
    std::cout << "Expected row file: " << expected_row_file << std::endl;

    // for the result sanity check: the desired key's row, as the server's data (file picked above)
    std::vector<uint64_t> expected_row = load_expected_row(expected_row_file, bucketization ? domain_size / 8 : 0);
    if (expected_row.empty())
    {
        std::cout << "No value row in expected row file " << expected_row_file << std::endl;
        return 1;
    }
    // the row each run retrieved, one line per run, rewritten every client start
    const std::string retrieved_row_file = "client/retrieved_row.txt";
    std::ofstream retrieved_row_out(retrieved_row_file, std::ios::trunc);
    int correct_runs = 0;

    for (int run_idx = 0; run_idx < num_runs; run_idx++)
    {
        std::cout << "===== Run " << (run_idx + 1) << " of " << num_runs << " =====\n";

        query_bytes.clear();

        // prepare the query for the client
        std::cout << "Preparing the query for the client\n";
        std::cout << "============================================================\n";
        time_start = chrono::high_resolution_clock::now();
        if (bucketization)
        {
            // the bucket is picked from the key's base-2 bits whatever -b is;
            // extract_query_digits_from_digits turns it into base-b digits
            desired_string_digits = key_text_to_digits(desired_string, domain_size, 2, domain_size);
        }
        else
        {
            desired_string_digits = key_text_to_digits(desired_string, key_size, base, digits_power_two); // same conversion as the server's populate functions
        }
        sum = extract_query_digits_from_digits(desired_string_digits, digit_indices);
        // diplay digits of the desired index for debugging
        std::cout << "Digits of the desired index: ";
        for (int i = 0; i < encoding_size; i++)
        {
            std::cout << digit_indices[i] << " ";
        }
        std::cout << std::endl;
        if (!query_expansion)
        {
            if (NUM_THREAD == 1)
            {
                for (int i = 0; i < encoding_size; i++)
                {
                    save_query_ciphertext(digit_plaintexts[digit_indices[i]], qss);
                }
                if (!unary_encoding)
                {
                    std::fill(client_query_sum.begin(), client_query_sum.end(), sum);
                    batch_encoder->encode(client_query_sum, client_query_pt_sum);
                    save_query_ciphertext(client_query_pt_sum, qss);
                }
                query_bytes = qss.str();
            }
            else
            {
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
                for (int i = 0; i < encoding_size; i++)
                {
                    std::ostringstream local_out;
                    save_query_ciphertext(digit_plaintexts[digit_indices[i]], local_out);
                    ciphertext_bytes[i] = local_out.str();
                }
                for (int i = 0; i < encoding_size; i++)
                {
                    query_bytes += ciphertext_bytes[i];
                }
                if (!unary_encoding)
                {
                    std::fill(client_query_sum.begin(), client_query_sum.end(), sum);
                    batch_encoder->encode(client_query_sum, client_query_pt_sum);
                    save_query_ciphertext(client_query_pt_sum, qss);
                    query_bytes += qss.str();
                }
            }
        }
        else
        {
            if (!unary_encoding)
            {
                digit_indices[encoding_size] = sum;
            }
            query_bytes = build_compressed_query(digit_indices, digit_offset);
        }
        time_end = chrono::high_resolution_clock::now();
        query_gen_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        printf("Query generation time (s): %lf\n", query_gen_time / 1000000.0);
        printf("Query size (MByte): %lf\n", query_bytes.size() / 1000000.0);
        query_gen_times.push_back(query_gen_time / 1000000.0);
        // clearing
        std::stringstream().swap(qss);
        for (auto &s : ciphertext_bytes)
        {
            std::string().swap(s);
        }

        std::cout << "Sending query to server at " << SERVER_IP << ":" << SERVER_PORT << std::endl;
        time_start = chrono::high_resolution_clock::now();
        rpc_client_conn->call("sendQuery", query_bytes); // blocks until the server has received it, so it's safe to free query_bytes right after
        rpc_client_conn->call("waitForQueryLoaded");
        time_end = chrono::high_resolution_clock::now();
        query_send_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        printf("Query send time (s): %lf\n", query_send_time / 1000000.0);
        query_send_times.push_back(query_send_time / 1000000.0);

        std::cout << "Waiting for the server to finish PIR processing and send the result\n";
        std::cout << "============================================================\n";
        int num_result_chunks = std::stoi(rpc_client_conn->call("getResult").as<std::string>());
        std::string().swap(query_bytes);
        result_bytes.clear();

        time_start = chrono::high_resolution_clock::now();
        std::vector<std::future<RPCLIB_MSGPACK::object_handle>> pending_chunks;
        pending_chunks.reserve(num_result_chunks);
        for (int c = 0; c < num_result_chunks; c++)
        {
            pending_chunks.push_back(rpc_client_conn->async_call("getResultChunk", c));
        }
        for (int c = 0; c < num_result_chunks; c++)
        {
            result_bytes += pending_chunks[c].get().as<std::string>();
        }
        result_in.str(result_bytes);
        result_in.clear();
        size_t num_loaded_ct = pir_compression ? (size_t)pir_compressed_output_count() : (size_t)pir_num_columns_per_obj;
        std::vector<Ciphertext> loaded_columns(num_loaded_ct);
        for (size_t i = 0; i < num_loaded_ct; i++)
        {
            loaded_columns[i].load(*context, result_in);
        }
        time_end = chrono::high_resolution_clock::now();
        result_send_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        std::cout << "Result send time (s): " << result_send_time / 1000000.0 << std::endl;
        result_send_times.push_back(result_send_time / 1000000.0);
        printf("Result size (MByte): %lf\n", result_bytes.size() / 1000000.0);

        time_start = chrono::high_resolution_clock::now();
        if (!pir_compression)
        {
            if (NUM_THREAD == 1)
            {
                for (uint32_t col = 0; col < pir_num_columns_per_obj; col++)
                {
                    decryptor->decrypt(loaded_columns[col], column_pt);
                    batch_encoder->decode(column_pt, decoded_columns[col]);
                }
            }
            else
            {
#pragma omp parallel for schedule(static) num_threads(NUM_THREAD)
                for (uint32_t col = 0; col < pir_num_columns_per_obj; col++)
                {
                    Plaintext local_column_pt;
                    decryptor->decrypt(loaded_columns[col], local_column_pt);
                    batch_encoder->decode(local_column_pt, decoded_columns[col]);
                }
            }
        }
        else
        {
            decoded_chunks = decode_pir_compressed_result(loaded_columns);
        }
        time_end = chrono::high_resolution_clock::now();
        result_decode_time = (chrono::duration_cast<chrono::microseconds>(time_end - time_start)).count();
        std::cout << "Result decode time (s): " << result_decode_time / 1000000.0 << std::endl;
        result_decode_times.push_back(result_decode_time / 1000000.0);

        // slot printout - after the decode timing above, so it isn't part of the reported time
        if (pir_compression)
        {
            print_pir_compressed_result(decoded_chunks);
        }
        else
        {
            for (uint32_t col = 0; col < 10; col++)
            {
                print_ciphertext_slots(loaded_columns[col], 10);
                if (fold_data)
                {
                    std::cout << "[DEBUG-FOLD] col " << col << " slots 16382..16392: ";
                    for (int s = 16382; s <= 16392; s++)
                    {
                        std::cout << decoded_columns[col][s] << " ";
                    }
                    std::cout << std::endl;
                }
            }
        }
        // sanity check
        const std::vector<std::vector<uint64_t>> &decoded_result = pir_compression ? decoded_chunks : decoded_columns;
        uint32_t found_key_slot = 0;
        bool key_found = verify_pir_result(decoded_result, expected_row, &found_key_slot);
        if (key_found)
        {
            std::cout << "Result is correct!" << std::endl;
            correct_runs++;
        }
        else
        {
            std::cout << "Result is incorrect!" << std::endl;
        }

        // the retrieved row's values, in order
        retrieved_row_out << "run " << run_idx + 1 << " | key " << desired_string << " | ";
        if (key_found)
        {
            retrieved_row_out << format_retrieved_row(retrieved_row_chunks(decoded_result, found_key_slot),
                                                      !synthetic_values && !values_as_numbers, bucketization ? domain_size / 8 : 0);
        }
        else
        {
            retrieved_row_out << "(key's slot not found in the result)";
        }
        retrieved_row_out << std::endl;

        rpc_client_conn->call("clientDone");
    }

    std::cout << "===== Averages over " << num_runs << " run(s) =====\n";
    std::cout << "Average Query generation time (s): " << average(query_gen_times) << std::endl;
    std::cout << "Average Query send time (s): " << average(query_send_times) << std::endl;
    std::cout << "Average Result send time (s): " << average(result_send_times) << std::endl;
    std::cout << "Average Result decode time (s): " << average(result_decode_times) << std::endl;
    std::cout << "Sanity check: " << correct_runs << " of " << num_runs << " run(s) correct" << std::endl;

    return 0;
}
