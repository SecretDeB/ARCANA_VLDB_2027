# Arcana: running the client and server

Arcana is a keyword PIR system over public data (BFV homomorphic encryption, Microsoft SEAL). A **server** holds the
key-value store and answers an encrypted query; a **client** encrypts a key, sends it, and decrypts the values.
This file explains how to build and run the two programs, once by hand and with the sweep scripts.

## Layout

| Path | What it is |
|---|---|
| `src/server/server.cpp`, `src/client/client.cpp` | the two programs |
| `include/` | shared code (`helper.hpp`, `globals.h`, `utils.hpp`) |
| `SEAL_parallel/` | the modified Microsoft SEAL (multi-threaded operations) |
| `rpclib/` | RPC library used between client and server |
| `src/scripts/bash/` | setup scripts and the experiment sweep scripts |
| `src/bin/` | built executables (`server`, `client`) |

## 1. Build

Requirements: GCC with C++20 (14 on Wulver), CMake, OpenSSL, OpenMP, `git`.

**One-time setup** (builds SEAL and rpclib; run from anywhere):

```bash
./src/scripts/bash/setup_wulver.sh            
```

**Build the programs:**

```bash
cd src
module load GCC/14.2.0 CMake/3.31.3 OpenSSL/3    
cmake -S . -B build
cmake --build build --target server client -j4
```

The executables land in `src/bin/` whatever the build directory is.

## 2. Run by hand

Start the **server first** and wait for it to print `Listening on port ... Waiting for client to send the keys`.
Then start the **client in a second terminal on the same machine** (the client connects to `127.0.0.1`).
Both get the same parameters.

```bash
cd src
# terminal 1
./bin/server -n 1048576 -k 256 -b 32 -v 2050 -t 64 -r 3 -s 1 -u 0 -d 0 -e 0 -c 1 -y 1 -l 0 -f <data_file.csv>
# terminal 2
./bin/client -n 1048576 -k 256 -b 32 -v 2050 -t 64 -r 3 -s 1 -u 0 -d 0 -e 0 -c 1 -y 1 -l 0 -q <query_key>
```

### Parameters

The server and client must agree on all shared parameters.

| Flag | Meaning |
|---|---|
| `-n` | number of keys (with `-d 1`: number of partitions) |
| `-k` | key size in bits (with `-d 1`: partition-id size in bits) |
| `-b` | base used to write keys and queries (2, 4, 8, 16, 32, 64, 128) |
| `-v` | maximum value size in bytes (with `-d 1`: maximum partition size) |
| `-t` | number of threads |
| `-r` | number of repetitions averaged in the output |
| `-d` | data partitioning / bit selection (0 = off, 1 = on) |
| `-a` | selected bit positions, comma separated (with `-d 1`) |
| `-o` | original key size in bits (with `-d 1`) |
| `-c` | PIR result compression (0/1; use 1) |
| `-y` | query packing and server-side expansion (0/1; use 1) |
| `-p` | pack the query into one padded ciphertext (0/1) |
| `-l` | larger plaintext modulus (0/1) |
| `-f` | server only: key-value data file |
| `-q` | client only: the key to query |



