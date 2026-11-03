#include <cstddef>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>
#include <sstream> 
#include<cmath>
#include<ctime>
#include<stack>
#include <unistd.h> 
#include<future>
#include<cassert>
#include<set>
#include<iostream>
#include "seal/seal.h"
//#include "md5.h"

#include "utils.hpp"

#include<rpc/client.h>
#include<rpc/server.h>

using namespace std::chrono;
using namespace std;
using namespace seal;
    
#define N 32768
// number of mod switches the result goes through - a variable (not a
// #define) so apply_plain_modulus_choice() (helper.hpp) can change it
// together with CT_PRIMES
int MOD_SWITCH_COUNT = 10;

#define MASTER_PORT 4000
#define CLIENT_PORT 2000
#define WORKER_PORT 3000

#define PLAIN_BIT 16
#define PLAIN_MODULUS 65537
// plaintext modulus actually given to SEAL: PLAIN_MODULUS unless
// apply_plain_modulus_choice() (helper.hpp) switches to LARGE_PLAIN_MODULUS.
// The values stay 16-bit chunks / mod PLAIN_MODULUS either way.
#define LARGE_PLAIN_MODULUS 786433 // 12 * 2^16 + 1: prime, and 1 mod 2N as batching needs
// for sums too big even for LARGE_PLAIN_MODULUS (e.g. 512-bit keys in base 128)
#define XL_PLAIN_MODULUS 1376257 // 21 * 2^16 + 1 = 2^20 + 2^18 + 2^16 + 1: prime, 1 mod 2N
uint64_t plain_modulus_value = PLAIN_MODULUS;
vector<int> CT_PRIMES({60,60,60,60,60,60,60,60,60,60,60,60});

#define LARGE_COEFF_COUNT (((CT_PRIMES.size() - 1) * (N) * 2))
#define SMALL_COEFF_COUNT (((CT_PRIMES.size() - 1 - MOD_SWITCH_COUNT) * (N) * 2))

typedef  std::vector<seal::Ciphertext> PIRQuery;
typedef  seal::Ciphertext PIRResponse;
