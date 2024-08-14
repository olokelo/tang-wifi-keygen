#pragma once

// enable verbose output
//#define TKG_DEBUG

// use openssl for cryptographic functions, it is recommended to leave it enabled
// if disabled, wolfssl would be used in addition to openssl
// jose depends on openssl anyways but if it were ever to switch to wolfssl
// the transition will be easier
#define TKG_USE_OPENSSL

// disable generating random salts, use only for testing
//#define DISABLE_RANDOM_SALTS

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <jansson.h>
#include <jose/cfg.h>
#include <jose/jwk.h>
#include <jose/jose.h>
#include <jose/openssl.h>

#ifdef TKG_USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#else
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#endif

#include "nanors/rs.h"

typedef reed_solomon rs_t;

typedef uint8_t u8;
typedef const uint8_t cu8;
typedef uint16_t u16;
typedef const uint16_t cu16;
typedef uint32_t u32;
typedef const uint32_t cu32;
typedef int32_t i32;
typedef const int32_t ci32;
typedef uint64_t u64;
typedef const uint64_t cu64;

// 24 KB
#define MAX_STDIN_JSON_LEN 24576

// maximum size of network list
// plane size: MAX_N * hpspec.hlen
// by default: 12*12 = 144 bytes

// memory usage by networks array:
// NETWORKS_MAX_COUNT*(NETWORK_MAC_LENGTH+NETWORK_MAX_SSID_LENGTH) +
//   + (NETWORKS_MAX_COUNT+1)*sizeof(int)
// by default: 40*(6+32)+41*4 = 1764 bytes
#define MAX_N 12
#define MAX_R MAX_N
#define MAX_NR (MAX_N+MAX_R)

#define PLANE_ITEM_MAX_LENGTH 32

#define NETWORK_MAX_SSID_LENGTH 32
#define NETWORK_MAC_LENGTH 6
#define NETWORKS_MAX_COUNT 40

#define KEY_SALT_LENGTH 16
#define SALT_LENGTH 8

#define KEY_LENGTH 64
#define KEY_ITERS 103791

// (tgkg), metafile version (1)
#define METAFILE_HEADER "\x79\x49\x01"
#define MAX_PATHNAME_LEN 128

/*
Hashcat results of RTX 4090
Take that into consideration when adjusting parameters

SHA3-*:   5.0GH/s
Keccak:   5.0GH/s

SHA-512:  7.4GH/s
SHA-384:  7.4GH/s
SHA-256: 21.9GH/s
*/

enum TKGStatus {
  
  TKG_OK = 0,  // No Error
  
  TKG_ERROR_INVALID_PARAM = -1, // Invalid Parameter During tkgctx Initialization
  TKG_ERROR_PLANE_SIZE_MISMATCH = -4,  // Plane Size Mismatch (plane.len was set incorrectly)
  
  TKG_ERROR_RS_INIT = -8,       // Reed Solomon Initialization Error
  TKG_ERROR_RS_ENC = -9,        // Reed Solomon Encoding Error
  TKG_ERROR_RS_DEC = -10,       // Reed Solomon Decoding Error
  TKG_ERROR_RECONSTRUCT = -16,  // Plane Reconstruction Failed (probably too few network matches)
  
  TKG_ERROR_PBKDF2 = -32,       // PBKDF2 Error (can be WolfSSL or OpenSSL)
  TKG_ERROR_GEN_HASH = -33,     // Error Generating Hash (similar to PBKDF2 Error)
  TKG_ERROR_GEN_PARTKEYS = -34, // Error Generating PartKeys (with KECCAK)

  TKG_ERROR_INVALID_HDR = -48,  // Error reading and validating metafile header
  TKG_ERROR_INVALID_VAL = -49,  // Invalid value read from metafile, raised by VALIDATE_VALUE macro
  TKG_ERROR_INVALID_READ = -50, // Invalid read size from metafile, raised by FULL_READ macro
  TKG_ERROR_INPUT_METAFILE = -51,  // Error while reading input metafile
  TKG_ERROR_OUTPUT_METAFILE = -52, // Error while writing output metafile

  TKG_ERROR_PARSE_INPUT = -56,  // Parsing input wifi networks failed
  TKG_ERROR_ADD_NETWORK = -57,  // Failed to add parsed wifi network to the network list

  TKG_ERROR_CREATE_JWK = -64,   // Error while recerating JWK from derieved partkey
  TKG_ERROR_OUTPUT_JWK = -65,   // Error while writing that key to output .jwk file

  TKG_ERROR_CRYPTO_INIT = -72,  // Crypto library initialization Error
  TKG_ERROR_RNG_INIT = -73,     // Random Number Generator Initialization Erorr
  TKG_ERROR_RNG_DEINIT = -74,   // Random Number Generator Deinitialization Erorr

  TKG_ERROR_UNKNOWN = -127      // Unknown Error
};

enum TKGHtype {
  TKG_HT_SHA1     = 0,
  TKG_HT_SHA2_224 = 1,
  TKG_HT_SHA2_256 = 2,
  TKG_HT_SHA2_384 = 3,
  TKG_HT_SHA2_512 = 4,
  TKG_HT_SHA3_224 = 5,
  TKG_HT_SHA3_256 = 6,
  TKG_HT_SHA3_384 = 7,
  TKG_HT_SHA3_512 = 8,
  TKG_HT_LAST     = 8
};


// context struct containing options
struct tkgctx {
  
  // origin networks count
  int n;
  
  // required count of networks to reconstruct the key
  int p;
  
  // number of repair packets
  // to reconstruct n network hashes having only p of them
  // we need additional n-p packets
  int r;
  
  // number of all packets (network hashes + repair)
  int nr;

};

typedef enum TKGStatus TKGStatus_t;
typedef enum TKGHtype TKGhtype_t;
typedef struct tkgctx tkgctx_t;


typedef struct TKGPlaneSpec {
  TKGhtype_t htype; // hash type
  int hlen;  // single hash length
  u32 n_iters;
} TKGPlaneSpec_t;

// Plane.data looks like this:
// AAABBBCCC000000...000
// it's in a compact form rather than spacing out its items
typedef struct Plane {
  TKGPlaneSpec_t spec;
  u8 data[MAX_N * PLANE_ITEM_MAX_LENGTH];
  int len;
} Plane_t;


typedef struct TKGNetwork {
  u8 mac[NETWORK_MAC_LENGTH];
  u8 ssid[NETWORK_MAX_SSID_LENGTH];
  int ssid_len;  // real ssid length, has to be <= NETWORK_MAX_SSID_LENGTH
} TKGNetwork_t;

typedef struct TKGNetworksArray {
  TKGNetwork_t nets[NETWORKS_MAX_COUNT];
  int nets_len;  // real array length, has to be <= NETWORKS_MAX_COUNT
} TKGNetworksArray_t;

TKGStatus_t tkg_load_nets(
  TKGNetworksArray_t *nets, int *input_n, const char *input_json_path
);
TKGStatus_t tkg_run_recreate(
  const char *metafile_path, const TKGNetworksArray_t *input_nets, const char *tang_db_dir
);
TKGStatus_t tkg_run_generate(
  const char *metafile_path, const TKGNetworksArray_t* input_nets, const int input_p
);
