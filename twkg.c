#include "twkg.h"


#ifdef TKG_USE_OPENSSL
// converts abstracted htype of tang keygen to htype/md of relevant SSL library
const EVP_MD *get_real_htype(TKGhtype_t htype) {
  switch (htype) {
    case TKG_HT_SHA1:     return EVP_sha1();
    case TKG_HT_SHA2_224: return EVP_sha224();
    case TKG_HT_SHA2_256: return EVP_sha256();
    case TKG_HT_SHA2_384: return EVP_sha384();
    case TKG_HT_SHA2_512: return EVP_sha512();
    case TKG_HT_SHA3_224: return EVP_sha3_224();
    case TKG_HT_SHA3_256: return EVP_sha3_256();
    case TKG_HT_SHA3_384: return EVP_sha3_384();
    case TKG_HT_SHA3_512: return EVP_sha3_512();
    default: return NULL;
  }
}
#else
enum wc_HashType get_real_htype(TKGhtype_t htype) {
  switch (htype) {
    case TKG_HT_SHA1:     return WC_HASH_TYPE_SHA;
    case TKG_HT_SHA2_224: return WC_HASH_TYPE_SHA224;
    case TKG_HT_SHA2_256: return WC_HASH_TYPE_SHA256;
    case TKG_HT_SHA2_384: return WC_HASH_TYPE_SHA384;
    case TKG_HT_SHA2_512: return WC_HASH_TYPE_SHA512;
    case TKG_HT_SHA3_224: return WC_HASH_TYPE_SHA3_224;
    case TKG_HT_SHA3_256: return WC_HASH_TYPE_SHA3_256;
    case TKG_HT_SHA3_384: return WC_HASH_TYPE_SHA3_384;
    case TKG_HT_SHA3_512: return WC_HASH_TYPE_SHA3_512;
    default: return -1;
  }
}
#endif


static TKGStatus_t tkgctx_init(tkgctx_t *tctx, const int n, const int p) {

  if ((n > MAX_N) || (p > n) || (p <= 0) || (n <= 0)) {
    #ifdef TKG_DEBUG
    printf("Unable to initialize the context with p=%d, n=%d\n", p, n);
    #endif
    return TKG_ERROR_INVALID_PARAM;
  }

  tctx->n = n;
  tctx->p = p;
  tctx->r = n-p;
  tctx->nr = tctx->n + tctx->r;

  return TKG_OK;
}


static int add_network(TKGNetworksArray_t *net_arr, TKGNetwork_t *net) {

  int idx = net_arr->nets_len;
  if (idx >= NETWORKS_MAX_COUNT) {
    // no space in the array
    return -1;
  }
  
  // copy network from net into networks array at current index
  memcpy(&net_arr->nets[idx], net, sizeof(TKGNetwork_t));
  
  // increment index
  net_arr->nets_len++;
  
  return 0;
}

static void u32_to_bytes(u8 bytes[4], const u32 n) {
  bytes[0] = (n >> 24) & 0xFF;
  bytes[1] = (n >> 16) & 0xFF;
  bytes[2] = (n >> 8) & 0xFF;
  bytes[3] = n & 0xFF;
}

static u32 bytes_to_u32(u8 bytes[4]) {
  return (bytes[0]<<24) | (bytes[1]<<16) | (bytes[2]<<8) | bytes[3];
}

static void reverse_bytes(u8 *data, int len) {
  for (int i = 0; i<len/2; i++) {
    u8 temp = data[i];
    data[i] = data[len-i-1];
    data[len-i-1] = temp;
  }
}

static void debug_print_buf(const u8 *buf, const int len) {

  for (int i = 0; i < len; i++) {
    printf("%02x", buf[i]);
  }
  printf("\n");

}


#ifdef TKG_USE_OPENSSL
static int generate_random(void *rng, u8 *buf, int len) {
  (void)rng;  // get rid of unused rng warning
  return !RAND_bytes(buf, len);
}
#else
static int generate_random(RNG *rng, u8 *buf, int len) {
  return wc_RNG_GenerateBlock(rng, buf, len);
}
#endif


static int get_netdata_len(const TKGNetwork_t *net) {
  return net->ssid_len + NETWORK_MAC_LENGTH;
}


// make sure length of outbuf is >= plspec->hlen
static int gen_net_hash(
  u8 *out, const TKGPlaneSpec_t *plspec,
  const TKGNetwork_t *net, const u8 *salt
) {

  // we can read this many bytes of TKGNetwork_t struct to get netdata
  int ndlen = get_netdata_len(net);

  #ifdef TKG_USE_OPENSSL
  const EVP_MD *md = get_real_htype(plspec->htype);
  // openssl returns 1 as success so we need to negate it
  return !PKCS5_PBKDF2_HMAC(
    (const char*)net, ndlen, salt, SALT_LENGTH,
    plspec->n_iters, md, plspec->hlen, out
  );

  #else

  return wc_PBKDF2(
    out, (cu8*)net, ndlen, salt, SALT_LENGTH,
    plspec->n_iters, plspec->hlen, get_real_htype(plspec->htype)
  );
  #endif
}


static TKGStatus_t gen_plane(
  Plane_t *pl, const int n,
  const TKGNetworksArray_t *nets_arr,
  const u8 salts_array[MAX_N][SALT_LENGTH]
) {

  // too small planebuf
  if (pl->len != n*pl->spec.hlen) {
    return TKG_ERROR_PLANE_SIZE_MISMATCH;
  }
  
  // iterate over networks and salts
  for (int i=0; i<n; i++) {

    const TKGNetwork_t *cnet = &nets_arr->nets[i];

    int ret = gen_net_hash(
      (pl->data)+(i*pl->spec.hlen), &pl->spec, cnet, salts_array[i]
    );
    //debug_print_buf(pl->data, pl->len);

    //printf("n_iters %d, hash_func %d\n", n_iters, hash_func);

    if (ret != 0) {
      // pbkdf2 error
      //printf("pbkdf2 err: %d\n", ret);
      return TKG_ERROR_PBKDF2;
    }

  }

  // no error
  return TKG_OK;
}


static int get_key(u8 *out, const Plane_t *hiddenplane, const u8 *salt) {

  #ifdef TKG_USE_OPENSSL
  const EVP_MD *md = EVP_sha3_512();
  return !PKCS5_PBKDF2_HMAC(
    (const char*)hiddenplane->data, hiddenplane->len,
    salt, KEY_SALT_LENGTH, KEY_ITERS,
    md, KEY_LENGTH, out);
  #else
  return wc_PBKDF2(
    out, hiddenplane->data, hiddenplane->len,
    salt, KEY_SALT_LENGTH, KEY_ITERS,
    KEY_LENGTH, WC_SHA3_512
  );
  #endif

}


static int find_net_controlplane_pos(
  const TKGNetwork_t *net, const tkgctx_t *tctx,
  const u8 salts_array[MAX_N][SALT_LENGTH], const Plane_t *controlplane
) {

  int hlen = controlplane->spec.hlen;

  u8 outbuf[hlen];
  // here we assume controlplane->len == n == len(salts_array)
  for (int i=0; i<tctx->n; i++) {
    gen_net_hash(outbuf, &controlplane->spec, net, salts_array[i]);
    
    // check every slot of plane for network hash
    for (int j=0; j<tctx->n; j++) {
      if (memcmp(outbuf, controlplane->data+(j*hlen), hlen) == 0) {
        return j;
      }
    }
  }
  
  // not found
  return -1;
}


static TKGStatus_t gen_repairplane(
  Plane_t *repairplane, const tkgctx_t *tctx, const Plane_t *hiddenplane
) {

  const int hlen = hiddenplane->spec.hlen;

  if (hiddenplane->len != tctx->n*hlen) {
    // hashplane length unexpected
    return TKG_ERROR_PLANE_SIZE_MISMATCH;
  }

  if (repairplane->len != tctx->r*hlen) {
    // repairplane length unexpected
    return TKG_ERROR_PLANE_SIZE_MISMATCH;
  }

  // this is actually a noop
  //reed_solomon_init();

  rs_t *rs = reed_solomon_new(tctx->n, tctx->r);
  if (rs == NULL) {
    // reed solomon init error
    return TKG_ERROR_RS_INIT;
  }

  u8 tmpdata[MAX_NR*hlen];
  u8 *hasharr[MAX_NR];

  // copy hashplane into data part of tmpplane
  memcpy(tmpdata, hiddenplane->data, hiddenplane->len);
  for (int i = 0; i < tctx->nr; i++) {
    hasharr[i] = &tmpdata[i * hlen];
  }

  int ret = reed_solomon_encode(rs, hasharr, tctx->nr, hlen);
  reed_solomon_release(rs);
  
  #ifdef TKG_DEBUG
  printf("RS encode returned: %d\n", ret);
  #endif
  if (ret != 0) {
    // reed solomon encode error
    return TKG_ERROR_RS_ENC;
  }

  // copy only recovery bytes to outbuf
  memcpy(repairplane->data, tmpdata+hiddenplane->len, repairplane->len);

  return TKG_OK;
}


static TKGStatus_t reconstruct_hiddenplane(
  Plane_t *hiddenplane, const tkgctx_t *tctx,
  const TKGNetworksArray_t *nets_arr,
  const u8 control_salts_array[MAX_N][SALT_LENGTH],
  const u8 hidden_salts_array[MAX_N][SALT_LENGTH],
  const Plane_t *controlplane,
  const Plane_t *repairplane
) {

  const int hlen = hiddenplane->spec.hlen;

  if (hiddenplane->len != hlen*tctx->n) {
    // unexpected hiddenplane length
    return TKG_ERROR_PLANE_SIZE_MISMATCH;
  }

  if (repairplane->len != tctx->r*hlen) {
    // unexpected repairplane length
    return TKG_ERROR_PLANE_SIZE_MISMATCH;
  }

  // how many origin plane networks we have
  int n_marks = 0;

  // marks of which origin plane networks were erased
  // initially assume that all of them are
  u8 marks[MAX_NR];

  // last r marks are repair packets which are always present
  // so mark them as not erased
  for (int i=0; i<tctx->nr; i++) {
    marks[i] = i<tctx->n;  // 0 for last r marks, otherwise 1
  }

  int ret;
  int pos;
  u8 net_hash_buf[hlen];
  for (int i=0; i<nets_arr->nets_len; i++) {

    const TKGNetwork_t *cnet = &nets_arr->nets[i];

    pos = find_net_controlplane_pos(cnet, tctx, control_salts_array, controlplane);
    if (pos == -1) {
      // skip network if it wasn't found in control plane
      continue;
    }

    // marked as false = no erasure
    marks[pos] = false;
    n_marks++;
    #ifdef TKG_DEBUG
    printf("Found controlplane match at controlplane pos %d, netarray pos %d\n", pos, i);
    #endif

    ret = gen_net_hash(net_hash_buf, &hiddenplane->spec, cnet, hidden_salts_array[pos]);
    if (ret != 0) {
      return TKG_ERROR_GEN_HASH;
    }
    memcpy(hiddenplane->data+(pos*hlen), net_hash_buf, hlen);

  }

  if (n_marks < tctx->p) {
    // we can't reconstruct hidden plane since we have too few matching networks
    return TKG_ERROR_RECONSTRUCT;
  }

  // if n == p, we need all networks to be present
  // we should skip reed solomon step entirely
  // and at this stage assume hiddenplane was recreated successfully
  if (tctx->n == tctx->p) {
    return TKG_OK;
  }

  // TODO: remove code dup
  rs_t *rs = reed_solomon_new(tctx->n, tctx->r);
  if (rs == NULL) {
    // reed solomon init error
    return TKG_ERROR_RS_INIT;
  }

  // partition plane into array of parts: network hashes and/or erasures
  u8 tmpdata[MAX_NR*hlen];
  int tmpdata_len = tctx->nr*hlen;
  u8 *hasharr[MAX_NR];

  // copy hashplane into data part of tmpplane
  memcpy(tmpdata, hiddenplane->data, hiddenplane->len);
  // copy repairplane into repair part of tmpplane (just after data)
  memcpy(tmpdata+hiddenplane->len, repairplane->data, repairplane->len);
  for (int i = 0; i < tctx->nr; i++) {
    hasharr[i] = &tmpdata[i * hlen];
  }

  #ifdef TKG_DEBUG
  printf("tmpplane before repair: ");
  debug_print_buf(tmpdata, tmpdata_len);
  #endif

  ret = reed_solomon_decode(rs, hasharr, marks, tctx->nr, hlen);
  reed_solomon_release(rs);

  #ifdef TKG_DEBUG
  printf("RS decode returned: %d\n", ret);
  #endif
  if (ret != 0) {
    // reed solomon decoding error
    return TKG_ERROR_RS_DEC;
  }

  #ifdef TKG_DEBUG
  printf("tmpplane after repair: ");
  debug_print_buf(tmpdata, tmpdata_len);
  #endif

  // move repaired hiddenplane back from tmpplane
  memcpy(hiddenplane->data, tmpdata, hiddenplane->len);

  return TKG_OK;

}


static TKGStatus_t gen_partkeys(
  u8 *partkeys, const int partkeys_len, const u8 *key, const int key_len
) {

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    return TKG_ERROR_GEN_PARTKEYS;
  }

  EVP_MD *shake256 = EVP_MD_fetch(NULL, "SHAKE256", NULL);
  if (shake256 == NULL) {
    return TKG_ERROR_GEN_PARTKEYS;
  }

  if (EVP_DigestInit_ex(mdctx, shake256, NULL) != 1) {
    return TKG_ERROR_GEN_PARTKEYS;
  }

  if (EVP_DigestUpdate(mdctx, key, key_len) != 1) {
    return TKG_ERROR_GEN_PARTKEYS;
  }

  if (EVP_DigestFinalXOF(mdctx, partkeys, partkeys_len) != 1) {
    return TKG_ERROR_GEN_PARTKEYS;
  }

  return TKG_OK;
}


// create file containing key parameters and salts
static TKGStatus_t write_metafile(
  FILE *fout, const tkgctx_t *tctx, const TKGPlaneSpec_t *cpspec, const TKGPlaneSpec_t *hpspec,
  const u8 control_salts_array[MAX_N][SALT_LENGTH],
  const u8 hidden_salts_array[MAX_N][SALT_LENGTH],
  const u8 key_salt[KEY_SALT_LENGTH],
  const Plane_t *controlplane, const Plane_t *repairplane
) {

  u8 buf[4] = {};

  fwrite(METAFILE_HEADER, 1, 3, fout);

  // n, p
  putc(tctx->n, fout);
  putc(tctx->p, fout);

  // cpspec, hpspec
  const TKGPlaneSpec_t *pspecs[2] = {cpspec, hpspec};
  for (int i=0; i<2; i++) {
    putc(pspecs[i]->htype, fout);
    putc(pspecs[i]->hlen, fout);
    u32_to_bytes(buf, pspecs[i]->n_iters);
    fwrite(buf, 1, 4, fout);
  }

  // final key params (can't be adjusted without recompilation, that's just for checking)
  putc(KEY_SALT_LENGTH, fout);
  putc(KEY_LENGTH, fout);
  u32_to_bytes(buf, KEY_ITERS);
  fwrite(buf, 1, 4, fout);

  // read key salt
  fwrite(key_salt, 1, KEY_SALT_LENGTH, fout);

  // salt length, also not adjustable
  putc(SALT_LENGTH, fout);

  // write salts (n*salt_length) bytes from salts_array
  fwrite(control_salts_array, 1, SALT_LENGTH*tctx->n, fout);
  fwrite(hidden_salts_array, 1, SALT_LENGTH*tctx->n, fout);

  // write controlplane data (n*cpspec.hlen bytes)
  fwrite(controlplane->data, 1, controlplane->len, fout);

  // write repairplane data
  // we know its length already r=(n-p) and spec is the same as hpspec
  fwrite(repairplane->data, 1, repairplane->len, fout);

  return TKG_OK;
}

#define TKG_VALUE_VALIDATE(v, vmin, vmax) { \
  i32 vc = v; \
  if (!(((i32)vmin <= vc) && (vc <= (i32)vmax))) return TKG_ERROR_INVALID_VAL; \
}
#define TKG_FULL_READ(rn, dn) if ((size_t)rn != (size_t)dn) return TKG_ERROR_INVALID_READ

static TKGStatus_t read_metafile(
  tkgctx_t *tctx, TKGPlaneSpec_t* cpspec, TKGPlaneSpec_t* hpspec,
  u8 control_salts_array[MAX_N][SALT_LENGTH],
  u8 hidden_salts_array[MAX_N][SALT_LENGTH],
  u8 key_salt[KEY_SALT_LENGTH],
  Plane_t *repairplane, Plane_t *controlplane, FILE *fin
) {

  u8 buf[4] = {};

  fread(buf, 1, 3, fin);
  if (memcmp(METAFILE_HEADER, buf, 3) != 0) {
    // invalid header or version
    return TKG_ERROR_INVALID_HDR;
  }

  // n, p
  int input_n = getc(fin);
  int input_p = getc(fin);
  TKG_VALUE_VALIDATE(input_n, 1, MAX_N);
  TKG_VALUE_VALIDATE(input_p, 1, input_n);
  TKGStatus_t tkgret = tkgctx_init(tctx, input_n, input_p);
  if (tkgret != TKG_OK) return tkgret;

  // cpspec, hpspec
  TKGPlaneSpec_t *pspecs[2] = {cpspec, hpspec};
  for (int i=0; i<2; i++) {
    pspecs[i]->htype = getc(fin);
    pspecs[i]->hlen = getc(fin);
    TKG_FULL_READ(fread(buf, 1, 4, fin), 4);
    pspecs[i]->n_iters = bytes_to_u32(buf);

    TKG_VALUE_VALIDATE(pspecs[i]->htype, 0, TKG_HT_LAST);
    TKG_VALUE_VALIDATE(pspecs[i]->hlen, 1, 64);
    TKG_VALUE_VALIDATE(pspecs[i]->n_iters, 1, 10000000);
  }

  // final key params (can't be adjusted without recompilation, that's just for checking)
  TKG_VALUE_VALIDATE(getc(fin), KEY_SALT_LENGTH, KEY_SALT_LENGTH);
  TKG_VALUE_VALIDATE(getc(fin), KEY_LENGTH, KEY_LENGTH);
  TKG_FULL_READ(fread(buf, 1, 4, fin), 4);
  TKG_VALUE_VALIDATE(bytes_to_u32(buf), KEY_ITERS, KEY_ITERS);

  // read key salt
  TKG_FULL_READ(fread(key_salt, 1, KEY_SALT_LENGTH, fin), KEY_SALT_LENGTH);

  // salt length, also not adjustable
  TKG_VALUE_VALIDATE(getc(fin), SALT_LENGTH, SALT_LENGTH);

  // read salts
  TKG_FULL_READ(fread(control_salts_array, 1, SALT_LENGTH*tctx->n, fin), SALT_LENGTH*tctx->n);
  TKG_FULL_READ(fread(hidden_salts_array,  1, SALT_LENGTH*tctx->n, fin), SALT_LENGTH*tctx->n);

  // read original controlplane data
  controlplane->spec = *cpspec;
  controlplane->len = cpspec->hlen*tctx->n;
  TKG_FULL_READ(fread(controlplane->data, 1, controlplane->len, fin), controlplane->len);

  // read repairplane data
  // we know its length already r=(n-p) and spec is the same as hpspec
  repairplane->spec = *hpspec;
  repairplane->len = hpspec->hlen*tctx->r;
  TKG_FULL_READ(fread(repairplane->data, 1, repairplane->len, fin), repairplane->len);

  return TKG_OK;
}


// maps ascii char to hex char index
// doesn't do ANY validation and requires upper case letters in ascii string
static char hex_ord(char c) {
  return c >= 'A' ? (c-'A'+10) : c-'0';
}


// converts mac address from "12:34:56:78:90:AB" to {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB}
static void mac_to_bytes(u8 bytes[NETWORK_MAC_LENGTH], const char *mac_str) {

  int j=0;
  for (int i=0; i<NETWORK_MAC_LENGTH; i++) {
    bytes[i]  = hex_ord(mac_str[j++]) << 4;
    bytes[i] |= hex_ord(mac_str[j++]);
    j++;
  }

}


TKGStatus_t tkg_load_nets(
  TKGNetworksArray_t *nets, int *input_n, const char *input_json_path
) {

  u8 inbuf[MAX_STDIN_JSON_LEN] = {};

  FILE *fin = fopen(input_json_path, "rb");
  if (fin == NULL) return TKG_ERROR_PARSE_INPUT;

  int inbuf_len = fread(inbuf, 1, MAX_STDIN_JSON_LEN, fin);
  fclose(fin);

  if (inbuf_len < 2) {
    return TKG_ERROR_PARSE_INPUT;
  }

  json_error_t error;
  json_t *root = json_loads((char*)inbuf, 0, &error);

  if (!root) {
    fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
    return TKG_ERROR_PARSE_INPUT;
  }

  json_t *results = json_object_get(root, "results");
  if (!json_is_array(results)) {
    fprintf(stderr, "error: results is not an array\n");
    json_decref(root);
    return TKG_ERROR_PARSE_INPUT;
  }

  #ifdef TKG_DEBUG
  printf("input parsing results:\n");
  #endif

  // iterate over all networks and add them to the array
  int ret;
  size_t idx;
  json_t *value;
  json_array_foreach(results, idx, value) {
    json_t *ssid = json_object_get(value, "ssid");
    json_t *mac_str = json_object_get(value, "bssid");

    if (!json_is_string(ssid) || !json_is_string(mac_str)) {
      // skip if ssid or mac aren't string
      continue;
    }

    if (json_string_length(ssid) > NETWORK_MAX_SSID_LENGTH) {
      // skip also if network name is too long
      // however wifi ssid length should be under 32 ascii chars
      // so this shouldn't even happen
      continue;
    }

    TKGNetwork_t new_net;

    new_net.ssid_len = json_string_length(ssid);
    memcpy(new_net.ssid, json_string_value(ssid), new_net.ssid_len);

    u8 mac_buf[6];
    mac_to_bytes(mac_buf, json_string_value(mac_str));
    memcpy(new_net.mac, mac_buf, NETWORK_MAC_LENGTH);

    #ifdef TKG_DEBUG
    printf("ssid %d:    %s\n", nets->nets_len, json_string_value(ssid));
    printf("mac %d:     %s -> ", nets->nets_len, json_string_value(mac_str));
    debug_print_buf(mac_buf, 6);
    #endif

    // add_network copies new_net to the array so we can pass a pointer here
    ret = add_network(nets, &new_net);
    if (ret != 0) {
      json_decref(root);
      return TKG_ERROR_ADD_NETWORK;
    }

  }

  // set input_n to number of networks given as input
  *input_n = nets->nets_len;

  //debug_print_buf((u8*)nets, sizeof(TKGNetwork_t)*6);

  json_decref(root);

  return TKG_OK;

}


TKGStatus_t tkg_run_generate(
  const char *metafile_path, const TKGNetworksArray_t* input_nets, const int input_p
) {

  tkgctx_t tctx = {};
  TKGStatus_t tkgret = tkgctx_init(&tctx, input_nets->nets_len, input_p);
  if (tkgret != TKG_OK) return tkgret;

  TKGPlaneSpec_t cpspec = {
    TKG_HT_SHA2_256, 3, 974
  };
  TKGPlaneSpec_t hpspec = {
    TKG_HT_SHA3_384, 12, 17903
  };

  Plane_t origin_controlplane = {};
  origin_controlplane.spec = cpspec;
  origin_controlplane.len = tctx.n*origin_controlplane.spec.hlen;

  Plane_t origin_hiddenplane = {};
  origin_hiddenplane.spec = hpspec;
  origin_hiddenplane.len = tctx.n*origin_hiddenplane.spec.hlen;

  u8 control_salts[MAX_N][SALT_LENGTH] = {};
  u8 hidden_salts[MAX_N][SALT_LENGTH] = {};

  u8 key_salt[KEY_SALT_LENGTH] = {};
  u8 key[KEY_LENGTH] = {};

  #ifdef TKG_USE_OPENSSL
  void *rng;
  if (OPENSSL_init_crypto(0, NULL) != 1) {
    return TKG_ERROR_CRYPTO_INIT;
  }
  #else
  if (wolfCrypt_Init() != 0) {
    return TKG_ERROR_CRYPTO_INIT;
  }
  RNG rng;

  if (wc_InitRng(&rng) != 0) return TKG_ERROR_RNG_INIT;
  #endif
  
  #ifndef DISABLE_RANDOM_SALTS
  // generate salts for hashes and checksums
  for (int i=0; i<tctx.n; i++) {
    generate_random(&rng, control_salts[i], SALT_LENGTH);
    generate_random(&rng, hidden_salts[i], SALT_LENGTH);
  }
  // generate key salt
  generate_random(&rng, key_salt, KEY_SALT_LENGTH);
  #endif

  #ifndef TKG_USE_OPENSSL
  if (wc_FreeRng(&rng) != 0) return TKG_ERROR_RNG_DEINIT;
  #endif

  /*
  printf("Hidden salts: ");
  for (int i = 0; i < 8*n; i++) {
    printf("%02x", hidden_salts[0][i]);
  }
  printf("\n");*/

  // generate origin control plane
  tkgret = gen_plane(&origin_controlplane, tctx.n, input_nets, control_salts);
  if (tkgret != 0) return tkgret;

  #ifdef TKG_DEBUG
  printf("Origin controlplane: ");
  debug_print_buf(origin_controlplane.data, origin_controlplane.len);
  #endif

  // generate origin hidden plane
  tkgret = gen_plane(&origin_hiddenplane, tctx.n, input_nets, hidden_salts);
  if (tkgret != 0) return tkgret;

  #ifdef TKG_DEBUG
  printf("Origin hiddenplane: ");
  debug_print_buf(origin_hiddenplane.data, origin_hiddenplane.len);
  #endif

  tkgret = get_key(key, &origin_hiddenplane, key_salt);
  if (tkgret != 0) return tkgret;

  #ifdef TKG_DEBUG
  printf("\nDerived key: ");
  debug_print_buf(key, KEY_LENGTH);
  printf("\n");
  #endif

  Plane_t repairplane = {};
  repairplane.spec = hpspec;
  repairplane.len = tctx.r*repairplane.spec.hlen;
  
  // generate repair data only if the we need to
  // when n == p, we will need all networks during reconstruction
  if (tctx.n != tctx.p) {
    tkgret = gen_repairplane(&repairplane, &tctx, &origin_hiddenplane);
    if (tkgret != 0) return tkgret;
  }

  #ifdef TKG_DEBUG
  printf("Repair data (%d): ", tkgret);
  debug_print_buf(repairplane.data, repairplane.len);
  #endif

  // write output metafile
  FILE *fout = fopen(metafile_path, "wb");
  if (fout == NULL) {
    return TKG_ERROR_OUTPUT_METAFILE;
  }
  write_metafile(
    fout, &tctx, &cpspec, &hpspec,
    control_salts, hidden_salts, key_salt,
    &origin_controlplane, &repairplane
  );
  fclose(fout);

  #ifdef TKG_USE_OPENSSL
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  #else
  wolfCrypt_Cleanup();
  #endif

  return TKG_OK;
}


static TKGStatus_t output_jwk_from_partkey(
  const u8 *input_partkey, const int partkey_len,
  const char* jwk_type, const char* tang_db_dir
) {

  // copy input_partkey into partkey so it can be modified
  u8 partkey[partkey_len];
  memcpy(partkey, input_partkey, partkey_len);

  TKGStatus_t outret = TKG_OK;
  u8 thpout[32];
  char thpout_fpath[MAX_PATHNAME_LEN] = {};

  #define ELEN_MAX 48  // 32 bytes as b64, should be enough
  u8 thpout_b64[ELEN_MAX];

  #ifdef TKG_DEBUG
  printf("Generating jwk type %s using partkey:\n", jwk_type);
  debug_print_buf(partkey, partkey_len);
  #endif

  // cut partkey to 521 bits
  partkey[0] &= 1;
  reverse_bytes(partkey, partkey_len);

  // convert the private key buffer to a BIGNUM
  BIGNUM *priv_key_bn = BN_bin2bn(partkey, partkey_len, NULL);
  if (!priv_key_bn) {
    fprintf(stderr, "Error converting private key buffer to BIGNUM\n");
    return TKG_ERROR_CREATE_JWK;
  }

  // create the OSSL_PARAM array with the private key and curve name
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string("group", "P-521", 0),
      OSSL_PARAM_construct_BN("priv", partkey, partkey_len),
      OSSL_PARAM_construct_end()
  };

  // create a new EVP_PKEY_CTX for the key generation
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!pctx) {
    fprintf(stderr, "Error creating context\n");
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_1;
  }

  // initialize the context for key generation
  if (EVP_PKEY_fromdata_init(pctx) != 1) {
    fprintf(stderr, "Error initializing fromdata context\n");
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_2;
  }

  // generate the key pair with the private key
  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
    fprintf(stderr, "Error setting private key\n");
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_2;
  }
  
  // create jwk from pkey
  jose_cfg_t *cfg = jose_cfg();
  jose_cfg_auto(&cfg);

  json_t *jwkout = jose_openssl_jwk_from_EVP_PKEY(cfg, pkey);
  if (jwkout == NULL) {
    printf("jwkout is NULL\n");
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_3;
  }

  // add jwk key_ops and alg parameters to the output object
  json_t *tmp_ja = json_array();
  json_array_append_new(tmp_ja, json_string("sign"));
  json_array_append_new(tmp_ja, json_string("verify"));

  json_object_set_new(jwkout, "key_ops", tmp_ja);
  json_object_set_new(jwkout, "alg", json_string(jwk_type));

  // generate thp (thumbprint used as filename for jwk file)
  jose_jwk_thp_buf(NULL, jwkout, "S256", thpout, 32);
  //debug_print_buf(thpout, 32);

  size_t elen = jose_b64_enc_buf(NULL, 32, NULL, 0);
  if ((elen == SIZE_MAX) || (elen > ELEN_MAX)) {
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_4;
  }

  size_t rlen = jose_b64_enc_buf(thpout, 32, thpout_b64, elen);
  if (rlen != elen) {
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_4;
  }

  const char *jwkout_str = json_dumps(jwkout, JSON_COMPACT);

  if (jwkout_str == NULL) {
    printf("output string is NULL\n");
    outret = TKG_ERROR_CREATE_JWK;
    goto jmp_err_4;
  }

  // construct output file path
  int tang_db_dir_len = strlen(tang_db_dir);
  if (tang_db_dir_len+1+elen+4 >= MAX_PATHNAME_LEN) {
    // thpout_fpath too small
    outret = TKG_ERROR_OUTPUT_JWK;
    goto jmp_err_4;
  }
  memcpy(thpout_fpath, tang_db_dir, tang_db_dir_len);
  thpout_fpath[tang_db_dir_len] = '/';  // add slash at the end
  memcpy(thpout_fpath+1+tang_db_dir_len, thpout_b64, elen);
  memcpy(thpout_fpath+1+tang_db_dir_len+elen, ".jwk", 4);  // add extension

  FILE* fout = fopen(thpout_fpath, "wb");
  if (fout == NULL) {
    outret = TKG_ERROR_OUTPUT_JWK;
    goto jmp_err_4;
  }
  
  fwrite(jwkout_str, 1, strlen(jwkout_str), fout);
  putc('\n', fout);  // append new line at the end to match tang-keygen's style
  fclose(fout);

  jmp_err_4:
  json_decref(jwkout);
  jmp_err_3:
  EVP_PKEY_CTX_free(pctx);
  jmp_err_2:
  EVP_PKEY_free(pkey);
  jmp_err_1:
  BN_clear_free(priv_key_bn);

  return outret;
}


TKGStatus_t tkg_run_recreate(
  const char *metafile_path, const TKGNetworksArray_t *input_nets, const char *tang_db_dir
) {

  int ret;
  TKGStatus_t tkgret;
  tkgctx_t tctx = {};
  TKGPlaneSpec_t cpspec = {};
  TKGPlaneSpec_t hpspec = {};
  Plane_t origin_controlplane = {};
  Plane_t repairplane = {};
  u8 control_salts[MAX_N][SALT_LENGTH] = {};
  u8 hidden_salts[MAX_N][SALT_LENGTH] = {};
  u8 key_salt[KEY_SALT_LENGTH] = {};
  u8 key[KEY_LENGTH] = {};

  // load metafile
  FILE *fin = fopen(metafile_path, "rb");
  if (fin == NULL) {
    // fopen failed
    return TKG_ERROR_INPUT_METAFILE;
  }
  tkgret = read_metafile(
    &tctx, &cpspec, &hpspec,
    control_salts, hidden_salts, key_salt,
    &repairplane, &origin_controlplane, fin
  );
  fclose(fin);
  if (tkgret != TKG_OK) return tkgret;

  Plane_t present_hiddenplane = {};
  present_hiddenplane.spec = hpspec;
  present_hiddenplane.len = tctx.n*present_hiddenplane.spec.hlen;

  tkgret = reconstruct_hiddenplane(
    &present_hiddenplane, &tctx, input_nets, control_salts, hidden_salts,
    &origin_controlplane, &repairplane
  );
  #ifdef TKG_DEBUG
  printf("Reconstructed hiddenplane (%d): ", tkgret);
  debug_print_buf(present_hiddenplane.data, present_hiddenplane.len);
  #endif
  if (tkgret != TKG_OK) return tkgret;

  ret = get_key(key, &present_hiddenplane, key_salt);
  if (ret != 0) return ret;

  #ifdef TKG_DEBUG
  printf("\nReconstructed key: ");
  debug_print_buf(key, KEY_LENGTH);
  printf("\n");
  #endif

  // use SHAKE-256 part to generate multiple partkeys
  // we need two part keys: one for ES521 and other for ECMR signing key
  int partkeys_len = 66*2;

  // GCC 14 complains about dangling pointer to partkeys
  // that's probably false-positive due to inlining
  // I made sure not to use it out of scope
  u8 partkeys[partkeys_len];
  tkgret = gen_partkeys(partkeys, partkeys_len, key, KEY_LENGTH);
  #ifdef TKG_DEBUG
  printf("Partkeys: ");
  debug_print_buf(partkeys, partkeys_len);
  printf("\n");
  #endif
  if (tkgret != TKG_OK) return tkgret;

  // 521 bits (66 bytes) is the length of ES521 curve key
  int partkey_len = 66;
  const char *jwk_types[2] = {"ES521", "ECMR"};

  for (int i=0; i<2; i++) {

    // select current partkey
    u8 *partkey = partkeys+(i*partkey_len);
    const char *jwk_type = jwk_types[i];

    tkgret = output_jwk_from_partkey(partkey, partkey_len, jwk_type, tang_db_dir);
    if (tkgret != TKG_OK) return tkgret;
  
  }

  #ifdef TKG_USE_OPENSSL
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  #else
  wolfCrypt_Cleanup();
  #endif

  return TKG_OK;

}
