#include <stdio.h>

#include <criterion/criterion.h>
#include <criterion/redirect.h>
#include <criterion/parameterized.h>

#include "../twkg.h"

#define jwk_path "/tmp/"
#define metafile_path "/tmp/mf.bin"

void genrec_test(
  const char *variant, TKGStatus_t ers, bool is_gen, int n, int p, int k, int o
) {

  int input_n = 0;
  TKGNetworksArray_t input_nets = {};
  char input_json_path[256] = {};
  snprintf(
    input_json_path, 256, "./tests/vectors/%s_n%d_p%d_k%d_o%d/%s.json",
    variant, n, p, k, o, (is_gen ? "gen" : "rec")
  );

  cr_log_info("using json file: %s", input_json_path);
  TKGStatus_t tkgret = tkg_load_nets(&input_nets, &input_n, input_json_path);
  cr_log_info("loaded %d networks\n", input_n);

  cr_assert_eq(tkgret, TKG_OK);
  cr_assert_eq(input_n, is_gen ? n : k);

  if (is_gen) {
    const int input_p = p;
    cr_assert_eq(
      tkg_run_generate(metafile_path, &input_nets, input_p), TKG_OK
    ); \
  } else {
    cr_assert_eq(
      tkg_run_recreate(metafile_path, &input_nets, jwk_path), ers
    );
  }
}

typedef struct {
  const char variant[16];
  TKGStatus_t ers;  // expected reconstruction status
  int n;
  int p;
  int k;
  int o;
} genrec_test_case_t;

genrec_test_case_t genrec_test_cases[] = {
  {"simple", TKG_OK, 3, 3, 3, 3},
  {"simple", TKG_OK, 5, 3, 3, 3},
  {"simple", TKG_OK, 8, 1, 15, 1},
  {"simple", TKG_OK, 12, 9, 20, 9},
  {"compact", TKG_OK, 6, 4, 8, 6},
  {"fail", TKG_ERROR_RECONSTRUCT, 8, 5, 20, 4},
  {"simple", TKG_OK, 8, 5, 20, 5},
};

ParameterizedTestParameters(parameterized_tests, genrec_test) {
  size_t num_tests = sizeof(genrec_test_cases) / sizeof(genrec_test_case_t);
  return cr_make_param_array(genrec_test_case_t, genrec_test_cases, num_tests);
}

ParameterizedTest(genrec_test_case_t *tc, parameterized_tests, genrec_test) {

  cr_log_info("GEN variant: %s, n: %d, p: %d, k: %d, o: %d",
                 tc->variant, tc->n, tc->p, tc->k, tc->o);
  genrec_test(tc->variant, tc->ers, true, tc->n, tc->p, tc->k, tc->o);

  cr_log_info("REC variant: %s, n: %d, p: %d, k: %d, o: %d",
                 tc->variant, tc->n, tc->p, tc->k, tc->o);
  genrec_test(tc->variant, tc->ers, false, tc->n, tc->p, tc->k, tc->o);

}

TestSuite(parameterized_tests);
