#include "twkg.h"

void print_help() {
  fprintf(stderr,
"usage: twkg [gen|rec] metafile [tang_db_dir if rec | p if gen] < wifi_json\n\n\
generate:    twkg gen /usr/share/twkg/metafile.bin 3 < /tmp/wifi.json\n\
reconstruct: twkg rec /usr/share/twkg/metafile.bin /tmp/tang/db/ < ubus call iwinfo scan '{\"device\":\"phy0-ap0\"}'\n");
}

int main(int argc, char **argv) {

  if(argc != 4) goto arg_err;

  const char *mode = argv[1];
  const char *metafile_path = argv[2];

  TKGNetworksArray_t input_nets = {};
  int input_n = 0;
  TKGStatus_t tkgret = tkg_load_nets(&input_nets, &input_n, "/dev/stdin");
  if (tkgret != TKG_OK) {
    printf("Error loading networks from stdin\n");
    return 1;
  }

  if (strcmp(mode, "gen") == 0) {
    const int input_p = atoi(argv[3]);
    return tkg_run_generate(metafile_path, &input_nets, input_p);
  } else if (strcmp(mode, "rec") == 0) {
    return tkg_run_recreate(metafile_path, &input_nets, argv[3]);
  }

  arg_err:

  // invalid mode or usage error
  print_help();

  return 1;
}
