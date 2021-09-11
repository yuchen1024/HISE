lib_dir="/usr/local/lib"
include_dir="/usr/local/include"

gcc test_global_escrow_pke2.c -L ${lib_dir} -l relic_s -l gmp -I ${include_dir} -o ../build/test_global_escrow_pke2 