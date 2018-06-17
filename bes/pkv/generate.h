#ifndef BES_PKV_GENERATE_H
#define BES_PKV_GENERATE_H

#include <bes/pkv/hash.h>
#include <bes/pkv/checksum.h>

/* Destination must have 7*n_sub_key+1 space to store the serial */
void
bes_pkv_generate(bes_u32 seed,
                 bes_pkv_checksum_fn checksum_function,
                 const bes_u32 *const sub_keys,
                 bes_size n_sub_keys,
                 bes_pkv_hash_fn *hash_functions,
                 bes_size n_hash_functions,
                 char *destination_,
                 bes_size *destination_length);
#endif
