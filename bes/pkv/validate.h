#ifndef BES_PKV_VALIDATE_H
#define BES_PKV_VALIDATE_H

#include <bes/pkv/checksum.h>
#include <bes/pkv/hash.h>
bes_bool
bes_pkv_validate_checksum(bes_pkv_checksum_fn checksum_function,
                          const bes_byte *const key,
                          bes_size key_length);

bes_bool
bes_pkv_validate_key(bes_pkv_hash_fn hash_function,
                     bes_pkv_checksum_fn checksum_function,
                     const bes_byte *const key,
                     bes_size key_length,
                     bes_size sub_key_index,
                     bes_u32 sub_key_base);

#endif
