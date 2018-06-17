#ifndef BES_PKV_HASH_H
#define BES_PKV_HASH_H

#include <bes/foundation/types.h>

typedef bes_u32 (*bes_pkv_hash_fn)(const bes_byte *const, bes_size);

/* Implementation of the FNV1a hash function */
bes_u32
bes_pkv_hash_fnv1a(const bes_byte *const data, bes_size length);

/* Implementation of Bob Jenkin's Lookup2 hash function */
bes_u32
bes_pkv_hash_lookup2(const bes_byte *const data, bes_size length);

/* Implementation of Bob Jenkin's One-at-a-time hash function */
bes_u32
bes_pkv_hash_one_at_a_time(const bes_byte *const data, bes_size length);

/* Implementation of Paul Jsieh's SuperFast hash */
bes_u32
bes_pkv_hash_super_fast(const bes_byte *const data, bes_size length);

/* Implementation of CRC32 used for hashing */
bes_u32
bes_pkv_hash_crc32(const bes_byte *const data, bes_size length);

/* Implementation of Dan Bernstein k=33 hash */
bes_u32
bes_pkv_hash_djb2(const bes_byte *const data, bes_size length);

#endif
