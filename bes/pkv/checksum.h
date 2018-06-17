#ifndef BES_PKV_CHECKSUM_H
#define BES_PKV_CHECKSUM_H

#include <bes/foundation/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef bes_u16 (*bes_pkv_checksum_fn)(const bes_byte *const, bes_size);

/* Implementation of Adler-16 checksum */
bes_u16
bes_pkv_checksum_adler16(const bes_byte *const data, bes_size length);

/* Implementation of CRC-16 checksum */
bes_u16
bes_pkv_checksum_crc16(const bes_byte *const data, bes_size length);

/* Implementation of CRC-ITU-T checksum */
bes_u16
bes_pkv_checksum_crc_itu_t(const bes_byte *const data, bes_size length);

#if defined(__cplusplus)
}
#endif

#endif
