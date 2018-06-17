#ifndef BES_PKV_BASE32_H
#define BES_PKV_BASE32_H

#include <bes/foundation/types.h>

#if defined(__cplusplus)
extern "C" {
#endif

void
bes_pkv_base32_enc(const bes_byte *const data,
                   bes_size length,
                   char *destination_,
                   bes_size *destination_length_);

/* Destination must be length * 5 / 8 + 1 in size */
void
bes_pkv_base32_dec(const char *const string,
                   bes_size data_length,
                   bes_byte *destination_,
                   bes_size *destination_length_);

#if defined(__cplusplus)
}
#endif

#endif
