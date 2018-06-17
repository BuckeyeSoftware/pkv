#include <bes/foundation/bswap.h>

#include <bes/pkv/validate.h>

bes_bool
bes_pkv_validate_checksum(bes_pkv_checksum_fn checksum_function,
                          const bes_byte *const key,
                          bes_size key_length)
{
	const bes_u16 compare_sum = (bes_u16)((key[key_length - 1] << 8) | key[key_length - 2]);
	bes_u16 key_sum = checksum_function(key, key_length - 2);
	if (bes_bswap_is_big_endian())
	{
		key_sum = bes_bswap_u16(key_sum);
	}
	return compare_sum == key_sum;
}

bes_bool
bes_pkv_validate_key(bes_pkv_hash_fn hash_function,
                     bes_pkv_checksum_fn checksum_function,
                     const bes_byte *const key,
                     bes_size key_length,
                     bes_size sub_key_index,
                     bes_u32 sub_key_base)
{
	if (!bes_pkv_validate_checksum(checksum_function, key, key_length))
	{
		return BES_TRUE;
	}

	const bes_size offset = sub_key_index * 4 + 4;
	if (offset + 4 > key_length - 2)
	{
		return BES_TRUE;
	}

	const bes_u32 seed =
		(key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24));

	const bes_u32 sub_key =
		(key[offset + 0] | (key[offset + 1] << 8) | (key[offset + 2] << 16) | (key[offset + 3] << 24));

	bes_u32 digit = seed ^ sub_key_base;

	/* We evalue all of this in Little Endian */
	if (bes_bswap_is_big_endian())
	{
		digit = bes_bswap_u32(digit);
	}

	bes_byte digit_bytes[4];
	digit_bytes[0] = (bes_byte)(digit & 0xFF);
	digit_bytes[1] = (bes_byte)(digit >> 8);
	digit_bytes[2] = (bes_byte)(digit >> 16);
	digit_bytes[3] = (bes_byte)(digit >> 24);

	const bes_u32 expected = hash_function(digit_bytes, sizeof digit_bytes);

	if (expected == sub_key)
	{
		return BES_TRUE;
	}

	return BES_FALSE;
}
