#include <bes/foundation/bswap.h>

#include <bes/pkv/generate.h>
#include <bes/pkv/validate.h>
#include <bes/pkv/base32.h>

void
bes_pkv_generate(bes_u32 seed,
                 bes_pkv_checksum_fn checksum_function,
                 const bes_u32 *const sub_keys,
                 bes_size n_sub_keys,
                 bes_pkv_hash_fn *hash_functions,
                 bes_size n_hash_functions,
                 char *destination_,
                 bes_size *destination_length_)
{
	const bes_size data_len = (n_sub_keys * 4) + 4;
	const bes_size key_len = data_len + 2;

	/* Need space for (n_sub_keys * 4) + 4 in data */
	bes_byte data[1024];

	/* Need space for (n_sub_keys * 4) + 4 + 2 for key */
	bes_byte key[1024 + 2];

	/* Don't allow this to happen */
	if (data_len > sizeof data || key_len > sizeof key)
	{
		return;
	}

	data[0] = (bes_byte)(seed & 0xFF);
	data[1] = (bes_byte)(seed >> 8);
	data[2] = (bes_byte)(seed >> 16);
	data[3] = (bes_byte)(seed >> 24);

	/* Cycle through hash functions applying them */
	bes_size hash_offset = 0;
	for (bes_size i = 0; i < n_sub_keys; i++)
	{
		bes_u32 digit = seed ^ sub_keys[i];

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

		const bes_u32 hash = hash_functions[hash_offset++](digit_bytes, sizeof digit_bytes);

		data[4 + (4 * i)] = (bes_byte)(hash & 0xFF);
		data[5 + (4 * i)] = (bes_byte)(hash >> 8);
		data[6 + (4 * i)] = (bes_byte)(hash >> 16);
		data[7 + (4 * i)] = (bes_byte)(hash >> 24);

		hash_offset %= n_hash_functions;
	}

	/* Calculate the checksum of our data and assemble the key */
	bes_u16 checksum = checksum_function(data, data_len);
	if (bes_bswap_is_big_endian())
	{
		checksum = bes_bswap_u16(checksum);
	}

	/* Copy the key into our working data */
	for (bes_size i = 0; i < data_len; i++)
	{
		key[i] = data[i];
	}

	/* Append the checksum */
	key[key_len - 2] = (bes_byte)(checksum & 0xFF);
	key[key_len - 1] = (bes_byte)(checksum >> 8);

	/* Generate the Base32 representation in destination */
	bes_pkv_base32_enc(key, key_len, destination_, destination_length_);
}
