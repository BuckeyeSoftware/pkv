#include <bes/foundation/bswap.h>

#include <bes/pkv/hash.h>

bes_u16
bes_pkv_hash_combine(bes_byte a, bes_byte b)
{
	const bes_u16 result = (bes_u16)((a << 8) | b);
	return bes_bswap_is_big_endian() ? bes_bswap_u16(result) : result;
}

/* Implementation of the FNV1a hash function */
bes_u32
bes_pkv_hash_fnv1a(const bes_byte *const data, bes_size length)
{
	bes_u32 hash = 2166136261;

	for (bes_size i = 0; i < length; i++)
	{
		const bes_byte byte = data[i];
		hash ^= byte;
		hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
	}

	return hash;
}

/* Implementation of Bob Jenkin's Lookup2 hash function */
static void
bes_pkv_hash_lookup2_mix(bes_u32 *a_, bes_u32 *b_, bes_u32 *c_)
{
	bes_u32 a = *a_;
	bes_u32 b = *b_;
	bes_u32 c = *c_;
	a -= b;
	a -= c;
	a ^= (c >> 13);
	b -= c;
	b -= a;
	b ^= (a << 8);
	c -= a;
	c -= b;
	c ^= (b >> 13);
	a -= b;
	a -= c;
	a ^= (c >> 12);
	b -= c;
	b -= a;
	b ^= (a << 16);
	c -= a;
	c -= b;
	c ^= (b >> 5);
	a -= b;
	a -= c;
	a ^= (c >> 3);
	b -= c;
	b -= a;
	b ^= (a << 10);
	c -= a;
	c -= b;
	c ^= (b >> 15);
	*a_ = a;
	*b_ = b;
	*c_ = c;
}

bes_u32
bes_pkv_hash_lookup2(const bes_byte *const data, bes_size length)
{
	bes_u32 a = 0x9e3779b9;
	bes_u32 b = 0x9e3779b9;
	bes_u32 c = 0;

	bes_size i = 0;
	while (i + 12 <= length)
	{
		a += data[i + 0] | ((bes_u32)data[i + 1] << 8) | ((bes_u32)data[i + 2] << 16) | ((bes_u32)data[i + 3] << 24);
		i += 4;
		b += data[i + 0] | ((bes_u32)data[i + 1] << 8) | ((bes_u32)data[i + 2] << 16) | ((bes_u32)data[i + 3] << 24);
		i += 4;
		c += data[i + 0] | ((bes_u32)data[i + 1] << 8) | ((bes_u32)data[i + 2] << 16) | ((bes_u32)data[i + 3] << 24);
		i += 4;
		bes_pkv_hash_lookup2_mix(&a, &b, &c);
	}

	c += (bes_u32)length;

	if (i < length)
	{
		a += data[i++];
	}
	if (i < length)
	{
		a += (bes_u32)data[i++] << 8;
	}
	if (i < length)
	{
		a += (bes_u32)data[i++] << 16;
	}
	if (i < length)
	{
		a += (bes_u32)data[i++] << 24;
	}

	if (i < length)
	{
		b += data[i++];
	}
	if (i < length)
	{
		b += (bes_u32)data[i++] << 8;
	}
	if (i < length)
	{
		b += (bes_u32)data[i++] << 16;
	}
	if (i < length)
	{
		b += (bes_u32)data[i++] << 24;
	}

	/* The first byte of c is reserved for length */
	if (i < length)
	{
		c += (bes_u32)data[i++] << 8;
	}
	if (i < length)
	{
		c += (bes_u32)data[i++] << 16;
	}
	if (i < length)
	{
		c += (bes_u32)data[i++] << 24;
	}

	bes_pkv_hash_lookup2_mix(&a, &b, &c);

	return c;
}

/* Implementation of Bob Jenkin's One-at-a-time hash function */
bes_u32
bes_pkv_hash_one_at_a_time(const bes_byte *const data, bes_size length)
{
	bes_u32 hash = 0;

	for (bes_size i = 0; i < length; i++)
	{
		hash += data[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash;
}

/* Implementation of Paul Jsieh's SuperFast hash */
bes_u32
bes_pkv_hash_super_fast(const bes_byte *const data, bes_size length)
{
	bes_size remainder = length & 3;
	bes_size offset = 0;
	bes_u32 hash = (bes_u32)length;

	length >>= 2;
	for (; length; length--)
	{
		hash += (data[offset+1] << 8) | data[offset];
		offset += 2;
		const bes_u16 next = bes_pkv_hash_combine(data[offset], data[offset+1]);
		offset += 2;
		const bes_u32 mask = (bes_u32)(next << 11) ^ hash;
		hash = (hash << 16) ^ mask;
		hash += hash >> 11;
	}

	switch (remainder)
	{
	case 3:
		hash += bes_pkv_hash_combine(data[offset], data[offset+1]);
		offset += 2;
		hash ^= hash << 16;
		hash ^= (bes_u32)(data[offset] << 18);
		hash += hash >> 11;
		break;
	case 2:
		hash += bes_pkv_hash_combine(data[offset], data[offset+1]);
		hash ^= hash << 11;
		hash += hash >> 17;
		break;
	case 1:
		hash += data[offset];
		hash ^= hash << 10;
		hash += hash >> 1;
	}

	/* Force avalanching of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash;
}

/* Implementation of CRC32 used for hashing */
static const bes_u32
bes_pkv_hash_crc32_table[256] =
{
	0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
	0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
	0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9, 0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
	0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
	0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
	0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
	0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
	0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1, 0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
	0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
	0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
	0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
	0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
	0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e, 0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
	0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
	0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
	0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
	0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
	0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f, 0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
	0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
	0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
	0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
	0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
	0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7, 0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
	0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
	0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
	0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
	0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
	0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088, 0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
	0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
	0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
	0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
	0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
};

static bes_u32
bes_pkv_hash_crc32_reflect(bes_u32 data, bes_byte n_bits)
{
	bes_u32 reflection = 0;

	/* Reflect the data about the center bit */
	for (bes_byte bit = 0; bit < n_bits; bit++)
	{
		/* If the LSB bit is set reflect it */
		if (data & 0x01)
		{
			reflection |= (bes_u32)(1 << ((n_bits - 1) - bit));
		}

		data >>= 1;
	}

	return reflection;
}

bes_u32
bes_pkv_hash_crc32(const bes_byte *const data, bes_size length)
{
	bes_u32 remainder = 0xFFFFFFFF;

	/* Divide the message by the polynomial one byte at a time */
	for (bes_size i = 0; i < length; i++)
	{
		const bes_byte byte = data[i];
		const bes_byte index =
			(bes_byte)(bes_pkv_hash_crc32_reflect(byte, 8) ^ (remainder >> 24));
		remainder = bes_pkv_hash_crc32_table[index] ^ (remainder << 8);
	}

	return bes_pkv_hash_crc32_reflect(remainder, 32) ^ 0xFFFFFFFF;
}

bes_u32
bes_pkv_hash_djb2(const bes_byte *const data, bes_size length)
{
	bes_u32 hash = 5381;

	for (bes_size i = 0; i < length; i++)
	{
		const bes_byte byte = data[i];
		hash = ((hash << 5) + hash) + byte;
	}

	return hash;
}
