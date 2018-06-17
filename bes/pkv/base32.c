#include <bes/pkv/base32.h>

static const char*
bes_pkv_base32_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

bes_byte
bes_pkv_base32_map_index_of(bes_byte ch)
{
	for (bes_size i = 0; i < 32; i++)
	{
		const bes_byte byte = bes_pkv_base32_map[i];
		if (byte == ch)
		{
			return (bes_byte)i;
		}
	}

	/* Unreachable */
	return 0;
}

void
bes_pkv_base32_enc(const bes_byte *const data,
                   bes_size length,
                   char *destination_,
                   bes_size *destination_length_)
{
	length--;
	for (bes_size i = 0, offset = 0; i <= length; i++)
	{
		bes_byte ip = 0;
		if (i != length)
		{
			ip = data[i + 1];
		}

		switch (offset)
		{
		case 0:
			*destination_++ = bes_pkv_base32_map[data[i] >> 3];
			*destination_++ = bes_pkv_base32_map[((data[i] << 2) & 0x1F) | (ip >> 6)];
			(*destination_length_) += 2;
			offset = 2;
			break;
		case 1:
			*destination_++ = bes_pkv_base32_map[(data[i] >> 2) & 0x1F];
			*destination_++ = bes_pkv_base32_map[((data[i] << 3) & 0x1F) | (ip >> 5)];
			(*destination_length_) += 2;
			offset = 3;
			break;
		case 2:
			*destination_++ = bes_pkv_base32_map[(data[i] >> 1) & 0x1F];
			*destination_++ = bes_pkv_base32_map[((data[i] << 4) & 0x1F) | (ip >> 4)];
			(*destination_length_) += 2;
			offset = 4;
			break;
		case 3:
			*destination_++ = bes_pkv_base32_map[data[i] & 0x1F];
			(*destination_length_)++;
			offset = 0;
			break;
		case 4:
			*destination_++ = bes_pkv_base32_map[((data[i] << 1) & 0x1F) | (ip >> 7)];
			(*destination_length_)++;
			offset = 1;
			break;
		}
	}

	*destination_++ = '\0';
}

void
bes_pkv_base32_dec(const char *const data,
                     bes_size data_length,
                     bes_byte *destination_,
                     bes_size *destination_length_)
{
	bes_size length = data_length * 5 / 8;
	for (bes_size i = 0, j = 0, offset = 0; i < length; i++)
	{
		bes_byte byte;
		switch (offset)
		{
		case 0:
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] = (bes_byte)(byte << 3);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte >> 2);
			offset = 3;
			break;
		case 1:
			destination_[i] = (bes_byte)(byte << 4);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte >> 1);
			offset = 4;
			break;
		case 2:
			destination_[i] = (bes_byte)(byte << 5);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= byte;
			offset = 0;
			break;
		case 3:
			destination_[i] = (bes_byte)(byte << 6);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte << 1);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte >> 4);
			destination_[i] |= (bes_byte)(byte >> 4);
			offset = 1;
			break;
		case 4:
			destination_[i] = (bes_byte)(byte << 7);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte << 2);
			byte = bes_pkv_base32_map_index_of(data[j++]);
			destination_[i] |= (bes_byte)(byte >> 3);
			offset = 2;
			break;
		}
	}

	*destination_length_ = length;
}
