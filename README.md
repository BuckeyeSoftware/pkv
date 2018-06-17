# Partial Key Verification

The following is an implementation of a partial key verification scheme
for verifying that a Pluck license is valid.

* It supports multiple sub keys (version cycling)
* It supports key revocation (serial embedded)
* It supports different checksums (platform cycling)
* It supports different seeding (digest embedding)
* It supports multiple hashing (sub key cycling)

The following work is based off of:
http://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi/

Some minor differences from that blog:
* Subkeys are 32 bits in size instead of 8
* 5-bit encoding via Base32 to shrink the key size to 20%
* Custom hash function per subkey
* Endianess safe (all keys are in LE, all evaluation is in LE)

# Rules
The following rules are set in stone for licensing, they cannot be
modified only added to except for major version bumps.

## Checksum
* Indie licenses utilize `bes_pkv_checksum_adler16`
* SDK licenses utilize `bes_pkv_checksum_crc16`
* Pro licenses utilize `bes_pkv_checksum_crc_itu_t`

## Subkeys
* Platform e.g: "Windows", "Orbis", "Linux", "macOS", etc hashed with `bes_pkv_hash_fnv1a`
* Purchase date in ISO 8601 e.g: "2008-09-15T15:53:00" hashed with `bes_pkv_hash_fnv1a`
* Company name e.g: "Acme" hashed with `bes_pkv_hash_fnv1a`
* Product name e.g: "Bomb" hashed with `bes_pkv_hash_fnv1a`

## Hashes
The hashes used for each subkey are applied in the order specified

* `bes_pkv_hash_lookup2`
* `bes_pkv_hash_one_at_a_time`
* `bes_pkv_hash_super_fast`
* `bes_pkv_hash_crc32`

## Seed
The seed is to be hased with `bes_pkv_hash_djb2`
