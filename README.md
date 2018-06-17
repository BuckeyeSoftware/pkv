# Partial Key Verification

The following is an implementation of a partial key verification scheme
for generating and verifying license keys.

* It supports multiple sub keys (e.g: version cycling)
* It supports key revocation (e.g: serial embedded)
* It supports different checksums (e.g: platform cycling)
* It supports different seeding (e.g: digest embedding)
* It supports multiple hashing (e.g: sub key cycling)

The following work is based off of:
http://www.brandonstaggs.com/2007/07/26/implementing-a-partial-serial-number-verification-system-in-delphi/

Some minor differences from that blog:
* Subkeys are 32 bits in size instead of 8
* 5-bit encoding via Base32 to shrink the key size to 20%
* Custom hash function per subkey
* Endianess safe (all keys are in LE, all evaluation is in LE)
