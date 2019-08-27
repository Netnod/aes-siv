# aead_aes_siv_cmac
Hardware implementation of AEAD_AES_SIV_CMAC

## Status
Not completed. Does **NOT** work. Do **NOT** use.


## Introduction
The authenticated encryption (AE) block cipher mode AEAD_AES_SIV_CMAC
(AES-SIV) combines the block cipher mode using CTR mode (see [NIST SP
800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf))
for encryption, and CMAC mode (see [NIST SP 800-38B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf)) for
authentication. The algorithm uses CMAC in a construction called S2V
that generates the MAC tag, which also is the Synthetic IV (SIV) for CTR
(which confusingly is called nonce in SP 800-38A). The generate the
synthetic IV (nonce) for CTR. The mode also supports additional (or
associated) data (AD) that is authenticated but not encrypted.

The AE mode AES-SIV is specified in [RFC 5297 - Synthetic Initialization Vector
(SIV) Authenticated Encryption Using the Advanced Encryption Standard
(AES)](https://tools.ietf.org/html/rfc5297).

The implementation will support AEAD_AES_SIV_CMAC_256 and
AEAD_AES_SIV_CMAC_512 as defined in RFC 5297. The implementation will not support
AEAD_AES_SIV_CMAC_384 since [the aes
core](https://github.com/secworks/aes) does not support 192 bit keys.


## Implementation details
The core is based on a single AES primitive. The cmac functionaliy has
been fetched from the [CMAC core](https://github.com/secworks/cmac). But
since that core contains its own AES instantiation it has been modified
to have the AES core extracted.

As a limitation compared to RFC 5297, the implementation does not
support an arbitrary number of AD fields. The fields supported by the
core:

* AD. Used as first string S in S2V.
* Nonce. Used as second string S in S2V.
* Plaintext. Used as third and final string S in S2V.

The core will support that the length of each field is zero or more
bytes.

The core expects to be connected to a memory and The core supports
dynamic (i.e. multi cycle) access latency to the memory. The core read
and write 128 bit blocks. Note that during encryption the plaintext
stored in the memory will be replaced with the
ciphertext. Correspondingly the ciphertext will be replaced with the
plaintext during decryption.
