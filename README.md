# CT-Codecs

A reimplementation of the base64 and hexadecimal codecs from libsodium and libhydrogen in Rust.

- Constant-time for a given length
- Strict (base64 strings are not malleable)
- Supports padded and unpadded, original and URL-safe base64 variants
- Supports characters to be ignored by the decoder
- Zero dependencies, `no_std` friendly
