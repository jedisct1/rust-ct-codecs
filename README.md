# CT-Codecs

A Rust implementation of constant-time Base64 and Hexadecimal codecs, originally from libsodium and libhydrogen.

[![Crates.io](https://img.shields.io/crates/v/ct-codecs.svg)](https://crates.io/crates/ct-codecs)
[![Documentation](https://docs.rs/ct-codecs/badge.svg)](https://docs.rs/ct-codecs)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jedisct1/rust-ct-codecs/blob/master/LICENSE)

## Features

- **Constant-time implementation**: Suitable for cryptographic applications where timing attacks are a concern
- **Strict validation**: Base64 strings are not malleable, providing security for cryptographic applications
- **Multiple variants**: Supports standard Base64, URL-safe Base64, both with and without padding
- **Character filtering**: Supports ignoring specific characters during decoding (useful for whitespace/newlines)
- **Zero dependencies**: No external crates required
- **`no_std` compatible**: Works in environments without the standard library
- **Memory safety**: No unsafe code (`#![forbid(unsafe_code)]`)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ct-codecs = "1.1.3"
```

## Usage Examples

### Base64 Encoding/Decoding

```rust
use ct_codecs::{Base64, Decoder, Encoder};

// Standard Base64 with padding
let data = b"Hello, world!";
let encoded = Base64::encode_to_string(data)?;
assert_eq!(encoded, "SGVsbG8sIHdvcmxkIQ==");

// Decoding
let decoded = Base64::decode_to_vec(&encoded, None)?;
assert_eq!(decoded, data);

// Ignoring specific characters (like whitespace)
let encoded_with_whitespace = "SGVsbG8s IHdvcmxk IQ==";
let decoded = Base64::decode_to_vec(&encoded_with_whitespace, Some(b" \t\n"))?;
assert_eq!(decoded, data);
```

### URL-safe Base64 Encoding/Decoding

```rust
use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};

// URL-safe Base64 with padding
let data = b"Hello, world!";
let encoded = Base64UrlSafe::encode_to_string(data)?;
assert_eq!(encoded, "SGVsbG8sIHdvcmxkIQ==");

// URL-safe Base64 without padding
let encoded_no_padding = Base64UrlSafeNoPadding::encode_to_string(data)?;
assert_eq!(encoded_no_padding, "SGVsbG8sIHdvcmxkIQ");

// Decoding
let decoded = Base64UrlSafeNoPadding::decode_to_vec(&encoded_no_padding, None)?;
assert_eq!(decoded, data);
```

### Hexadecimal Encoding/Decoding

```rust
use ct_codecs::{Hex, Decoder, Encoder};

let data = b"Hello, world!";
let encoded = Hex::encode_to_string(data)?;
assert_eq!(encoded, "48656c6c6f2c20776f726c6421");

let decoded = Hex::decode_to_vec(&encoded, None)?;
assert_eq!(decoded, data);
```

### Working in `no_std` Environments

```rust
use ct_codecs::{Base64, Decoder, Encoder};

// Preallocated buffers for no_std environments
let data = b"Hello, world!";
let mut encoded_buf = [0u8; 20]; // Buffer must be large enough
let encoded = Base64::encode(&mut encoded_buf, data)?;

let mut decoded_buf = [0u8; 13]; // Buffer must be large enough
let decoded = Base64::decode(&mut decoded_buf, encoded, None)?;
assert_eq!(decoded, data);
```

## Error Handling

The library uses a simple error type with two variants:

- `Error::Overflow`: The provided output buffer would be too small
- `Error::InvalidInput`: The input isn't valid for the given encoding

## Security Considerations

All operations are implemented to run in constant time relative to the input length, which helps prevent timing side-channel attacks. This makes the library suitable for handling sensitive cryptographic material.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jedisct1/rust-ct-codecs/blob/master/LICENSE) file for details.