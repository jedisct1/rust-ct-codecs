# CT-Codecs

A Rust implementation of constant-time Base64, Base32, and Hexadecimal codecs for cryptographic applications, originally derived from libsodium and libhydrogen.

[![Crates.io](https://img.shields.io/crates/v/ct-codecs.svg)](https://crates.io/crates/ct-codecs)
[![Documentation](https://docs.rs/ct-codecs/badge.svg)](https://docs.rs/ct-codecs)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jedisct1/rust-ct-codecs/blob/master/LICENSE)

## Overview

This library provides constant-time encoding and decoding functions for Base64, Base32, and Hexadecimal formats. It is specifically designed for cryptographic applications where timing side-channel attacks are a concern.

## Features

- **Constant-time implementation**: Resistant to timing side-channel attacks
- **Multiple codec formats**:
  - **Base64**: Standard and URL-safe variants, with and without padding
  - **Base32**: Standard and Hex variants, with and without padding
  - **Hexadecimal**: Lowercase hex encoding and decoding
- **Strict validation**: Non-malleable strings for enhanced security
- **Character filtering**: Optional ignoring of specific characters during decoding (whitespace, etc.)
- **Zero dependencies**: No external crates required
- **`no_std` compatible**: Works in environments without the standard library
- **Memory safety**: No unsafe code (`#![forbid(unsafe_code)]`)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ct-codecs = "1"
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

### Base64 Variants

```rust
use ct_codecs::{Base64, Base64NoPadding, Base64UrlSafe, Base64UrlSafeNoPadding, Decoder, Encoder};

let data = b"Hello, world!";

// Standard Base64 with padding
let encoded1 = Base64::encode_to_string(data)?;
assert_eq!(encoded1, "SGVsbG8sIHdvcmxkIQ==");

// Standard Base64 without padding
let encoded2 = Base64NoPadding::encode_to_string(data)?;
assert_eq!(encoded2, "SGVsbG8sIHdvcmxkIQ");

// URL-safe Base64 with padding
let encoded3 = Base64UrlSafe::encode_to_string(data)?;
assert_eq!(encoded3, "SGVsbG8sIHdvcmxkIQ==");

// URL-safe Base64 without padding
let encoded4 = Base64UrlSafeNoPadding::encode_to_string(data)?;
assert_eq!(encoded4, "SGVsbG8sIHdvcmxkIQ");
```

### Base32 Encoding/Decoding

```rust
use ct_codecs::{Base32, Base32Hex, Decoder, Encoder};

let data = b"Hello";

// Standard Base32 with padding
let encoded = Base32::encode_to_string(data)?;
assert_eq!(encoded, "JBSWY3DP");

// Base32Hex variant
let encoded_hex = Base32Hex::encode_to_string(data)?;
assert_eq!(encoded_hex, "91IMOR3F");

// Decoding
let decoded = Base32::decode_to_vec(&encoded, None)?;
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

### Constant-Time Operations

All operations in this library are implemented to run in constant time relative to the input length, which helps prevent timing side-channel attacks. This makes it suitable for handling sensitive cryptographic material where traditional implementations might leak information about the data being processed.

### Implementation Details

- No branches dependent on secret data
- No table lookups indexed by secret data
- Careful implementation of character validation

### Strict Validation

The decoders apply strict validation rules to prevent malleability, making them suitable for cryptographic applications where data integrity is crucial.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/jedisct1/rust-ct-codecs/blob/master/LICENSE) file for details.
