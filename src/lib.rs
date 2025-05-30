//! # CT-Codecs
//!
//! A Rust implementation of constant-time Base64 and Hexadecimal codecs,
//! reimplemented from libsodium and libhydrogen.
//!
//! ## Features
//!
//! - **Constant-time implementation** for cryptographic applications where timing attacks are a concern
//! - **Strict validation** ensuring Base64 strings are not malleable
//! - **Multiple variants** of Base64: standard, URL-safe, with and without padding
//! - **Character filtering** for ignoring specific characters during decoding (like whitespace)
//! - **Zero dependencies** and **`no_std` compatible**
//! - **Memory safety** with `#![forbid(unsafe_code)]`
//!
//! ## Usage Examples
//!
//! ### Base64 Encoding
//!
//! ```
//! use ct_codecs::{Base64, Encoder};
//!
//! fn example() -> Result<(), ct_codecs::Error> {
//!     let data = b"Hello, world!";
//!     let encoded = Base64::encode_to_string(data)?;
//!     assert_eq!(encoded, "SGVsbG8sIHdvcmxkIQ==");
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! ### Base64 Decoding
//!
//! ```
//! use ct_codecs::{Base64, Decoder};
//!
//! fn example() -> Result<(), ct_codecs::Error> {
//!     let encoded = "SGVsbG8sIHdvcmxkIQ==";
//!     let decoded = Base64::decode_to_vec(encoded, None)?;
//!     assert_eq!(decoded, b"Hello, world!");
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! ### Hexadecimal Encoding/Decoding
//!
//! ```
//! use ct_codecs::{Hex, Encoder, Decoder};
//!
//! fn example() -> Result<(), ct_codecs::Error> {
//!     let data = b"Hello, world!";
//!     let encoded = Hex::encode_to_string(data)?;
//!     let decoded = Hex::decode_to_vec(&encoded, None)?;
//!     assert_eq!(decoded, data);
//!     Ok(())
//! }
//! # example().unwrap();
//! ```
//!
//! ### No-std Usage with Pre-allocated Buffers
//!
//! ```
//! use ct_codecs::{Base64, Encoder, Decoder};
//!
//! fn example() -> Result<(), ct_codecs::Error> {
//!     let data = b"Hello, world!";
//!     let mut encoded_buf = [0u8; 20]; // Must be large enough
//!     let encoded = Base64::encode(&mut encoded_buf, data)?;
//!     
//!     let mut decoded_buf = [0u8; 13]; // Must be large enough
//!     let decoded = Base64::decode(&mut decoded_buf, encoded, None)?;
//!     assert_eq!(decoded, data);
//!     Ok(())
//! }
//! # example().unwrap();
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

mod base64;
mod error;
mod hex;

pub use base64::*;
pub use error::*;
pub use hex::*;

/// Trait for encoding binary data into text representations.
///
/// Implementors of this trait provide constant-time encoding operations
/// for a specific encoding format (Base64, Hex, etc.).
pub trait Encoder {
    /// Calculates the length of the encoded output for a given binary input length.
    ///
    /// # Arguments
    ///
    /// * `bin_len` - The length of the binary input in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The required length for the encoded output
    /// * `Err(Error::Overflow)` - If the calculation would overflow
    fn encoded_len(bin_len: usize) -> Result<usize, Error>;

    /// Encodes binary data into a text representation.
    ///
    /// # Arguments
    ///
    /// * `encoded` - Mutable buffer to store the encoded output
    /// * `bin` - Binary input data to encode
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice of the encoded buffer containing the encoded data
    /// * `Err(Error::Overflow)` - If the output buffer is too small
    fn encode<IN: AsRef<[u8]>>(encoded: &mut [u8], bin: IN) -> Result<&[u8], Error>;

    /// Encodes binary data and returns the result as a string slice.
    ///
    /// # Arguments
    ///
    /// * `encoded` - Mutable buffer to store the encoded output
    /// * `bin` - Binary input data to encode
    ///
    /// # Returns
    ///
    /// * `Ok(&str)` - A string slice containing the encoded data
    /// * `Err(Error::Overflow)` - If the output buffer is too small
    fn encode_to_str<IN: AsRef<[u8]>>(encoded: &mut [u8], bin: IN) -> Result<&str, Error> {
        Ok(core::str::from_utf8(Self::encode(encoded, bin)?).unwrap())
    }

    /// Encodes binary data and returns the result as a String.
    ///
    /// This method is only available when the `std` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `bin` - Binary input data to encode
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - A String containing the encoded data
    /// * `Err(Error::Overflow)` - If the calculation would overflow
    #[cfg(feature = "std")]
    fn encode_to_string<IN: AsRef<[u8]>>(bin: IN) -> Result<String, Error> {
        let mut encoded = vec![0u8; Self::encoded_len(bin.as_ref().len())?];
        let encoded_len = Self::encode(&mut encoded, bin)?.len();
        encoded.truncate(encoded_len);
        Ok(String::from_utf8(encoded).unwrap())
    }
}

/// Trait for decoding text representations back into binary data.
///
/// Implementors of this trait provide constant-time decoding operations
/// for a specific encoding format (Base64, Hex, etc.).
pub trait Decoder {
    /// Decodes text data back into its binary representation.
    ///
    /// # Arguments
    ///
    /// * `bin` - Mutable buffer to store the decoded output
    /// * `encoded` - Text input data to decode
    /// * `ignore` - Optional set of characters to ignore during decoding (e.g., whitespace)
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice of the binary buffer containing the decoded data
    /// * `Err(Error::Overflow)` - If the output buffer is too small
    /// * `Err(Error::InvalidInput)` - If the input contains invalid characters
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        encoded: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error>;

    /// Decodes text data and returns the result as a Vec<u8>.
    ///
    /// This method is only available when the `std` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `encoded` - Text input data to decode
    /// * `ignore` - Optional set of characters to ignore during decoding (e.g., whitespace)
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A Vec containing the decoded binary data
    /// * `Err(Error::InvalidInput)` - If the input contains invalid characters
    #[cfg(feature = "std")]
    fn decode_to_vec<IN: AsRef<[u8]>>(
        encoded: IN,
        ignore: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut bin = vec![0u8; encoded.as_ref().len()];
        let bin_len = Self::decode(&mut bin, encoded, ignore)?.len();
        bin.truncate(bin_len);
        Ok(bin)
    }
}

/// Constant-time equality check for two byte slices.
///
/// # Arguments
///
/// * `x` - First byte slice
/// * `y` - Second byte slice
///
/// # Returns
///
/// * `bool` - `true` if the slices are equal, `false` otherwise
pub fn verify(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false;
    }
    let mut v: u32 = 0;
    // Old Rust versions, don't have black_box(), using volatile is unsafe,
    // and WebAssembly doesn't support volatile and ignores black_box() anyway.
    // So, add an extra layer of compiler confusion.
    let (mut h1, mut h2) = (0u32, 0u32);
    for (b1, b2) in x.iter().zip(y.iter()) {
        h1 ^= (h1 << 5).wrapping_add((h1 >> 2) ^ *b1 as u32);
        h2 ^= (h2 << 5).wrapping_add((h2 >> 2) ^ *b2 as u32);
    }
    v |= h1 ^ h2;
    for (a, b) in x.iter().zip(y.iter()) {
        v |= (a ^ b) as u32;
    }
    v == 0
}
