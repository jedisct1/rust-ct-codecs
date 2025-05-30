use crate::error::*;
use crate::{Decoder, Encoder};

/// Hexadecimal encoder and decoder implementation.
///
/// Provides constant-time encoding and decoding of binary data to and from
/// hexadecimal representation. The implementation uses only lowercase
/// hexadecimal characters (0-9, a-f) for encoding.
///
/// # Security
///
/// All operations run in constant time relative to input length, making
/// this implementation suitable for handling sensitive cryptographic data.
///
/// # Examples
///
/// ```
/// use ct_codecs::{Hex, Encoder, Decoder};
///
/// fn example() -> Result<(), ct_codecs::Error> {
///     let data = b"Hello";
///
///     // Encode binary data to hex
///     let encoded = Hex::encode_to_string(data)?;
///     assert_eq!(encoded, "48656c6c6f");
///
///     // Decode hex back to binary
///     let decoded = Hex::decode_to_vec(&encoded, None)?;
///     assert_eq!(decoded, data);
///
///     // Working with preallocated buffers (useful for no_std)
///     let mut hex_buf = [0u8; 10];
///     let hex = Hex::encode(&mut hex_buf, data)?;
///     assert_eq!(hex, b"48656c6c6f");
///
///     let mut bin_buf = [0u8; 5];
///     let bin = Hex::decode(&mut bin_buf, hex, None)?;
///     assert_eq!(bin, data);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
pub struct Hex;

impl Encoder for Hex {
    /// Calculates the encoded length for a hexadecimal representation.
    ///
    /// The encoded length is always twice the binary length, as each byte
    /// is represented by two hexadecimal characters.
    ///
    /// # Arguments
    ///
    /// * `bin_len` - The length of the binary input in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The required length for the encoded output
    /// * `Err(Error::Overflow)` - If the calculation would overflow
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        bin_len.checked_mul(2).ok_or(Error::Overflow)
    }

    /// Encodes binary data into a hexadecimal representation.
    ///
    /// The encoding is performed in constant time relative to the input length.
    ///
    /// # Arguments
    ///
    /// * `hex` - Mutable buffer to store the encoded output
    /// * `bin` - Binary input data to encode
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice of the encoded buffer containing the hex data
    /// * `Err(Error::Overflow)` - If the output buffer is too small
    fn encode<IN: AsRef<[u8]>>(hex: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        let bin = bin.as_ref();
        let bin_len = bin.len();
        let hex_maxlen = hex.len();
        if hex_maxlen < bin_len.checked_shl(1).ok_or(Error::Overflow)? {
            return Err(Error::Overflow);
        }
        for (i, v) in bin.iter().enumerate() {
            let (b, c) = ((v >> 4) as u16, (v & 0xf) as u16);
            let x = (((87 + c + (((c.wrapping_sub(10)) >> 8) & !38)) as u8) as u16) << 8
                | ((87 + b + (((b.wrapping_sub(10)) >> 8) & !38)) as u8) as u16;
            hex[i * 2] = x as u8;
            hex[i * 2 + 1] = (x >> 8) as u8;
        }
        Ok(&hex[..bin_len * 2])
    }
}

impl Decoder for Hex {
    /// Decodes hexadecimal data back into its binary representation.
    ///
    /// The decoding is performed in constant time relative to the input length.
    /// Both uppercase and lowercase hexadecimal characters are accepted.
    ///
    /// # Arguments
    ///
    /// * `bin` - Mutable buffer to store the decoded output
    /// * `hex` - Hexadecimal input data to decode
    /// * `ignore` - Optional set of characters to ignore during decoding
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice of the binary buffer containing the decoded data
    /// * `Err(Error::Overflow)` - If the output buffer is too small
    /// * `Err(Error::InvalidInput)` - If the input contains invalid characters or has odd length
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        hex: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        let hex = hex.as_ref();
        let bin_maxlen = bin.len();
        let mut bin_pos = 0;
        let mut state = false;
        let mut c_acc = 0;
        for &c in hex {
            let c_num = c ^ 48;
            let c_num0 = ((c_num as u16).wrapping_sub(10) >> 8) as u8;
            let c_alpha = (c & !32).wrapping_sub(55);
            let c_alpha0 = (((c_alpha as u16).wrapping_sub(10)
                ^ ((c_alpha as u16).wrapping_sub(16)))
                >> 8) as u8;
            if (c_num0 | c_alpha0) == 0 {
                match ignore {
                    Some(ignore) if ignore.contains(&c) => continue,
                    _ => return Err(Error::InvalidInput),
                };
            }
            let c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
            if bin_pos >= bin_maxlen {
                return Err(Error::Overflow);
            }
            if !state {
                c_acc = c_val << 4;
            } else {
                bin[bin_pos] = c_acc | c_val;
                bin_pos += 1;
            }
            state = !state;
        }
        if state {
            return Err(Error::InvalidInput);
        }
        Ok(&bin[..bin_pos])
    }
}

#[cfg(feature = "std")]
#[test]
fn test_hex() {
    let bin = [1u8, 5, 11, 15, 19, 131];
    let hex = Hex::encode_to_string(bin).unwrap();
    let expected = "01050b0f1383";
    assert_eq!(hex, expected);
    let bin2 = Hex::decode_to_vec(&hex, None).unwrap();
    assert_eq!(bin, &bin2[..]);
}

#[test]
fn test_hex_no_std() {
    let bin = [1u8, 5, 11, 15, 19, 131];
    let expected = "01050b0f1383";
    let mut hex = [0u8; 12];
    let hex = Hex::encode_to_str(&mut hex, bin).unwrap();
    assert_eq!(&hex, &expected);
    let mut bin2 = [0u8; 6];
    let bin2 = Hex::decode(&mut bin2, hex, None).unwrap();
    assert_eq!(bin, bin2);
}
