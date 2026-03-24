use crate::error::*;
use crate::{Decoder, Encoder};

struct Base32Impl;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Base32Variant {
    Standard = 1,
    StandardNoPadding = 3,
    Hex = 5,
    HexNoPadding = 7,
}

enum VariantMask {
    NoPadding = 2,
    Hex = 4,
}

impl Base32Impl {
    #[inline]
    fn is_no_padding(variant: Base32Variant) -> bool {
        (variant as u16 & VariantMask::NoPadding as u16) != 0
    }

    #[inline]
    fn is_hex(variant: Base32Variant) -> bool {
        (variant as u16 & VariantMask::Hex as u16) != 0
    }

    #[inline]
    fn _eq(x: u8, y: u8) -> u8 {
        !(((0u16.wrapping_sub((x as u16) ^ (y as u16))) >> 8) as u8)
    }

    #[inline]
    fn _gt(x: u8, y: u8) -> u8 {
        (((y as u16).wrapping_sub(x as u16)) >> 8) as u8
    }

    #[inline]
    fn _ge(x: u8, y: u8) -> u8 {
        !Self::_gt(y, x)
    }

    #[inline]
    fn _lt(x: u8, y: u8) -> u8 {
        Self::_gt(y, x)
    }

    #[inline]
    fn _le(x: u8, y: u8) -> u8 {
        Self::_ge(y, x)
    }

    #[inline]
    fn b32_byte_to_char(x: u8) -> u8 {
        (Self::_lt(x, 26) & (x.wrapping_add(b'A')))
            | (Self::_ge(x, 26) & Self::_lt(x, 32) & (x.wrapping_add(b'2'.wrapping_sub(26))))
    }

    #[inline]
    fn b32_char_to_byte(c: u8) -> u8 {
        let x = (Self::_ge(c, b'A') & Self::_le(c, b'Z') & (c.wrapping_sub(b'A')))
            | (Self::_ge(c, b'2') & Self::_le(c, b'7') & (c.wrapping_sub(b'2').wrapping_add(26)));
        x | (Self::_eq(x, 0) & (Self::_eq(c, b'A') ^ 0xff))
    }

    #[inline]
    fn b32_hex_byte_to_char(x: u8) -> u8 {
        (Self::_lt(x, 10) & (x.wrapping_add(b'0')))
            | (Self::_ge(x, 10) & Self::_lt(x, 32) & (x.wrapping_add(b'A'.wrapping_sub(10))))
    }

    #[inline]
    fn b32_hex_char_to_byte(c: u8) -> u8 {
        let x = (Self::_ge(c, b'0') & Self::_le(c, b'9') & (c.wrapping_sub(b'0')))
            | (Self::_ge(c, b'A') & Self::_le(c, b'V') & (c.wrapping_sub(b'A').wrapping_add(10)));
        x | (Self::_eq(x, 0) & ((Self::_eq(c, b'0') | Self::_eq(c, b'A')) ^ 0xff))
    }

    #[inline]
    #[allow(clippy::manual_div_ceil)]
    fn encoded_len(bin_len: usize, variant: Base32Variant) -> Result<usize, Error> {
        let groups = bin_len / 5;
        let remainder = bin_len - 5 * groups;
        let mut b32_len = groups.checked_mul(8).ok_or(Error::Overflow)?;
        if remainder != 0 {
            let remainder_len = if Self::is_no_padding(variant) {
                (remainder * 8 + 4) / 5
            } else {
                8
            };
            b32_len = b32_len.checked_add(remainder_len).ok_or(Error::Overflow)?;
        }
        Ok(b32_len)
    }

    #[allow(clippy::manual_div_ceil)]
    pub fn encode<'t>(
        b32: &'t mut [u8],
        bin: &[u8],
        variant: Base32Variant,
    ) -> Result<&'t [u8], Error> {
        let b32_len = Self::encoded_len(bin.len(), variant)?;
        let b32_maxlen = b32.len();
        let mut acc_len = 0usize;
        let mut b32_pos = 0usize;
        let mut acc = 0u16;

        if b32_maxlen < b32_len {
            return Err(Error::Overflow);
        }
        if Self::is_hex(variant) {
            for &v in bin {
                acc = (acc << 8) + v as u16;
                acc_len += 8;
                while acc_len >= 5 {
                    acc_len -= 5;
                    b32[b32_pos] = Self::b32_hex_byte_to_char(((acc >> acc_len) & 0x1f) as u8);
                    b32_pos += 1;
                }
            }
            if acc_len > 0 {
                b32[b32_pos] = Self::b32_hex_byte_to_char(((acc << (5 - acc_len)) & 0x1f) as u8);
                b32_pos += 1;
            }
        } else {
            for &v in bin {
                acc = (acc << 8) + v as u16;
                acc_len += 8;
                while acc_len >= 5 {
                    acc_len -= 5;
                    b32[b32_pos] = Self::b32_byte_to_char(((acc >> acc_len) & 0x1f) as u8);
                    b32_pos += 1;
                }
            }
            if acc_len > 0 {
                b32[b32_pos] = Self::b32_byte_to_char(((acc << (5 - acc_len)) & 0x1f) as u8);
                b32_pos += 1;
            }
        }
        while b32_pos < b32_len {
            b32[b32_pos] = b'=';
            b32_pos += 1
        }
        Ok(&b32[..b32_pos])
    }

    fn skip_padding<'t>(
        b32: &'t [u8],
        mut padding_len: usize,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        let b32_len = b32.len();
        let mut b32_pos = 0usize;
        while padding_len > 0 {
            if b32_pos >= b32_len {
                return Err(Error::InvalidInput);
            }
            let c = b32[b32_pos];
            if c == b'=' {
                padding_len -= 1
            } else {
                match ignore {
                    Some(ignore) if ignore.contains(&c) => {}
                    _ => return Err(Error::InvalidInput),
                }
            }
            b32_pos += 1
        }
        Ok(&b32[b32_pos..])
    }

    pub fn decode<'t>(
        bin: &'t mut [u8],
        b32: &[u8],
        ignore: Option<&[u8]>,
        variant: Base32Variant,
    ) -> Result<&'t [u8], Error> {
        let bin_maxlen = bin.len();
        let is_hex = Self::is_hex(variant);
        let is_no_padding = Self::is_no_padding(variant);
        let mut acc = 0u16;
        let mut acc_len = 0usize;
        let mut bin_pos = 0usize;
        let mut premature_end = None;
        for (b32_pos, &c) in b32.iter().enumerate() {
            let d = if is_hex {
                Self::b32_hex_char_to_byte(c)
            } else {
                Self::b32_char_to_byte(c)
            };
            if d == 0xff {
                match ignore {
                    Some(ignore) if ignore.contains(&c) => continue,
                    _ => {
                        premature_end = Some(b32_pos);
                        break;
                    }
                }
            }
            acc = (acc << 5) + d as u16;
            acc_len += 5;
            if acc_len >= 8 {
                acc_len -= 8;
                if bin_pos >= bin_maxlen {
                    return Err(Error::Overflow);
                }
                bin[bin_pos] = (acc >> acc_len) as u8;
                bin_pos += 1;
            }
        }
        if acc_len >= 5 || (acc & ((1u16 << acc_len).wrapping_sub(1))) != 0 {
            return Err(Error::InvalidInput);
        }
        let padding_len = [0, 3, 6, 1, 4][acc_len];
        if let Some(premature_end) = premature_end {
            let remaining = if !is_no_padding {
                Self::skip_padding(&b32[premature_end..], padding_len, ignore)?
            } else {
                &b32[premature_end..]
            };
            match ignore {
                None => {
                    if !remaining.is_empty() {
                        return Err(Error::InvalidInput);
                    }
                }
                Some(ignore) => {
                    for &c in remaining {
                        if !ignore.contains(&c) {
                            return Err(Error::InvalidInput);
                        }
                    }
                }
            }
        } else if !is_no_padding && padding_len != 0 {
            return Err(Error::InvalidInput);
        }
        Ok(&bin[..bin_pos])
    }
}

/// Standard Base32 encoder and decoder with padding.
///
/// This implementation follows the standard Base32 encoding as defined in RFC 4648,
/// and includes padding characters ('=') when needed.
///
/// # Standard Base32 Alphabet
///
/// The standard Base32 alphabet uses characters:
/// - 'A' to 'Z' (26 characters, values 0-25)
/// - '2' to '7' (6 characters, values 26-31)
/// - '=' (padding character)
///
/// # Examples
///
/// ```
/// use ct_codecs::{Base32, Encoder, Decoder};
///
/// fn example() -> Result<(), ct_codecs::Error> {
///     let data = b"foobar";
///     let encoded = Base32::encode_to_string(data)?;
///     assert_eq!(encoded, "MZXW6YTBOI======");
///
///     let decoded = Base32::decode_to_vec(&encoded, None)?;
///     assert_eq!(decoded, data);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
pub struct Base32;

/// Standard Base32 encoder and decoder without padding.
///
/// This implementation follows the standard Base32 encoding as defined in RFC 4648,
/// but omits padding characters ('=').
///
/// # Examples
///
/// ```
/// use ct_codecs::{Base32NoPadding, Encoder, Decoder};
///
/// fn example() -> Result<(), ct_codecs::Error> {
///     let data = b"foobar";
///     let encoded = Base32NoPadding::encode_to_string(data)?;
///     assert_eq!(encoded, "MZXW6YTBOI");
///
///     let decoded = Base32NoPadding::decode_to_vec(&encoded, None)?;
///     assert_eq!(decoded, data);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
pub struct Base32NoPadding;

/// Base32 Hex encoder and decoder with padding.
///
/// This implementation follows the Base32hex encoding variant as defined in RFC 4648.
/// It uses the extended hex alphabet (0-9, A-V) instead of the standard base32 alphabet.
/// Padding characters ('=') are included when needed.
///
/// # Base32hex Alphabet
///
/// The Base32hex alphabet uses characters:
/// - '0' to '9' (10 characters, values 0-9)
/// - 'A' to 'V' (22 characters, values 10-31)
/// - '=' (padding character)
///
/// # Examples
///
/// ```
/// use ct_codecs::{Base32Hex, Encoder, Decoder};
///
/// fn example() -> Result<(), ct_codecs::Error> {
///     let data = b"foobar";
///     let encoded = Base32Hex::encode_to_string(data)?;
///     assert_eq!(encoded, "CPNMUOJ1E8======");
///
///     let decoded = Base32Hex::decode_to_vec(&encoded, None)?;
///     assert_eq!(decoded, data);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
pub struct Base32Hex;

/// Base32 Hex encoder and decoder without padding.
///
/// This implementation follows the Base32hex encoding variant as defined in RFC 4648,
/// but omits padding characters ('='). This is particularly useful for identifiers
/// and other cases where the padding is unnecessary.
///
/// # Examples
///
/// ```
/// use ct_codecs::{Base32HexNoPadding, Encoder, Decoder};
///
/// fn example() -> Result<(), ct_codecs::Error> {
///     let data = b"foobar";
///     let encoded = Base32HexNoPadding::encode_to_string(data)?;
///     assert_eq!(encoded, "CPNMUOJ1E8");
///
///     let decoded = Base32HexNoPadding::decode_to_vec(&encoded, None)?;
///     assert_eq!(decoded, data);
///     Ok(())
/// }
/// # example().unwrap();
/// ```
pub struct Base32HexNoPadding;

impl Encoder for Base32 {
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        Base32Impl::encoded_len(bin_len, Base32Variant::Standard)
    }

    #[inline]
    fn encode<IN: AsRef<[u8]>>(b32: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        Base32Impl::encode(b32, bin.as_ref(), Base32Variant::Standard)
    }
}

impl Decoder for Base32 {
    #[inline]
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        b32: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        Base32Impl::decode(bin, b32.as_ref(), ignore, Base32Variant::Standard)
    }
}

impl Encoder for Base32NoPadding {
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        Base32Impl::encoded_len(bin_len, Base32Variant::StandardNoPadding)
    }

    #[inline]
    fn encode<IN: AsRef<[u8]>>(b32: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        Base32Impl::encode(b32, bin.as_ref(), Base32Variant::StandardNoPadding)
    }
}

impl Decoder for Base32NoPadding {
    #[inline]
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        b32: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        Base32Impl::decode(bin, b32.as_ref(), ignore, Base32Variant::StandardNoPadding)
    }
}

impl Encoder for Base32Hex {
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        Base32Impl::encoded_len(bin_len, Base32Variant::Hex)
    }

    #[inline]
    fn encode<IN: AsRef<[u8]>>(b32: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        Base32Impl::encode(b32, bin.as_ref(), Base32Variant::Hex)
    }
}

impl Decoder for Base32Hex {
    #[inline]
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        b32: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        Base32Impl::decode(bin, b32.as_ref(), ignore, Base32Variant::Hex)
    }
}

impl Encoder for Base32HexNoPadding {
    #[inline]
    fn encoded_len(bin_len: usize) -> Result<usize, Error> {
        Base32Impl::encoded_len(bin_len, Base32Variant::HexNoPadding)
    }

    #[inline]
    fn encode<IN: AsRef<[u8]>>(b32: &mut [u8], bin: IN) -> Result<&[u8], Error> {
        Base32Impl::encode(b32, bin.as_ref(), Base32Variant::HexNoPadding)
    }
}

impl Decoder for Base32HexNoPadding {
    #[inline]
    fn decode<'t, IN: AsRef<[u8]>>(
        bin: &'t mut [u8],
        b32: IN,
        ignore: Option<&[u8]>,
    ) -> Result<&'t [u8], Error> {
        Base32Impl::decode(bin, b32.as_ref(), ignore, Base32Variant::HexNoPadding)
    }
}

#[cfg(feature = "std")]
#[test]
fn test_base32() {
    let test_vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "MY======"),
        (b"fo", "MZXQ===="),
        (b"foo", "MZXW6==="),
        (b"foob", "MZXW6YQ="),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI======"),
    ];
    for &(bin, expected) in test_vectors {
        let b32 = Base32::encode_to_string(bin).unwrap();
        assert_eq!(b32, expected);
        let decoded = Base32::decode_to_vec(&b32, None).unwrap();
        assert_eq!(decoded, bin);
    }
}

#[cfg(feature = "std")]
#[test]
fn test_base32_no_padding() {
    let test_vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "MY"),
        (b"fo", "MZXQ"),
        (b"foo", "MZXW6"),
        (b"foob", "MZXW6YQ"),
        (b"fooba", "MZXW6YTB"),
        (b"foobar", "MZXW6YTBOI"),
    ];
    for &(bin, expected) in test_vectors {
        let b32 = Base32NoPadding::encode_to_string(bin).unwrap();
        assert_eq!(b32, expected);
        let decoded = Base32NoPadding::decode_to_vec(&b32, None).unwrap();
        assert_eq!(decoded, bin);
    }
}

#[cfg(feature = "std")]
#[test]
fn test_base32_hex() {
    let test_vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "CO======"),
        (b"fo", "CPNG===="),
        (b"foo", "CPNMU==="),
        (b"foob", "CPNMUOG="),
        (b"fooba", "CPNMUOJ1"),
        (b"foobar", "CPNMUOJ1E8======"),
    ];
    for &(bin, expected) in test_vectors {
        let b32 = Base32Hex::encode_to_string(bin).unwrap();
        assert_eq!(b32, expected);
        let decoded = Base32Hex::decode_to_vec(&b32, None).unwrap();
        assert_eq!(decoded, bin);
    }
}

#[cfg(feature = "std")]
#[test]
fn test_base32_hex_no_padding() {
    let test_vectors: &[(&[u8], &str)] = &[
        (b"", ""),
        (b"f", "CO"),
        (b"fo", "CPNG"),
        (b"foo", "CPNMU"),
        (b"foob", "CPNMUOG"),
        (b"fooba", "CPNMUOJ1"),
        (b"foobar", "CPNMUOJ1E8"),
    ];
    for &(bin, expected) in test_vectors {
        let b32 = Base32HexNoPadding::encode_to_string(bin).unwrap();
        assert_eq!(b32, expected);
        let decoded = Base32HexNoPadding::decode_to_vec(&b32, None).unwrap();
        assert_eq!(decoded, bin);
    }
}

#[test]
fn test_base32_no_std() {
    let bin = [1u8, 5, 11, 15, 19, 131, 122];
    let mut b32 = [0u8; 17];
    let b32 = Base32::encode(&mut b32, bin).unwrap();
    let expected = b"AECQWDYTQN5A====";
    assert_eq!(b32, expected);
    let mut bin2 = [0u8; 7];
    let bin2 = Base32::decode(&mut bin2, b32, None).unwrap();
    assert_eq!(bin, bin2);
}

#[test]
fn test_base32_encoded_len() {
    let test_vectors: &[(usize, usize, usize)] = &[
        (0, 0, 0),
        (1, 8, 2),
        (2, 8, 4),
        (3, 8, 5),
        (4, 8, 7),
        (5, 8, 8),
        (6, 16, 10),
    ];
    for &(bin_len, padded_len, unpadded_len) in test_vectors {
        assert_eq!(Base32::encoded_len(bin_len), Ok(padded_len));
        assert_eq!(Base32NoPadding::encoded_len(bin_len), Ok(unpadded_len));
        assert_eq!(Base32Hex::encoded_len(bin_len), Ok(padded_len));
        assert_eq!(Base32HexNoPadding::encoded_len(bin_len), Ok(unpadded_len));
    }
}

#[test]
fn test_base32_encoded_len_overflow() {
    let mult_overflow_bin_len = (usize::MAX / 8 + 1).checked_mul(5).unwrap();
    assert_eq!(
        Base32::encoded_len(mult_overflow_bin_len),
        Err(Error::Overflow)
    );
    assert_eq!(
        Base32NoPadding::encoded_len(mult_overflow_bin_len),
        Err(Error::Overflow)
    );
    assert_eq!(
        Base32Hex::encoded_len(mult_overflow_bin_len),
        Err(Error::Overflow)
    );
    assert_eq!(
        Base32HexNoPadding::encoded_len(mult_overflow_bin_len),
        Err(Error::Overflow)
    );

    let add_overflow_bin_len = (usize::MAX / 8).checked_mul(5).unwrap() + 1;
    assert_eq!(
        Base32::encoded_len(add_overflow_bin_len),
        Err(Error::Overflow)
    );
    assert_eq!(
        Base32Hex::encoded_len(add_overflow_bin_len),
        Err(Error::Overflow)
    );
}

#[cfg(feature = "std")]
#[test]
fn test_base32_missing_padding() {
    let missing_padding = "MY";
    assert!(Base32::decode_to_vec(missing_padding, None).is_err());
    assert!(Base32NoPadding::decode_to_vec(missing_padding, None).is_ok());
    let missing_padding = "MZXQ";
    assert!(Base32::decode_to_vec(missing_padding, None).is_err());
    assert!(Base32NoPadding::decode_to_vec(missing_padding, None).is_ok());
}

#[cfg(feature = "std")]
#[test]
fn test_base32_invalid_padding() {
    let valid_padding = "MY======";
    assert_eq!(Base32::decode_to_vec(valid_padding, None), Ok(vec![b'f']));
    let invalid_padding = "MY=====";
    assert_eq!(
        Base32::decode_to_vec(invalid_padding, None),
        Err(Error::InvalidInput)
    );
    let invalid_padding = "MY=";
    assert_eq!(
        Base32::decode_to_vec(invalid_padding, None),
        Err(Error::InvalidInput)
    );
}

#[cfg(feature = "std")]
#[test]
fn test_base32_non_canonical() {
    assert!(Base32::decode_to_vec("MZ======", None).is_err());
    assert!(Base32NoPadding::decode_to_vec("MZ", None).is_err());
}

#[cfg(feature = "std")]
#[test]
fn test_base32_no_padding_rejects_padding() {
    assert!(Base32NoPadding::decode_to_vec("MY======", None).is_err());
    assert!(Base32NoPadding::decode_to_vec("MZXQ====", None).is_err());
}

#[cfg(feature = "std")]
#[test]
fn test_base32_hex_rejects_lowercase() {
    assert!(Base32Hex::decode_to_vec("cpnmuoj1e8======", None).is_err());
    assert!(Base32HexNoPadding::decode_to_vec("cpnmuoj1e8", None).is_err());
}
