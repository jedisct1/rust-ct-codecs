use core::fmt::{self, Display};

/// Error type for ct-codecs operations.
///
/// This enum represents the possible error conditions that can occur
/// during encoding and decoding operations.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The provided output buffer would be too small to hold the result.
    ///
    /// This error occurs when:
    /// - The output buffer passed to an encode/decode function is too small
    /// - A calculation would result in an integer overflow
    Overflow,

    /// The input isn't valid for the given encoding.
    ///
    /// This error occurs when:
    /// - A Base64 string contains invalid characters
    /// - A Base64 string has invalid padding
    /// - A hex string contains non-hexadecimal characters
    /// - A hex string has an odd length
    InvalidInput,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Overflow => write!(f, "Output buffer too small or calculation overflow"),
            Error::InvalidInput => write!(f, "Invalid input for the given encoding"),
        }
    }
}