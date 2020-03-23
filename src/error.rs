#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// The provided output buffer would be too small.
    Overflow,
    /// The input isn't valid for the given encoding.
    InvalidInput,
}
