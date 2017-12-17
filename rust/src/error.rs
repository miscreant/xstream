//! `error.rs`: XSTREAM error type

/// How to display the error type in messages
const DISPLAY_STRING: &str = "xstream::error::Error";

/// An opaque error type, used for all XSTREAM errors
#[derive(Debug, Eq, PartialEq)]
pub struct Error;

impl ::std::fmt::Display for Error {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "{}", DISPLAY_STRING)
    }
}

impl ::std::error::Error for Error {
    #[inline]
    fn description(&self) -> &str {
        DISPLAY_STRING
    }
}
