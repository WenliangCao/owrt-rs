//! libuci error codes (uci.h) and their strings (libuci.c uci_errstr).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Error {
    Mem = 1,
    Inval = 2,
    NotFound = 3,
    Io = 4,
    Parse = 5,
    Duplicate = 6,
    Unknown = 7,
}

impl Error {
    pub fn strerror(self) -> &'static str {
        match self {
            Error::Mem => "Out of memory",
            Error::Inval => "Invalid argument",
            Error::NotFound => "Entry not found",
            Error::Io => "I/O error",
            Error::Parse => "Parse error",
            Error::Duplicate => "Duplicate entry",
            Error::Unknown => "Unknown error",
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Map a std::io::Error onto the libuci code the C paths would have thrown.
pub fn io(_e: &std::io::Error) -> Error {
    Error::Io
}
