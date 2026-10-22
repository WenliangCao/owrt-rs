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
    /// Extensions returned only after Context::set_io_budget opts in.
    TimedOut = 8,
    Cancelled = 9,
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
            Error::TimedOut => "Operation timed out",
            Error::Cancelled => "Operation cancelled",
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.strerror())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Map a std::io::Error onto the libuci code the C paths would have thrown.
pub fn io(_e: &std::io::Error) -> Error {
    Error::Io
}
