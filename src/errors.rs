use std::error::Error;
use std::fmt;

/// Types of errors that can occur during privilege dropping operations
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// System-level error when interacting with OS privileges
    SysError,
}

/// Internal representation of privilege dropping errors
#[derive(Debug)]
enum ErrorRepr {
    /// Error from the nix crate
    FromNix(nix::Error),
    /// Error with a static description
    WithDescription(ErrorKind, &'static str),
}

/// Error type for privilege dropping operations
#[derive(Debug)]
pub struct PrivDropError {
    repr: ErrorRepr,
}

impl Error for PrivDropError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self.repr {
            ErrorRepr::FromNix(ref e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for PrivDropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self.repr {
            ErrorRepr::FromNix(ref e) => write!(f, "Privilege drop error: {}", e),
            ErrorRepr::WithDescription(_, description) => {
                write!(f, "Privilege drop error: {}", description)
            }
        }
    }
}

impl From<nix::Error> for PrivDropError {
    fn from(e: nix::Error) -> PrivDropError {
        PrivDropError {
            repr: ErrorRepr::FromNix(e),
        }
    }
}

impl From<(ErrorKind, &'static str)> for PrivDropError {
    fn from((kind, description): (ErrorKind, &'static str)) -> PrivDropError {
        PrivDropError {
            repr: ErrorRepr::WithDescription(kind, description),
        }
    }
}
