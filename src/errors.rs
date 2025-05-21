use std::error::Error;
use std::fmt;

/// Types of errors that can occur during privilege dropping operations.
///
/// This enum categorizes the different kinds of errors that might occur when
/// attempting to drop privileges. It helps consumers of this crate to identify
/// the general category of failure.
///
/// The `#[non_exhaustive]` attribute indicates that more error kinds might be
/// added in future versions of the crate without breaking backward compatibility.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// System-level error when interacting with OS privileges.
    ///
    /// This represents errors that occur at the operating system level,
    /// such as failures to:
    /// - Look up user or group information
    /// - Perform chroot operations
    /// - Set user or group IDs
    /// - Access required system resources
    SysError,
}

/// Internal representation of privilege dropping errors.
///
/// This enum is used internally to represent different sources of errors
/// that may occur during privilege dropping operations. It encapsulates both
/// errors from the underlying nix crate and custom errors with static descriptions.
#[derive(Debug)]
enum ErrorRepr {
    /// Error originating from the nix crate's operations.
    ///
    /// These errors typically occur when calling nix functions like
    /// `setuid`, `setgid`, `chroot`, etc.
    FromNix(nix::Error),

    /// Error with a static description and an associated error kind.
    ///
    /// This variant is used for custom errors with a descriptive message
    /// and categorization via `ErrorKind`.
    WithDescription(ErrorKind, &'static str),
}

/// Error type for privilege dropping operations.
///
/// `PrivDropError` is the main error type returned by this crate when privilege
/// dropping operations fail. It implements the standard `Error` trait and provides
/// detailed information about what went wrong during the privilege dropping process.
///
/// This struct encapsulates the internal error representation and provides a
/// consistent interface for error handling regardless of the error source.
///
/// ## Usage
///
/// ```no_run
/// use privdrop::PrivDrop;
///
/// match PrivDrop::default().user("nonexistent-user").apply() {
///     Ok(()) => println!("Successfully dropped privileges"),
///     Err(e) => eprintln!("Failed to drop privileges: {}", e),
/// }
/// ```
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
