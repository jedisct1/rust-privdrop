use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use libc;
use nix::unistd;

use super::errors::*;

#[test]
fn test_privdrop() {
    use std;
    use std::io::Write;

    if unistd::geteuid().is_root() {
        PrivDrop::default()
            .chroot("/var/empty")
            .user("nobody")
            .apply()
            .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));
    } else {
        writeln!(
            std::io::stderr(),
            "Test was skipped because it needs to be run as root."
        ).unwrap();
    }
}

/// `PrivDrop` structure
///
/// # Example
/// ```ignore
/// privdrop::PrivDrop::default()
///     .chroot("/var/empty")
///     .user("nobody")
///     .apply()
///     .unwrap_or_else(|e| { panic!("Failed to drop privileges: {}", e) });
/// ```
#[derive(Default, Clone, Debug)]
pub struct PrivDrop {
    chroot: Option<PathBuf>,
    user: Option<OsString>,
    group: Option<OsString>,
}

#[derive(Default, Clone, Debug)]
struct UidGid {
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
}

impl PrivDrop {
    /// chroot() to a specific directory before switching to a non-root user
    pub fn chroot<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.chroot = Some(path.as_ref().to_owned());
        self
    }

    /// Set the name of a user to switch to
    pub fn user<S: AsRef<OsStr>>(mut self, user: S) -> Self {
        self.user = Some(user.as_ref().to_owned());
        self
    }

    /// Set a group name to switch to, if different from the primary group of the user
    pub fn group<S: AsRef<OsStr>>(mut self, group: S) -> Self {
        self.group = Some(group.as_ref().to_owned());
        self
    }

    /// Apply the changes
    pub fn apply(self) -> Result<(), PrivDropError> {
        Self::preload()?;
        let ids = self.lookup_ids()?;
        self.do_chroot()?.do_idchange(ids)?;
        Ok(())
    }

    fn preload() -> Result<(), PrivDropError> {
        let c_locale = CString::new("C").unwrap();
        unsafe {
            libc::strerror(1);
            libc::setlocale(libc::LC_CTYPE, c_locale.as_ptr());
            libc::setlocale(libc::LC_COLLATE, c_locale.as_ptr());
            let mut now: libc::time_t = 0;
            libc::time(&mut now);
            libc::localtime(&now);
        }
        Ok(())
    }

    fn uidcheck() -> Result<(), PrivDropError> {
        if !unistd::geteuid().is_root() {
            Err(PrivDropError::from((
                ErrorKind::SysError,
                "Starting this application requires root privileges",
            )))
        } else {
            Ok(())
        }
    }

    fn do_chroot(mut self) -> Result<Self, PrivDropError> {
        if let Some(chroot) = self.chroot.take() {
            Self::uidcheck()?;
            unistd::chdir(&chroot)?;
            unistd::chroot(&chroot)?;
            unistd::chdir("/")?
        }
        Ok(self)
    }

    fn lookup_user(user: &OsStr) -> Result<(libc::uid_t, libc::gid_t), PrivDropError> {
        let pwent = unsafe {
            libc::getpwnam(
                CString::new(user.as_bytes())
                    .map_err(|_| {
                        PrivDropError::from((
                            ErrorKind::SysError,
                            "Unable to access the system user database",
                        ))
                    })?.as_ptr(),
            )
        };
        if pwent.is_null() {
            return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
        }
        Ok(unsafe { ((*pwent).pw_uid, (*pwent).pw_gid) })
    }

    fn lookup_group(group: &OsStr) -> Result<libc::gid_t, PrivDropError> {
        let grent = unsafe {
            libc::getgrnam(
                CString::new(group.as_bytes())
                    .map_err(|_| {
                        PrivDropError::from((
                            ErrorKind::SysError,
                            "Unable to access the system group database",
                        ))
                    })?.as_ptr(),
            )
        };
        if grent.is_null() {
            return Err(PrivDropError::from((
                ErrorKind::SysError,
                "Group not found",
            )));
        }
        Ok(unsafe { *grent }.gr_gid)
    }

    fn lookup_ids(&self) -> Result<UidGid, PrivDropError> {
        let mut ids = UidGid::default();

        if let Some(ref user) = self.user {
            let pair = PrivDrop::lookup_user(user)?;
            ids.uid = Some(pair.0);
            ids.gid = Some(pair.1);
        }

        if let Some(ref group) = self.group {
            ids.gid = Some(PrivDrop::lookup_group(group)?);
        }

        Ok(ids)
    }

    fn do_idchange(&self, ids: UidGid) -> Result<(), PrivDropError> {
        Self::uidcheck()?;

        if let Some(gid) = ids.gid {
            if unsafe { libc::setgroups(1, &gid) } != 0 {
                return Err(PrivDropError::from((
                    ErrorKind::SysError,
                    "Unable to revoke supplementary groups",
                )));
            }
            unistd::setgid(unistd::Gid::from_raw(gid))?;
        }
        if let Some(uid) = ids.uid {
            unistd::setuid(unistd::Uid::from_raw(uid))?
        }
        Ok(())
    }
}
