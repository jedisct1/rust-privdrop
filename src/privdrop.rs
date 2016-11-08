use errors::*;
use libc;
use nix::unistd;
use std::ffi::CString;
use std::path::{Path, PathBuf};

/// PrivDrop structure
///
/// # Example
/// ```
/// PrivDrop::default().chroot("/var/empty").user("_appuser").apply().unwrap();
/// ```
#[derive(Default, Clone, Debug)]
pub struct PrivDrop {
    chroot: Option<PathBuf>,
    user: Option<String>,
    group: Option<String>,
}

impl PrivDrop {
    /// chroot() to a specific directory before switching to a non-root user
    pub fn chroot<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.chroot = Some(path.as_ref().to_owned());
        self
    }

    /// Set the name of a user to switch to
    pub fn user<T: AsRef<str>>(mut self, user: T) -> Self {
        self.user = Some(user.as_ref().to_owned());
        self
    }

    /// Set a group name to switch to, if different from the primary group of the user
    pub fn group<T: AsRef<str>>(mut self, group: T) -> Self {
        self.group = Some(group.as_ref().to_owned());
        self
    }

    /// Apply the changes
    pub fn apply(self) -> Result<(), PrivDropError> {
        try!(try!(try!(self.do_preload()).do_chroot()).do_idchange());
        Ok(())
    }

    fn do_preload(self) -> Result<Self, PrivDropError> {
        unsafe {
            libc::strerror(1);
            libc::setlocale(libc::LC_CTYPE, CString::new("C").unwrap().as_ptr());
            libc::setlocale(libc::LC_COLLATE, CString::new("C").unwrap().as_ptr());
            let mut now: libc::time_t = 0;
            libc::time(&mut now);
            libc::localtime(&now);
        }
        Ok(self)
    }

    fn do_chroot(mut self) -> Result<Self, PrivDropError> {
        if let Some(chroot) = self.chroot.take() {
            try!(unistd::chdir(&chroot));
            try!(unistd::chroot(&chroot));
            try!(unistd::chdir("/"))
        }
        Ok(self)
    }

    fn do_idchange(mut self) -> Result<Self, PrivDropError> {
        let user = match self.user.take() {
            None => return Ok(self),
            Some(user) => user,
        };
        let pwent = unsafe {
            libc::getpwnam(try!(CString::new(user).map_err(|_| {
                    PrivDropError::from((ErrorKind::SysError,
                                         "Unable to access the system user database"))
                }))
                .as_ptr())
        };
        if pwent.is_null() {
            return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
        }
        let (uid, gid) = (unsafe { *pwent }.pw_uid, unsafe { *pwent }.pw_gid);
        let gid = match self.group.take() {
            None => gid,
            Some(group) => {
                let grent = unsafe {
                    libc::getgrnam(try!(CString::new(group).map_err(|_| {
                            PrivDropError::from((ErrorKind::SysError,
                                                 "Unable to access the system group database"))
                        }))
                        .as_ptr())
                };
                if grent.is_null() {
                    return Err(PrivDropError::from((ErrorKind::SysError, "Group not found")));
                }
                unsafe { *grent }.gr_gid
            }
        };
        if unsafe { libc::setgroups(1, &gid) } != 0 {
            return Err(PrivDropError::from((ErrorKind::SysError,
                                            "Unable to revoke supplementary groups")));
        }
        try!(unistd::setgid(gid));
        try!(unistd::setuid(uid));
        Ok(self)
    }
}
