
use errors::*;
use libc;
use nix::unistd;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct PrivDrop {
    chroot_dir: Option<PathBuf>,
    user: Option<String>,
    group: Option<String>,
}

impl PrivDrop {
    pub fn new() -> Self {
        PrivDrop::default()
    }

    pub fn chroot_dir<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.chroot_dir = Some(path.as_ref().to_owned());
        self
    }

    pub fn user<T: AsRef<str>>(mut self, user: T) -> Self {
        self.user = Some(user.as_ref().to_owned());
        self
    }

    fn do_preload(&self) -> Result<(), PrivDropError> {
        unsafe {
            libc::strerror(1);
            libc::setlocale(libc::LC_CTYPE, "C".as_ptr() as *const i8);
            libc::setlocale(libc::LC_COLLATE, "C".as_ptr() as *const i8);
            let mut now: libc::time_t = 0;
            libc::time(&mut now);
            libc::localtime(&now);
        }
        Ok(())
    }

    fn do_chroot(&self) -> Result<(), PrivDropError> {
        if let Some(ref chroot_dir) = self.chroot_dir {
            try!(unistd::chdir(chroot_dir));
            try!(unistd::chroot(chroot_dir));
            try!(unistd::chdir("/"))
        }
        Ok(())
    }

    fn do_userchange(&self) -> Result<(), PrivDropError> {
        if let Some(ref user) = self.user {
            let pwent = unsafe { libc::getpwnam(user.as_ptr() as *const i8) };
            if pwent.is_null() {
                return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
            }
            let (uid, gid) = (unsafe { *pwent }.pw_uid, unsafe { *pwent }.pw_gid);
            let gid = if let Some(ref group) = self.group {
                let grent = unsafe { libc::getgrnam(group.as_ptr() as *const i8) };
                if grent.is_null() {
                    return Err(PrivDropError::from((ErrorKind::SysError, "Group not found")));
                }
                unsafe { *grent }.gr_gid
            } else {
                gid
            };
            try!(unistd::setgid(gid));
            try!(unistd::setuid(uid));
        }
        Ok(())
    }

    pub fn apply(self) -> Result<(), PrivDropError> {
        try!(self.do_preload());
        try!(self.do_chroot());
        try!(self.do_userchange());
        Ok(())
    }
}
