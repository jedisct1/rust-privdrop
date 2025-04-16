use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::unistd;

use super::errors::*;

const INITIAL_BUFFER_SIZE: usize = 4096;
const MAX_GROUPS: usize = 256;

#[test]
fn test_privdrop() {
    if unistd::geteuid().is_root() {
        PrivDrop::default()
            .chroot("/var/empty")
            .user("nobody")
            .apply()
            .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));
    } else {
        eprintln!("Test was skipped because it needs to be run as root.");
    }
}

/// `PrivDrop` structure for securely dropping privileges in Unix systems.
///
/// This structure provides a builder pattern interface for configuring and
/// executing privilege dropping operations. It allows:
/// - Changing the root directory (chroot)
/// - Switching to a non-root user
/// - Setting group memberships
/// - Managing supplementary groups
///
/// # Example
/// ```ignore
/// privdrop::PrivDrop::default()
///     .chroot("/var/empty")
///     .user("nobody")
///     .apply()
///     .unwrap_or_else(|e| { panic!("Failed to drop privileges: {}", e) });
/// ```
///
/// # Safety
/// This structure handles privileged operations and should be used with care.
/// All operations are performed atomically during the `apply()` call.
#[derive(Default, Clone, Debug)]
pub struct PrivDrop {
    chroot: Option<PathBuf>,
    user: Option<OsString>,
    group: Option<OsString>,
    group_list: Option<Vec<OsString>>,
    include_default_supplementary_groups: bool,
    fallback_to_ids_if_names_are_numeric: bool,
}

#[derive(Default, Clone, Debug)]
struct UserIds {
    uid: Option<libc::uid_t>,
    gid: Option<libc::gid_t>,
    group_list: Option<Vec<libc::gid_t>>,
}

impl PrivDrop {
    /// Sets the directory to chroot into before switching to a non-root user.
    ///
    /// # Arguments
    /// * `path` - The path to use as the new root directory
    pub fn chroot<T: AsRef<Path>>(mut self, path: T) -> Self {
        self.chroot = Some(path.as_ref().to_owned());
        self
    }

    /// Sets the name of the user to switch to.
    ///
    /// # Arguments
    /// * `user` - The username to switch to
    pub fn user<S: AsRef<OsStr>>(mut self, user: S) -> Self {
        self.user = Some(user.as_ref().to_owned());
        self
    }

    /// Sets a group name to switch to, if different from the user's primary group.
    ///
    /// # Arguments
    /// * `group` - The group name to switch to
    pub fn group<S: AsRef<OsStr>>(mut self, group: S) -> Self {
        self.group = Some(group.as_ref().to_owned());
        self
    }

    /// Includes the user's default supplementary groups in addition to specified groups.
    pub fn include_default_supplementary_groups(mut self) -> Self {
        self.include_default_supplementary_groups = true;
        self
    }

    /// Enables fallback to numeric IDs if names cannot be resolved.
    ///
    /// When enabled, if a username or group name lookup fails, the system will
    /// attempt to interpret the name as a numeric ID.
    pub fn fallback_to_ids_if_names_are_numeric(mut self) -> Self {
        self.fallback_to_ids_if_names_are_numeric = true;
        self
    }

    /// Sets the complete list of groups to switch to.
    ///
    /// # Arguments
    /// * `group_list` - List of group names to switch to
    pub fn group_list<S: AsRef<OsStr>>(mut self, group_list: &[S]) -> Self {
        self.group_list = Some(group_list.iter().map(|x| x.as_ref().to_owned()).collect());
        self
    }

    /// Applies the configured privilege changes.
    ///
    /// This method must be called with root privileges. It will:
    /// 1. Preload necessary system resources
    /// 2. Look up all required user and group IDs
    /// 3. Perform chroot if configured
    /// 4. Change to the specified user and group IDs
    ///
    /// # Errors
    /// Returns `PrivDropError` if any operation fails
    pub fn apply(self) -> Result<(), PrivDropError> {
        Self::preload()?;
        let ids = self.lookup_ids()?;
        self.do_chroot()?.do_idchange(ids)?;
        Ok(())
    }

    fn preload() -> Result<(), PrivDropError> {
        // Preload system resources to prevent deadlocks after privilege drop
        let c_locale = CString::new("C").map_err(|_| {
            PrivDropError::from((ErrorKind::SysError, "Failed to create C locale string"))
        })?;

        unsafe {
            // Preload error strings
            libc::strerror(1);
            // Preload locale data
            libc::setlocale(libc::LC_CTYPE, c_locale.as_ptr());
            libc::setlocale(libc::LC_COLLATE, c_locale.as_ptr());
            // Preload time zone data
            let mut now: libc::time_t = 0;
            libc::time(&mut now);
            libc::localtime(&now);
        }
        Ok(())
    }

    fn uidcheck() -> Result<(), PrivDropError> {
        if !unistd::geteuid().is_root() {
            return Err(PrivDropError::from((
                ErrorKind::SysError,
                "Starting this application requires root privileges",
            )));
        }
        Ok(())
    }

    fn do_chroot(mut self) -> Result<Self, PrivDropError> {
        if let Some(chroot) = self.chroot.take() {
            Self::uidcheck()?;
            // Change to the new root directory before calling chroot
            unistd::chdir(&chroot).map_err(|_e| {
                PrivDropError::from((ErrorKind::SysError, "Failed to change to chroot directory"))
            })?;

            // Perform the chroot operation
            unistd::chroot(&chroot).map_err(|_e| {
                PrivDropError::from((ErrorKind::SysError, "Failed to change root directory"))
            })?;

            // Change to root directory inside the chroot
            unistd::chdir("/").map_err(|_e| {
                PrivDropError::from((
                    ErrorKind::SysError,
                    "Failed to change to root directory after chroot",
                ))
            })?;
        }
        Ok(self)
    }

    fn lookup_user(
        user: &OsStr,
        fallback_to_ids_if_names_are_numeric: bool,
    ) -> Result<UserIds, PrivDropError> {
        let username = CString::new(user.as_bytes())
            .map_err(|_| PrivDropError::from((ErrorKind::SysError, "Invalid username")))?;

        let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut pwbuf = vec![0; INITIAL_BUFFER_SIZE];
        let mut pwent = std::ptr::null_mut::<libc::passwd>();

        let ret = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                &mut pwd,
                pwbuf.as_mut_ptr(),
                pwbuf.len(),
                &mut pwent,
            )
        };

        if ret != 0 || pwent.is_null() {
            if !fallback_to_ids_if_names_are_numeric {
                return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
            }

            // Try to parse the username as a numeric UID
            let user_str = user.to_str().ok_or_else(|| {
                PrivDropError::from((
                    ErrorKind::SysError,
                    "User not found and username is not valid UTF-8",
                ))
            })?;

            let uid = user_str.parse().map_err(|_| {
                PrivDropError::from((
                    ErrorKind::SysError,
                    "User not found and username is not a valid numeric ID",
                ))
            })?;

            return Ok(UserIds {
                uid: Some(uid),
                gid: None,
                group_list: None,
            });
        }

        let uid = unsafe { *pwent }.pw_uid;
        let gid = unsafe { *pwent }.pw_gid;

        Ok(UserIds {
            uid: Some(uid),
            gid: Some(gid),
            group_list: None,
        })
    }

    fn default_group_list(
        user: &OsStr,
        gid: libc::gid_t,
    ) -> Result<Option<Vec<libc::gid_t>>, PrivDropError> {
        let username = CString::new(user.as_bytes())
            .map_err(|_| PrivDropError::from((ErrorKind::SysError, "Invalid username")))?;

        let mut groups = vec![0; MAX_GROUPS];
        let mut ngroups = groups.len() as _;

        let ret = unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                gid as _,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };

        if ret == -1 {
            return Ok(None);
        }

        groups.truncate(ngroups as _);
        Ok(Some(groups.into_iter().map(|g| g as libc::gid_t).collect()))
    }

    fn lookup_group(
        group: &OsStr,
        fallback_to_ids_if_names_are_numeric: bool,
    ) -> Result<libc::gid_t, PrivDropError> {
        let groupname = CString::new(group.as_bytes())
            .map_err(|_| PrivDropError::from((ErrorKind::SysError, "Invalid group name")))?;

        let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
        let mut grbuf = vec![0; 4096];
        let mut grent = std::ptr::null_mut::<libc::group>();
        let ret = unsafe {
            libc::getgrnam_r(
                groupname.as_ptr(),
                &mut grp,
                grbuf.as_mut_ptr(),
                grbuf.len(),
                &mut grent,
            )
        };

        if ret != 0 || grent.is_null() {
            if !fallback_to_ids_if_names_are_numeric {
                return Err(PrivDropError::from((
                    ErrorKind::SysError,
                    "Group not found",
                )));
            }
            let group_str = group.to_str().ok_or_else(|| {
                PrivDropError::from((
                    ErrorKind::SysError,
                    "Group not found and group is not a valid number",
                ))
            })?;
            let gid: libc::gid_t = group_str.parse().map_err(|_| {
                PrivDropError::from((
                    ErrorKind::SysError,
                    "Group not found and group is not a valid number",
                ))
            })?;
            return Ok(gid);
        }

        Ok(unsafe { *grent }.gr_gid)
    }

    fn lookup_ids(&self) -> Result<UserIds, PrivDropError> {
        let mut ids = UserIds::default();

        if let Some(ref user) = self.user {
            ids = PrivDrop::lookup_user(user, self.fallback_to_ids_if_names_are_numeric)?;
        }

        if let Some(ref group) = self.group {
            ids.gid = Some(PrivDrop::lookup_group(
                group,
                self.fallback_to_ids_if_names_are_numeric,
            )?);
        }

        if let Some(ref group_list) = self.group_list {
            let mut groups = Vec::with_capacity(group_list.len());
            for group in group_list {
                groups.push(PrivDrop::lookup_group(
                    group,
                    self.fallback_to_ids_if_names_are_numeric,
                )?);
            }
            ids.group_list = Some(groups);
        }

        Ok(ids)
    }

    fn do_idchange(&self, ids: UserIds) -> Result<(), PrivDropError> {
        Self::uidcheck()?;

        let mut groups = vec![];
        if self.include_default_supplementary_groups {
            if let (Some(user), Some(gid)) = (&self.user, ids.gid) {
                if let Some(group_list) = Self::default_group_list(user, gid)? {
                    groups.extend(group_list);
                }
            } else {
                return Err(PrivDropError::from((
                    ErrorKind::SysError,
                    "Unable to determine default supplementary groups without a user name and a base gid",
                )));
            }
        }
        if let Some(ref group_list) = ids.group_list {
            groups.extend(group_list.iter().cloned());
        }
        if let Some(gid) = ids.gid {
            groups.push(gid);
            let mut unique_groups = vec![];
            for group in groups {
                if !unique_groups.contains(&group) {
                    unique_groups.push(group);
                }
            }
            if unsafe { libc::setgroups(unique_groups.len() as _, unique_groups.as_ptr()) } != 0 {
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
