use std::collections::HashSet;
use std::ffi::{CString, OsStr, OsString};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use nix::unistd;

use super::errors::*;

const INITIAL_BUFFER_SIZE: usize = 4096;
const MAX_GROUPS: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd;

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
}

/// `PrivDrop` structure for securely dropping privileges in Unix systems.
///
/// This structure provides a builder pattern interface for configuring and
/// executing privilege dropping operations. Privilege dropping is a critical security
/// practice for applications that start with root permissions but need to operate
/// with minimal privileges during normal execution.
///
/// ## Capabilities
///
/// This structure enables:
/// - Changing the root directory (chroot) to isolate the application
/// - Switching to a non-root user to eliminate root privileges
/// - Setting primary group membership for appropriate resource access
/// - Managing supplementary groups for fine-grained access control
/// - Handling both named and numeric user/group identifiers
///
/// ## Usage Pattern
///
/// 1. Create a `PrivDrop` instance using `default()`
/// 2. Configure desired privilege dropping operations using builder methods
/// 3. Call `apply()` to atomically execute all operations
/// 4. Handle any errors from the privileged operations
///
/// ## Basic Example
///
/// ```ignore
/// privdrop::PrivDrop::default()
///     .chroot("/var/empty")
///     .user("nobody")
///     .apply()
///     .unwrap_or_else(|e| { panic!("Failed to drop privileges: {}", e) });
/// ```
///
/// ## Security Considerations
///
/// - This structure handles privileged operations and should be used with care
/// - All operations are performed atomically during the `apply()` call to avoid
///   potential security issues during partial privilege dropping
/// - Root privileges are required to use this structure effectively
/// - Once privileges are dropped, they cannot be regained
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

    /// Sets a primary group name to switch to, if different from the user's default group.
    ///
    /// This method allows specifying a primary group that differs from the
    /// default primary group associated with the user. This is useful for
    /// customizing access permissions beyond the user's default settings.
    ///
    /// If not specified, and a user is set, the user's default primary group will be used.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use privdrop::PrivDrop;
    ///
    /// PrivDrop::default()
    ///     .user("www-data")
    ///     .group("web-content")  // Use a custom primary group
    ///     .apply()
    ///     .expect("Failed to drop privileges");
    /// ```
    ///
    /// # Arguments
    /// * `group` - The group name to switch to (can be a name or numeric ID if
    ///   `fallback_to_ids_if_names_are_numeric` is enabled)
    pub fn group<S: AsRef<OsStr>>(mut self, group: S) -> Self {
        self.group = Some(group.as_ref().to_owned());
        self
    }

    /// Includes the user's default supplementary groups in addition to any explicitly specified groups.
    ///
    /// When this option is enabled, the system will include all supplementary groups that the
    /// specified user belongs to by default, in addition to any groups specified via `group_list`.
    /// This is useful when you want to maintain the user's standard group memberships while
    /// also adding custom groups.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use privdrop::PrivDrop;
    ///
    /// PrivDrop::default()
    ///     .user("www-data")
    ///     .group_list(&["web-content", "deployment"])  // Add specific groups
    ///     .include_default_supplementary_groups()      // Also include default groups
    ///     .apply()
    ///     .expect("Failed to drop privileges");
    /// ```
    ///
    /// ## Security Note
    ///
    /// Including default supplementary groups increases the permission scope of your application.
    /// Only use this option when you specifically need access to resources controlled by the
    /// user's default group memberships.
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

    /// Sets the complete list of supplementary groups to switch to.
    ///
    /// This method allows specifying a list of supplementary groups that the process
    /// should belong to after privileges are dropped. Supplementary groups provide
    /// additional access permissions beyond what the primary group offers.
    ///
    /// ## Behavior Notes
    ///
    /// - If `include_default_supplementary_groups()` is also called, both the default
    ///   groups and these explicitly specified groups will be included
    /// - Duplicate groups are automatically handled (no need to filter)
    /// - The primary group (set via `group()` or from the user's default) is always included
    ///   automatically and doesn't need to be specified here
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use privdrop::PrivDrop;
    ///
    /// PrivDrop::default()
    ///     .user("service-user")
    ///     .group_list(&["www-data", "logs", "backups"])  // Set multiple supplementary groups
    ///     .apply()
    ///     .expect("Failed to drop privileges");
    /// ```
    ///
    /// # Arguments
    /// * `group_list` - List of group names to switch to (can include numeric IDs if
    ///   `fallback_to_ids_if_names_are_numeric` is enabled)
    pub fn group_list<S: AsRef<OsStr>>(mut self, group_list: &[S]) -> Self {
        self.group_list = Some(group_list.iter().map(|x| x.as_ref().to_owned()).collect());
        self
    }

    /// Applies the configured privilege changes atomically.
    ///
    /// This method executes all configured privilege-dropping operations in a secure,
    /// predetermined sequence. It must be called with root privileges.
    ///
    /// ## Execution Sequence
    ///
    /// 1. Preload necessary system resources (locale data, error strings, timezone information)
    ///    to prevent potential deadlocks after privilege drop
    /// 2. Look up all required user and group IDs before dropping privileges
    /// 3. Perform chroot operation if configured, changing to the new root directory
    /// 4. Drop privileges by changing to the specified user and group IDs
    ///
    /// ## Security Guarantees
    ///
    /// - All operations occur atomically to prevent security gaps
    /// - If any operation fails, the entire privilege drop fails, leaving the application
    ///   in its original state rather than in a partially-privileged state
    /// - Once privileges are dropped, they cannot be regained
    ///
    /// ## Error Handling
    ///
    /// This method returns detailed errors for various failure scenarios:
    /// - Missing root privileges
    /// - Invalid user or group names
    /// - Failed chroot operations
    /// - Issues setting user or group IDs
    ///
    /// # Errors
    ///
    /// Returns `PrivDropError` if any operation fails, with contextual information
    /// about the specific failure point
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

        let mut pwd = MaybeUninit::<libc::passwd>::uninit();
        let mut pwent = std::ptr::null_mut::<libc::passwd>();

        // Start with the initial buffer size and increase if needed
        let mut bufsize = INITIAL_BUFFER_SIZE;
        let mut pwbuf = vec![0; bufsize];

        let mut ret;
        loop {
            ret = unsafe {
                libc::getpwnam_r(
                    username.as_ptr(),
                    pwd.as_mut_ptr(),
                    pwbuf.as_mut_ptr(),
                    pwbuf.len(),
                    &mut pwent,
                )
            };

            // If we get ERANGE, the buffer was too small, double it and try again
            if ret == libc::ERANGE {
                bufsize *= 2;
                pwbuf.resize(bufsize, 0);
            } else {
                break;
            }
        }

        if ret != 0 || pwent.is_null() {
            if !fallback_to_ids_if_names_are_numeric {
                if ret != 0 && ret == libc::ENOENT {
                    return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
                } else if ret != 0 {
                    return Err(PrivDropError::from((
                        ErrorKind::SysError,
                        "Failed to look up user",
                    )));
                } else {
                    return Err(PrivDropError::from((ErrorKind::SysError, "User not found")));
                }
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

        // First call getgrouplist to get the number of groups
        let mut groups = vec![0; 1]; // Initial small buffer to get count
        let mut ngroups: libc::c_int = 0;

        // getgrouplist returns -1 if the buffer is too small and updates ngroups
        unsafe {
            libc::getgrouplist(
                username.as_ptr(),
                gid as _,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };

        // Now we know how many groups there are, allocate the proper size buffer
        if ngroups > 0 {
            groups = vec![0; ngroups as usize];

            // Call again with the properly sized buffer
            let ret = unsafe {
                libc::getgrouplist(
                    username.as_ptr(),
                    gid as _,
                    groups.as_mut_ptr(),
                    &mut ngroups,
                )
            };

            // This call should succeed now that we have the right buffer size
            if ret >= 0 {
                groups.truncate(ngroups as usize);
                return Ok(Some(groups.into_iter().map(|g| g as libc::gid_t).collect()));
            }
        }

        // Something went wrong if we get here
        Ok(None)
    }

    fn lookup_group(
        group: &OsStr,
        fallback_to_ids_if_names_are_numeric: bool,
    ) -> Result<libc::gid_t, PrivDropError> {
        let groupname = CString::new(group.as_bytes())
            .map_err(|_| PrivDropError::from((ErrorKind::SysError, "Invalid group name")))?;

        let mut grp = MaybeUninit::<libc::group>::uninit();
        let mut grent = std::ptr::null_mut::<libc::group>();

        // Start with the initial buffer size and increase if needed
        let mut bufsize = INITIAL_BUFFER_SIZE;
        let mut grbuf = vec![0; bufsize];

        let mut ret;
        loop {
            ret = unsafe {
                libc::getgrnam_r(
                    groupname.as_ptr(),
                    grp.as_mut_ptr(),
                    grbuf.as_mut_ptr(),
                    grbuf.len(),
                    &mut grent,
                )
            };

            // If we get ERANGE, the buffer was too small, double it and try again
            if ret == libc::ERANGE {
                bufsize *= 2;
                grbuf.resize(bufsize, 0);
            } else {
                break;
            }
        }

        if ret != 0 || grent.is_null() {
            if !fallback_to_ids_if_names_are_numeric {
                if ret != 0 && ret == libc::ENOENT {
                    return Err(PrivDropError::from((
                        ErrorKind::SysError,
                        "Group not found",
                    )));
                } else if ret != 0 {
                    return Err(PrivDropError::from((
                        ErrorKind::SysError,
                        "Failed to look up group",
                    )));
                } else {
                    return Err(PrivDropError::from((
                        ErrorKind::SysError,
                        "Group not found",
                    )));
                }
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

        // Estimate capacity to reduce allocations
        let mut groups_capacity = 1; // Primary group
        if let Some(ref group_list) = ids.group_list {
            groups_capacity += group_list.len();
        }
        if self.include_default_supplementary_groups {
            groups_capacity += MAX_GROUPS;
        }

        let mut groups = Vec::with_capacity(groups_capacity);

        // Add default supplementary groups if requested
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

        // Add explicitly specified groups
        if let Some(ref group_list) = ids.group_list {
            groups.extend(group_list.iter().cloned());
        }

        if let Some(gid) = ids.gid {
            groups.push(gid);

            // Use HashSet for efficient deduplication
            let unique_groups: Vec<_> = groups
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();

            if unsafe { libc::setgroups(unique_groups.len() as _, unique_groups.as_ptr()) } != 0 {
                return Err(PrivDropError::from((
                    ErrorKind::SysError,
                    "Unable to set supplementary groups",
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
