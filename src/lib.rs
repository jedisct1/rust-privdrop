/*!
# privdrop

A simple crate to drop privileges safely in Unix systems.

This crate provides a mechanism for privileged processes to drop
their privileges by:
- Changing the root directory (chroot)
- Switching to a non-root user
- Setting group memberships
- Managing supplementary groups

All operations are performed atomically during the `apply()` call.

## Example

```no_run
use privdrop::PrivDrop;

fn main() {
    PrivDrop::default()
        .chroot("/var/empty")
        .user("nobody")
        .apply()
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with dropped privileges...
}
```

## Safety

This crate performs privilege operations that require root access.
All operations are executed in a specific order to ensure security.
*/

pub use self::errors::*;
pub use self::privdrop::*;

mod errors;
mod privdrop;

/// Reexported dependencies for use in consuming crates
pub mod reexports {
    pub use {libc, nix};
}
