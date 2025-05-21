/*!
# privdrop

A secure and comprehensive crate for privilege dropping in Unix-based systems.

## Overview

This crate provides a robust mechanism for privileged processes to safely drop
their elevated permissions, a critical operation for services that need to start
with root privileges but should run with minimal permissions afterward. It supports:

- Changing the root directory (chroot) to restrict filesystem access
- Switching to a non-root user to relinquish privileges
- Setting primary group memberships for proper resource access
- Managing supplementary groups for fine-grained permission control

All operations are performed atomically during the `apply()` call, ensuring
security during the transition.

## Features

- **Atomic Operations**: All privilege-dropping actions occur in one atomic step
- **Builder Pattern**: Simple and flexible configuration interface
- **Error Handling**: Comprehensive error reporting with specific error types
- **Safety Focused**: Designed with security best practices

## Basic Example

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

## Advanced Example

```no_run
use privdrop::PrivDrop;

fn main() {
    PrivDrop::default()
        .chroot("/var/empty")                       // Change root directory
        .user("nobody")                             // Switch to non-root user
        .group("nogroup")                           // Set primary group
        .group_list(&["www-data", "adm"])           // Set supplementary groups
        .include_default_supplementary_groups()     // Include default groups
        .fallback_to_ids_if_names_are_numeric()     // Allow numeric IDs
        .apply()
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with dropped privileges...
}
```

## Safety Considerations

This crate performs privilege operations that require root access initially.
All operations are executed in a specific order to ensure security:

1. Preloading necessary resources before privilege drop to prevent deadlocks
2. Looking up user and group IDs
3. Performing chroot operations if configured
4. Dropping privileges by changing user and group IDs

The system ensures that once privileges are dropped, they cannot be regained.
*/

pub use self::errors::*;
pub use self::privdrop::*;

mod errors;
mod privdrop;

/// Reexported dependencies for use in consuming crates.
///
/// This module provides access to the underlying dependencies used by this crate,
/// allowing consumers to utilize the same versions without specifying them separately.
///
/// ## Available Reexports
///
/// - `libc`: Low-level bindings to the C standard library
/// - `nix`: Rust friendly bindings to *nix APIs with user and filesystem features
pub mod reexports {
    pub use {libc, nix};
}
