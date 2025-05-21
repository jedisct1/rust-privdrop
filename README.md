# privdrop

A comprehensive, secure crate for dropping privileges in Unix-based systems.

[![Documentation](https://docs.rs/privdrop/badge.svg)](https://docs.rs/privdrop)
[![Crates.io](https://img.shields.io/crates/v/privdrop.svg)](https://crates.io/crates/privdrop)

## Overview

The `privdrop` crate provides a robust, security-focused mechanism for applications that need to drop root privileges safely. This is a critical security practice for services that start with root permissions but need to operate with minimal privileges during execution.

### Features

- **Atomic Operations**: All privilege-dropping actions occur in one atomic step
- **Comprehensive Security**: Handles all aspects of privilege dropping properly
- **Flexible Configuration**: Builder pattern for simple, chainable setup
- **Error Handling**: Detailed error reporting for security operations
- **Cross-Platform**: Works on Unix-like systems with privilge-dropping syscalls

## Key Capabilities

The crate enables processes to:

- **Change Root Directory (chroot)**: Isolate the application's filesystem access
- **Switch User**: Relinquish root privileges by changing to a non-root user
- **Manage Primary Group**: Control primary group membership
- **Configure Supplementary Groups**: Set precise access permissions
- **Handle Numeric IDs**: Optionally use UIDs/GIDs directly when names aren't available

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
privdrop = "0.5.5"
```

## Basic Example

This example shows the simplest way to drop privileges:

```rust
use privdrop::PrivDrop;

fn main() {
    // Application starts with root privileges

    PrivDrop::default()
        .chroot("/var/empty")  // Restrict filesystem access
        .user("nobody")        // Switch to unprivileged user
        .apply()               // Apply all changes atomically
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with dropped privileges...
}
```

## Advanced Usage

This example demonstrates more complex configurations:

```rust
use privdrop::PrivDrop;

fn main() {
    PrivDrop::default()
        // Basic configuration
        .chroot("/var/empty")                       // Change root directory
        .user("service-user")                       // Switch to non-root user

        // Group management
        .group("service-group")                     // Set primary group
        .group_list(&["www-data", "logs"])          // Add supplementary groups
        .include_default_supplementary_groups()     // Include user's default groups

        // Fallback options
        .fallback_to_ids_if_names_are_numeric()     // Allow numeric UIDs/GIDs

        // Apply all changes
        .apply()
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with limited privileges...
}
```

## Security Architecture

The privilege dropping process is carefully designed to prevent security issues:

1. **Preloading**: System resources are preloaded before dropping privileges to prevent deadlocks
2. **Complete Preparation**: All user/group IDs are looked up while still privileged
3. **Chroot First**: Root directory is changed before user/group IDs to prevent bypassing
4. **Atomic ID Changes**: User and group IDs are changed in the correct order
5. **All-or-Nothing**: If any operation fails, the entire privilege drop fails

## Platform Support

This crate is supported on:
- Linux
- macOS
- FreeBSD
- OpenBSD
- Other Unix-like systems that provide the necessary privilege-dropping syscalls

## Documentation

For detailed API documentation and more examples, see the [API documentation](https://docs.rs/privdrop).

## License

Licensed under ISC license, see [LICENSE](LICENSE) for details.
