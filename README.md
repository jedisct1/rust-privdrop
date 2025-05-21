# privdrop

A simple crate to drop privileges in Unix systems safely.

[![Documentation](https://docs.rs/privdrop/badge.svg)](https://docs.rs/privdrop)
[![Crates.io](https://img.shields.io/crates/v/privdrop.svg)](https://crates.io/crates/privdrop)

## Overview

This crate provides a safe mechanism for privileged processes to drop their privileges by:
- Changing the root directory (chroot)
- Switching to a non-root user
- Setting group memberships
- Managing supplementary groups

All operations are performed atomically during the `apply()` call.

## Usage

Add the dependency to your `Cargo.toml`:
```toml
[dependencies]
privdrop = "0.5"
```

### Example

```rust
use privdrop::PrivDrop;

fn main() {
    // Application starts as root

    // Set up privilege dropping
    PrivDrop::default()
        .chroot("/var/empty")  // Change root directory
        .user("nobody")        // Switch to non-root user
        .apply()               // Apply changes
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with dropped privileges...
}
```

### Advanced Usage

```rust
use privdrop::PrivDrop;

fn main() {
    PrivDrop::default()
        .chroot("/var/empty")
        .user("nobody")
        .group("nogroup")
        .include_default_supplementary_groups()
        .fallback_to_ids_if_names_are_numeric()
        .apply()
        .unwrap_or_else(|e| panic!("Failed to drop privileges: {}", e));

    // Continue running with dropped privileges...
}
```

## Safety Notes

This crate performs privilege operations that require root access. All operations are executed in a specific order to ensure security. The privilege dropping is atomic - it happens all at once during the `apply()` call.

## Platform Support

This crate is only supported on Unix-like systems that provide the necessary privilege-dropping syscalls.

[API documentation](https://docs.rs/privdrop)
