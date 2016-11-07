#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

extern crate libc;
extern crate nix;

pub use errors::*;
pub use privdrop::*;

mod errors;
mod privdrop;
