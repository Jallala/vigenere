#![no_std]
#[macro_use]
extern crate alloc;

// Only set allocator if running `cargo test`
#[cfg(any(feature = "test", test))]
use wee_alloc;
#[cfg(any(feature = "test", test))]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub mod key;
pub mod table;
pub mod decipherer;
#[cfg(encrypt)]
mod encrypt;