#![feature(core_intrinsics, lang_items, alloc_error_handler)]
#![no_std]
#[macro_use]
extern crate alloc;

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