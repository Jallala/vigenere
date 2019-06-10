#![feature(core_intrinsics, lang_items, alloc_error_handler)]
#![no_std]
#[macro_use]
extern crate alloc;

#[cfg(not(any(feature = "test", test)))]
use core::intrinsics::abort;
#[cfg(not(any(feature = "test", test)))]
use core::panic::PanicInfo;


#[cfg(any(feature = "test", test))]
use wee_alloc;
#[cfg(any(feature = "test", test))]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[cfg(not(any(feature = "test", test)))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { abort() }
}

#[cfg(not(any(feature = "test", test)))]
#[alloc_error_handler]
fn foo(_: core::alloc::Layout) -> ! {
    unsafe { abort() }
}
#[cfg(not(any(feature = "test", test)))]
#[lang = "eh_personality"]
extern fn eh_personality() {}

pub mod key;
pub mod table;
pub mod decipherer;
#[cfg(encrypt)]
mod encrypt;