#![no_std]
extern crate alloc;

use alloc::string::String;

use vigenere::decipherer::Decipherer;
use alloc::vec::Vec;
use vigenere::key::Id;

const SLICE_BUFFER_SIZE: usize = 512;

#[inline]
fn is_not_printable(c: u8) -> bool {
    (b'\0' <= c && c < b'\n') || (b'\x0B' <= c && c < b'\r')
}

#[inline]
fn is_slice_printable(buf: &[u8]) -> Option<String> {
    for c in buf {
        if is_not_printable(*c) {
            return None;
        }
    }
    match String::from_utf8(buf.to_vec()) {
        Ok(s) => Some(s),
        _ => None
    }
}

pub trait DecipherBase64 {
    fn check_for_candidates(&mut self, start_key: Id, end_key: Id, on_candidate: fn(&String));
    fn vec_fallback(&mut self, start_key: Id, end_key: Id, on_candidate: fn(&String));
}

impl<'t> DecipherBase64 for Decipherer<'t> {
    fn check_for_candidates(&mut self, start_key: Id, end_key: Id, on_candidate: fn(&String)) {
        self.key.set_id(start_key);
        self.decipher_fully();
        if self.text.len() >= SLICE_BUFFER_SIZE { return self.vec_fallback(start_key, end_key, on_candidate); }
        let mut decode_buf = [0; SLICE_BUFFER_SIZE];
        'outer: for _ in start_key..end_key {
            self.decipher_next_key();
            if let Ok(size) = base64::decode_config_slice(
                &self.buf, base64::STANDARD, &mut decode_buf) {
                let mut c = decode_buf.as_ptr();
                for _ in 0..size {
                    unsafe {
                        if is_not_printable(*c) {
                            continue 'outer;
                        }
                        c = c.offset(1);
                    }
                }
                if let Ok(candidate) = String::from_utf8(decode_buf[..size].to_vec()) {
                    on_candidate(&candidate)
                }
            }
        }
    }

    fn vec_fallback(&mut self, start_key: Id, end_key: Id, on_candidate: fn(&String)) {
        let mut decode_buf = Vec::with_capacity(self.text.len());
        for _ in start_key..end_key {
            decode_buf.clear();
            self.decipher_next_key();
            if let Ok(()) = base64::decode_config_buf(
                &self.buf, base64::STANDARD, &mut decode_buf) {
                if let Some(candidate) = is_slice_printable(decode_buf.as_slice()) {
                    on_candidate(&candidate)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn foo() {}
}