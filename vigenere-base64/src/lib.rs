#![no_std]
#[macro_use]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// Only set allocator if running `cargo test`
#[cfg(any(feature = "test", test))]
use wee_alloc;

use vigenere::decipherer::Decipherer;
use vigenere::key::Id;

#[cfg(any(feature = "test", test))]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const SLICE_BUFFER_SIZE: usize = 2 * 192 * core::mem::size_of::<u8>();

#[inline]
fn is_unwanted_character(c: u8) -> bool {
    (b'\0' <= c && c < b'\n') || (b'\x0B' <= c && c < b'\r')
}

#[inline]
fn does_slice_contain_unwanted_characters(buf: &[u8]) -> Option<String> {
    {
        let mut c = buf.as_ptr();
        for _ in 0..buf.len() {
            unsafe {
                if is_unwanted_character(*c) {
                    return None;
                }
                c = c.offset(1);
            }
        }
    }
    match String::from_utf8(buf.to_vec()) {
        Ok(s) => Some(s),
        _ => None
    }
}

#[inline]
fn decoded_size(input_size: usize) -> usize {
    input_size + 3 / 4 * 3
}

pub trait DecipherBase64 {
    fn check_for_candidates<F: FnMut(&String)>(&mut self, start: Id, end: Id, on_candidate: F) -> Id where F: FnMut(&String);
    fn check_for_candidates_vec<F>(&mut self, start: Id, end: Id, on_candidate: F) -> Id where F: FnMut(&String);
}


impl<'t> DecipherBase64 for Decipherer<'t> {
    fn check_for_candidates<F: FnMut(&String)>(&mut self, start: Id, end: Id, on_candidate: F) -> Id {
        let mut on_candidate = on_candidate;
        let size_decoded_max = decoded_size(self.text.len());
        if size_decoded_max >= SLICE_BUFFER_SIZE {
            return self.check_for_candidates_vec(start, end, on_candidate);
        }
        self.key.set_id(start);
        self.decipher_fully();
        let mut candidates = 0;
        let mut decode_buf = [0; SLICE_BUFFER_SIZE];

        loop {
            if let Ok(size) = base64::decode_config_slice(
                &self.buf, base64::STANDARD, &mut decode_buf) {
                assert!(size < decode_buf.len());
                if let Some(candidate) = does_slice_contain_unwanted_characters(&decode_buf[..size]) {
                    candidates += 1;
                    on_candidate(&candidate)
                }
            }
            if self.key.id >= end { return candidates; }
            self.decipher_next_key();
        }
    }

    fn check_for_candidates_vec<F>(&mut self, start: Id, end: Id, on_candidate: F) -> Id where F: FnMut(&String) {
        let mut on_candidate = on_candidate;
        self.key.set_id(start);
        self.decipher_fully();
        let mut candidates = 0;
        let mut decode_buf = Vec::with_capacity(decoded_size(self.text.len()));
        loop {
            decode_buf.clear();
            if let Ok(()) = base64::decode_config_buf(
                &self.buf, base64::STANDARD, &mut decode_buf) {
                if let Some(candidate) = does_slice_contain_unwanted_characters(decode_buf.as_slice()) {
                    candidates += 1;
                    on_candidate(&candidate)
                }
            }
            if self.key.id >= end { return candidates; }
            self.decipher_next_key();
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::iter::repeat;

    use super::*;

    #[test]
    fn test_slice_buffer_size_is_multiple_of_3_and_4() {
        assert_eq!(SLICE_BUFFER_SIZE % 3, 0);
        assert_eq!(SLICE_BUFFER_SIZE % 4, 0);
    }

    #[test]
    fn test_upper_estimate_does_not_panic() {
        fn test_slice(slice: &mut [u8], subst: &[u8], expected_size: usize) {
            for (idx, ch) in subst.iter().enumerate() {
                slice[slice.len() - subst.len() + idx] = *ch;
            }
            let mut dc = Decipherer::from_slice(slice);
            let d = |s: &String| assert_eq!(s.len(), expected_size);
            let found = dc.check_for_candidates(0, 0, d);
            assert_eq!(found, 1)
        }

        const INPUT_LEN: usize = (SLICE_BUFFER_SIZE / 3) * 4;
        assert_eq!(INPUT_LEN + 3 / 4 * 3, INPUT_LEN);
        assert_eq!(INPUT_LEN % 4, 0);
        assert!(SLICE_BUFFER_SIZE > 0);

        test_slice(&mut [b'6'; INPUT_LEN - 4], b"", SLICE_BUFFER_SIZE - 3);
        test_slice(&mut [b'6'; INPUT_LEN], b"", SLICE_BUFFER_SIZE);
        test_slice(&mut [b'6'; INPUT_LEN + 4], b"", SLICE_BUFFER_SIZE + 3);
        test_slice(&mut [b'6'; INPUT_LEN + 4], b"Yg==", SLICE_BUFFER_SIZE + 1);
        test_slice(&mut [b'6'; INPUT_LEN], b"Yg==", SLICE_BUFFER_SIZE - 2);
        test_slice(&mut [b'6'; INPUT_LEN + 4], b"YWE=", SLICE_BUFFER_SIZE + 2);
        test_slice(&mut [b'6'; INPUT_LEN], b"YWE=", SLICE_BUFFER_SIZE - 1);
    }

    #[test]
    fn test_vec_impl_yields_same_results() {
        let cases = [
            "".to_string(),
            "A".to_string(),
            "Hello, world".to_string(),
            repeat("A").take((SLICE_BUFFER_SIZE / 3) * 4).collect(),
            repeat("A").take((SLICE_BUFFER_SIZE / 3) * 4 * 2).collect()
        ];
        let ranges = [(0, 0), (0, 1), (1, 1), (1, 10000), (0, 10000), (5000, 10000)];
        for case in cases.iter() {
            for (start, end) in ranges.iter() {
                let v = base64::encode_config(case, base64::STANDARD);
                test_implementation_equality(v.as_bytes(), *start, *end);
            }
        }
    }

    fn test_implementation_equality(text: &[u8], start: Id, end: Id) {
        enum Func { Slice, Vec }
        let save_candidates = |func: Func| {
            let mut dc = Decipherer::from_slice(text);
            let mut candidates = Vec::new();
            let on_candidates = |s: &String| candidates.push(s.clone());
            let n = match func {
                Func::Slice => dc.check_for_candidates(start, end, on_candidates),
                Func::Vec => dc.check_for_candidates_vec(start, end, on_candidates)
            };
            (n, candidates)
        };

        let (slice_found, slice_candidates) = save_candidates(Func::Slice);
        let (vec_found, vec_candidates) = save_candidates(Func::Vec);

        assert_eq!(slice_found, vec_found);
        assert_eq!(slice_candidates.len(), slice_found as usize);
        assert_eq!(vec_candidates.len(), vec_found as usize);
        assert_eq!(slice_candidates.len(), vec_candidates.len());
        for (vec_candidate, slice_candidate) in vec_candidates.iter().zip(slice_candidates.iter()) {
            assert_eq!(vec_candidate, slice_candidate);
        }
    }
}