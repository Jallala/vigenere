use alloc::{string::String, string::ToString, vec::Vec};
use core::{cmp::min, fmt, ptr};

use crate::key::Key;
use crate::table::ALPHABET_LOWER_UPPER_A_Z;

const BUF_NOT_VALID_UTF8: &'static str = "<Not valid UTF-8>";

#[derive(Debug)]
pub struct Decipherer<'t> {
    pub key: Key,
    pub text: &'t [u8],
    pub compact_text: Vec<u8>,
    pub buf: Vec<u8>,
    pointers_to_buf: Vec<*mut u8>,
}

macro_rules! decipher_using_table {
    ($cipher:expr, $key:expr) => {
        unsafe {
            *ALPHABET_LOWER_UPPER_A_Z
                .get_unchecked($cipher as usize)
                .get_unchecked($key as usize)
        }
    };
}

macro_rules! decipher_to_ptr {
    ($pointers:expr, $index:expr, $cipher:expr, $key:expr) => {
        unsafe {
            (*$pointers.get_unchecked_mut($index))
                .write(*ALPHABET_LOWER_UPPER_A_Z
                    .get_unchecked($cipher as usize)
                    .get_unchecked($key as usize)
            );
        }
    };
}

impl<'t> Decipherer<'t> {
    pub fn from_slice(text: &[u8]) -> Decipherer {
        let mut buf = vec![b'A'; text.len()];
        let mut raw_ptr = buf.as_mut_slice().as_mut_ptr();
        let key = Key::first();
        let compact_size = text.iter()
            .filter(|c| c.is_ascii_alphabetic())
            .count();

        let mut compact_text = Vec::with_capacity(compact_size);
        let mut pointers_to_buf = Vec::with_capacity(compact_size);
        for c in text.iter() {
            unsafe {
                if c.is_ascii_alphabetic() {
                    ptr::write(raw_ptr, b'A');
                    compact_text.push(c.clone());
                    pointers_to_buf.push(raw_ptr);
                } else {
                    ptr::write(raw_ptr, c.clone());
                }
                raw_ptr = raw_ptr.offset(1)
            };
        }
        Decipherer { key, text, compact_text, pointers_to_buf, buf }
    }

    #[inline]
    pub fn decipher_char_using_table(cipher: u8, key: u8) -> u8 {
        decipher_using_table!(cipher, key)
    }

    #[inline]
    pub fn decipher_fully(&mut self) {
        for (idx, (cipher, key)) in self.compact_text
            .iter()
            .zip(self.key
                .iter()
                .cycle())
            .enumerate() {
            decipher_to_ptr!(self.pointers_to_buf, idx, *cipher, *key);
        }
    }

    /// Decrypts next key in sequence. Assumes that buffer already has been fully deciphered
    #[inline]
    pub fn decipher_next_key(&mut self) {
        // We only need to decipher characters that have been since the last pass
        // e.g. if cipher is "ABCD" and key is changes from "AA" -> "AB",
        // only "-B-D" needs to be deciphered
        let key_characters_modified = self.key.advance();
        let size = self.key.len();
        let modify_every = size - key_characters_modified;
        let mut idx = modify_every;

        while idx < self.compact_text.len() {
            let end_of_sequence = modify_every + min(key_characters_modified, self.compact_text.len() - idx);
            for key_idx in modify_every..end_of_sequence {
                decipher_to_ptr!(self.pointers_to_buf, idx, *self.compact_text.get_unchecked(idx), *self.key.get_unchecked(key_idx));
                idx += 1;
            }
            idx += modify_every;
        }
    }

    pub fn buf_to_string(&self) -> String {
        Decipherer::try_convert_to_utf8(&self.buf.to_vec())
    }

    pub fn compact_to_string(&self) -> String {
        Decipherer::try_convert_to_utf8(&self.compact_text)
    }

    pub fn pointers_to_buf_to_string(&self) -> String {
        let mut work_buf = Vec::with_capacity(self.pointers_to_buf.len());
        for v in self.pointers_to_buf.iter() {
            assert_ne!(*v, ptr::null_mut());
            unsafe {
                work_buf.push(**v)
            }
        };
        Decipherer::try_convert_to_utf8(&work_buf)
    }

    fn try_convert_to_utf8(vec: &Vec<u8>) -> String {
        match String::from_utf8(vec.clone()) {
            Ok(s) => s,
            _ => BUF_NOT_VALID_UTF8.to_string()
        }
    }
}

impl<'t> fmt::Display for Decipherer<'t> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Cipher {{\n\tkey: {},\n\tpointers_to_buf: {},\n\tbuf: {}\n}}",
               self.key,
               self.pointers_to_buf_to_string(),
               self.buf_to_string()
        )
    }
}

impl <'t> Clone for Decipherer<'t> {
    fn clone(&self) -> Self {
        let mut c = Decipherer::from_slice(&self.text[..]);
        c.key.set_id(self.key.id);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Id;

    #[test]
    fn test_cipher_decrypt_char_lower() {
        for cipher in b'a'..=b'z' {
            for key in b'a'..=b'z' {
                let result = Decipherer::decipher_char_using_table(cipher, key);
                assert!(result.is_ascii_alphabetic());
                assert!(result.is_ascii_lowercase());
            }
        }
    }

    #[test]
    fn test_cipher_decrypt_char_upper() {
        for cipher in b'A'..=b'Z' {
            for key in b'A'..=b'Z' {
                let result = Decipherer::decipher_char_using_table(cipher, key);
                assert!(result.is_ascii_alphabetic());
                assert!(result.is_ascii_uppercase());
            }
        }
    }

    #[test]
    fn test_decipher_next_key() {
        let original_text = "abc123";
        fn check_id_and_buffers(d: &Decipherer, expected: (Id, &str, &str)) {
            assert_eq!(d.key.id, expected.0);
            assert_eq!(d.key.buf_to_string(), expected.1.to_string());
            assert_eq!(d.buf_to_string(), expected.2.to_string());
        }
        let mut dc = Decipherer::from_slice(original_text.as_bytes());
        dc.decipher_fully();
        check_id_and_buffers(&dc, (0, "A", original_text));
        dc.decipher_next_key();
        check_id_and_buffers(&dc, (1, "B", "zab123"));
        dc.decipher_next_key();
        check_id_and_buffers(&dc, (2, "C", "yza123"));
        while dc.key.id < 26 {
            dc.decipher_next_key();
        }
        check_id_and_buffers(&dc, (26, "AA", original_text));
        dc.decipher_next_key();
        check_id_and_buffers(&dc, (27, "AB", "aac123"));
    }

    #[test]
    fn test_cipher_compact() {
        let c = Decipherer::from_slice(b"a1bc123A=B!\nC");
        assert_eq!(c.compact_to_string(), "abcABC".to_string());
    }
}