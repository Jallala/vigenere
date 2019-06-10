use alloc::{string::String, vec::Vec};
use core::{fmt, mem};

use crate::table::ALPHABET_SIZE;

#[derive(Debug)]
pub struct Key {
    pub id: u64,
    pub buf: Vec<u8>,
}

impl Key {
    pub fn first() -> Key {
        Key { id: 0, buf: vec![b'A'] }
    }

    #[inline]
    pub fn set_id(&mut self, mut id: u64) {
        self.id = id.clone();
        self.buf.clear();
        loop {
            let div = id / ALPHABET_SIZE as u64;
            let rem = id % ALPHABET_SIZE as u64;
            self.buf.insert(0, b'A' + rem as u8);
            if id < 26 {
                break;
            }
            id = div - 1;
        }
    }

    pub fn from_slice(key: &[u8]) -> Key {
        if key.len() == 0 {
            Key::first()
        } else {
            let mut id = 0;
            let mut pow = 1;
            let buf = key.clone().into();
            for k in key.iter().rev() {
                if !k.is_ascii_alphabetic() {
                    panic!("Invalid characters in key")
                }
                id += pow * (k - b'A' + 1) as u64;
                pow *= ALPHABET_SIZE as u64;
            }
            Key { id: id - 1, buf }
        }
    }

    /// Advances key to the next in in the sequence and returns the
    /// amount of characters changed from the right.
    /// # Examples:
    /// ```
    /// use vigenere::key::Key;
    ///
    /// let mut k = Key::from_slice(b"AA");
    /// let modified = k.advance();
    /// assert_eq!(k.buf_to_string(), "AB");
    /// assert_eq!(modified, 1);
    ///
    /// let mut k = Key::from_slice(b"ABZZ");
    /// let modified = k.advance();
    /// assert_eq!(k.buf_to_string(), "ACAA");
    /// assert_eq!(modified, 3);
    /// ```
    pub fn advance(&mut self) -> usize {
        self.id += 1;
        for (i, key_char) in self.buf.iter_mut().rev().enumerate() {
            if *key_char != b'Z' {
                mem::replace(key_char, *key_char + 1);
                return i + 1;
            }
            mem::replace(key_char, b'A');
        }
        self.buf.insert(0, b'A');
        self.buf.len()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn buf_to_string(&self) -> String {
        match String::from_utf8(self.buf.clone()) {
            Ok(s) => s,
            _ => panic!("Key is not valid UTF-8")
        }
    }
}

impl From<u64> for Key {
    fn from(id: u64) -> Self {
        let mut k = Key::first();
        k.set_id(id);
        k
    }
}


impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{id: {}, buf: {}}}", self.id, self.buf_to_string())
    }
}