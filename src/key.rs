use alloc::{string::String, vec::Vec};
use core::{fmt, mem};

use crate::table::ALPHABET_SIZE;
use core::convert::TryFrom;
use core::slice::Iter;
use core::ops::Index;

pub type Id = u128;

#[derive(Debug)]
pub struct Key {
    pub id: Id,
    pub buf: Vec<u8>,
}

impl Key {
    pub fn first() -> Key {
        Key { id: 0, buf: vec![b'A'] }
    }

    pub fn set_id(&mut self, mut id: Id) {
        self.id = id.clone();
        self.buf.clear();
        loop {
            let div = id / ALPHABET_SIZE as Id;
            let rem = id % ALPHABET_SIZE as Id;
            self.buf.insert(0, b'A' + rem as u8);
            if id < 26 {
                break;
            }
            id = div - 1;
        }
    }

    pub fn from_slice(key: &[u8]) -> Result<Key, &'static str> {
        if key.len() == 0 {
            Ok(Key::first())
        } else {
            let mut id = 0;
            let mut pow = 1;
            let buf = key.clone().into();
            for k in key.iter().rev() {
                if !k.is_ascii_alphabetic() {
                    return Err("Invalid characters in key");
                }
                id += pow * (k - b'A' + 1) as Id;
                pow *= ALPHABET_SIZE as Id;
            }
            Ok(Key { id: id - 1, buf })
        }
    }

    /// Advances key to the next in in the sequence and returns the
    /// amount of characters changed from the right.
    /// # Examples:
    /// ```
    /// use vigenere::key::Key;
    ///
    /// let mut k = Key::from_slice(b"AA").unwrap();
    /// let modified = k.advance();
    /// assert_eq!(k.buf_to_string(), "AB");
    /// assert_eq!(modified, 1);
    ///
    /// let mut k = Key::from_slice(b"ABZZ").unwrap();
    /// let modified = k.advance();
    /// assert_eq!(k.buf_to_string(), "ACAA");
    /// assert_eq!(modified, 3);
    /// ```
    #[inline]
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

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }


    pub fn buf_to_string(&self) -> String {
        match String::from_utf8(self.buf.clone()) {
            Ok(s) => s,
            _ => panic!("Key is not valid UTF-8")
        }
    }

    #[inline]
    pub unsafe fn get_unchecked(&self, idx: usize) -> &u8 {
        self.buf.get_unchecked(idx)
    }

    #[inline]
    pub fn iter(&self) -> Iter<u8> {
        self.buf.iter()
    }
}

impl From<Id> for Key {
    fn from(id: Id) -> Self {
        let mut k = Key::first();
        k.set_id(id);
        k
    }
}

impl Index<usize> for Key {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[index]
    }
}


impl TryFrom<&str> for Key {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Key::from_slice(value.as_bytes())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{id: {}, buf: {}}}", self.id, self.buf_to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate test;
    use test::Bencher;
    use core::convert::TryInto;

    #[test]
    fn test_first_key() {
        let k = Key::first();
        assert_eq!(0, k.id);
        assert_eq!("A", k.buf_to_string());
        assert_eq!(vec![b'A'], k.buf);
    }

    #[test]
    fn test_advance() {
        let mut k = Key::first();
        k.advance();
        assert_eq!(1, k.id);
        assert_eq!("B", k.buf_to_string());
    }

    #[bench]
    fn bench_advance(b: &mut Bencher) {
        let mut k = Key::first();
        b.iter(|| k.advance())
    }

    #[bench]
    fn bench_from_str(b: &mut Bencher) {
        b.iter(|| {
            let mut _k: Key = "ABCDEFGH".try_into().unwrap();
        })
    }

    #[bench]
    fn bench_from_slice(b: &mut Bencher) {
        b.iter(|| Key::from_slice(b"ABCDEFGH"))
    }

    #[bench]
    fn bench_from_id(b: &mut Bencher) {
        let id = {
            Key::from_slice(b"ABCDEFGH").unwrap().id
        };
        b.iter(|| {
            let _: Key = id.into();
        })
    }
}