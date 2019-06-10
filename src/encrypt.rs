#[cfg(feature = "encrypt")]
mod encrypt {
    use alloc::vec::Vec;
    use core::mem;

    use crate::table::ALPHABET_SIZE;

    pub fn encrypt_slice_from(plaintext: &[u8], key: &Vec<u8>, buf: &mut Vec<u8>) {
        let mut counter = 0;
        while buf.len() < plaintext.len() {
            buf.push(b'A');
        }
        if key.len() == 0 {
            return;
        }
        for (i, c) in plaintext.iter().enumerate() {
            if c.is_ascii_alphabetic() {
                if counter >= key.len() {
                    counter = 0;
                }
                let v = cipher_char(plaintext[i], key[counter]);
                mem::replace(&mut buf[i], v);
                counter += 1;
            } else {
                mem::replace(&mut buf[i], *c);
            };
        }
    }

    pub fn cipher_char(cipher: u8, key: u8) -> u8 {
        let kc = key.to_ascii_uppercase();
        let cipher_is_lowercase = cipher.is_ascii_lowercase();
        let cipher = cipher.to_ascii_uppercase();
        let first = b'A';
        let mut rem = (cipher - first) as i8 + (kc - first) as i8;
        if rem >= ALPHABET_SIZE as i8 { rem -= ALPHABET_SIZE as i8; }
        let cipher = first + rem as u8;
        if cipher_is_lowercase {
            cipher.to_ascii_lowercase()
        } else {
            cipher
        }
    }
}