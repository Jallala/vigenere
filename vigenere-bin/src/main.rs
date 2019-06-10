#![feature(exclusive_range_pattern)]

use vigenere::decipherer::Decipherer;
use time::PreciseTime;
use base64;

fn main() {
    let cipher_text =
        b"G2pilVJccjJiQZ1poiM3iYZhj3I0IRbvj3wxomnoeOatVHUxZ2ozGKJgjXMzj2L\
        goOitBOM1dSDzHMatdRpmQZpidNehG29mkTxwmDJbGJxsjnVeQT9mTPSwSAOwnuWhSE\
        50ByMpcuJoqGstJOCxqHCtdvG3HJV0TOGuwOIyoOGhwOHgm2GhlZpyISJik3J/";
    let end_key = 99190197600;
    let start_key = end_key - 10000000;

    // let cipher_text = b"Kwj ody hhlew szioap";
    // DSAFDSA

    println!("{}", end_key - start_key);
    let start = PreciseTime::now();
    check_for_candidates(start_key, end_key, cipher_text);
    let stop = start.to(PreciseTime::now());
    {
        let num_keys = end_key - start_key;
        let (it_per_sec, mu_sec_it) = stop.num_nanoseconds().map(|ns| ns as f64)
            .map_or_else(|| (0.0, 0.0), |ns| (num_keys as f64 / (ns / 1000_000_000.0), ns / num_keys as f64));
        println!("{:?}, n={}, {:.3} it/s, {:.3} ns/it", stop, num_keys, it_per_sec, mu_sec_it);
    };
}

fn check_for_candidates(start_key: usize, end_key: usize, cipher_text: &[u8]) {
    let mut decipherer = Decipherer::from_slice(cipher_text);
    decipherer.key.set_id(start_key as u64);
    decipherer.decipher_fully();
    let mut buf = [0; 4096];
    let mut candidates = 0u64;
    let mut tries = 0u64;
    const PRINT_EVERY: u64 = 10_000_000;
    'outer: for current_key in start_key..end_key {
        if decipherer.key.id > end_key as u64 {
            break;
        }
        decipherer.decipher_next_key();
        if tries >= PRINT_EVERY {
            tries = 0;
            println!("Tested {} of {} keys, candidates: {}, key: {}", current_key - start_key, end_key - start_key, candidates, decipherer.key);
        }
        tries += 1;
        if let Ok(size) = base64::decode_config_slice(&decipherer.buf, base64::STANDARD, &mut buf) {
            assert!(size < buf.len());
            let mut buf_ptr = buf.as_ptr();
            for _ in 0..size {
                unsafe {
                    match *buf_ptr {
                        b'\0'..b'\n' | b'\x0B'..b'\r' => continue 'outer,
                        _ => buf_ptr = buf_ptr.offset(1)
                    };
                }
            }
            if let Ok(candidate) = String::from_utf8(buf[..size].to_vec()) {
                println!("{}\n{}", decipherer.key, candidate);
                candidates += 1;
                break;
            }
        }
    }
    println!("{}", decipherer);
    println!(
        "Tested {} keys, candidates: {}",
        end_key - start_key,
        candidates,
    );
}