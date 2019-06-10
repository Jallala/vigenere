
use vigenere::decipherer::Decipherer;
use vigenere_base64::DecipherBase64;
use time::PreciseTime;

fn main() {
    let cipher_text: &'static [u8] =
        b"G2pilVJccjJiQZ1poiM3iYZhj3I0IRbvj3wxomnoeOatVHUxZ2ozGKJgjXMzj2L\
        goOitBOM1dSDzHMatdRpmQZpidNehG29mkTxwmDJbGJxsjnVeQT9mTPSwSAOwnuWhSE\
        50ByMpcuJoqGstJOCxqHCtdvG3HJV0TOGuwOIyoOGhwOHgm2GhlZpyISJik3J/";
    let end_key = {
        let id = vigenere::key::Key::from_slice(b"LIBITINA").id;
        println!("{}", id);
        id
    };
    let threads = 4;
    let per_thread = 20000000;
    let start_key = end_key - threads * per_thread;

    let start = PreciseTime::now();
    let on_candidate = |c: &String| println!("{}", c);
    let mut decipherer = Decipherer::from_slice(cipher_text);
    decipherer.check_for_candidates(start_key, end_key, on_candidate);


    let stop = start.to(PreciseTime::now());
    {
        let num_keys = end_key - start_key;
        let (it_per_sec, mu_sec_it) = stop.num_nanoseconds().map(|ns| ns as f64)
            .map_or_else(|| (0.0, 0.0), |ns| (num_keys as f64 / (ns / 1000_000_000.0), ns / num_keys as f64));
        println!("{:?}, n={}, {:.3} it/s, {:.3} ns/it", stop, num_keys, it_per_sec, mu_sec_it);
    };
    println!("{}", decipherer);
}