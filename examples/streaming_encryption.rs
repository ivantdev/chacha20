use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
use rand::Rng;

fn main() {
    let key: [u8; 32] = rand::thread_rng().gen();
    let nonce: [u8; 12] = rand::thread_rng().gen();

    let mut cipher = ChaCha20Impl::new(&key, &nonce);

    let stream = vec![
        b"Hello, ".to_vec(),
        b"this is ".to_vec(),
        b"a live ".to_vec(),
        b"stream!".to_vec(),
    ];

    let mut encrypted_stream = vec![];

    for chunk in stream {
        let mut encrypted_chunk = chunk.clone();
        cipher.apply_keystream(&mut encrypted_chunk);
        encrypted_stream.push(encrypted_chunk);
    }

    println!("Encrypted Stream: {:?}", encrypted_stream);

    // Decrypting
    cipher.seek(0); // Reset the counter
    let mut decrypted_stream = vec![];

    for chunk in encrypted_stream {
        let mut decrypted_chunk = chunk.clone();
        cipher.apply_keystream(&mut decrypted_chunk);
        decrypted_stream.push(String::from_utf8_lossy(&decrypted_chunk).to_string());
    }

    println!("Decrypted Stream: {:?}", decrypted_stream);
}
