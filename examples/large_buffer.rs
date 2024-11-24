use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
use rand::Rng;

fn main() {
    let key: [u8; 32] = rand::thread_rng().gen();
    let nonce: [u8; 12] = rand::thread_rng().gen();

    let mut cipher = ChaCha20Impl::new(&key, &nonce);

    let plaintext = vec![0u8; 256]; // Example of a large buffer
    let mut ciphertext = plaintext.clone();

    for chunk in ciphertext.chunks_mut(64) {
        cipher.apply_keystream(chunk);
    }

    println!("Ciphertext: {:?}", ciphertext);

    // Decrypting
    cipher.seek(0); // Reset the counter
    let mut decrypted = ciphertext.clone();
    for chunk in decrypted.chunks_mut(64) {
        cipher.apply_keystream(chunk);
    }

    println!("Decrypted: {:?}", decrypted);
}
