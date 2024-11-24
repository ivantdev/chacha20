use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};

fn main() {
    // Use a predefined 256-bit key and 96-bit nonce for simplicity
    let key = [0u8; 32]; // All zeros
    let nonce = [0u8; 12]; // All zeros

    let mut cipher = ChaCha20Impl::new(&key, &nonce);

    let plaintext = b"Hello, ChaCha20!"; // Example plaintext
    let mut ciphertext = plaintext.clone();

    // Encrypt the plaintext
    cipher.apply_keystream(&mut ciphertext);
    println!("Ciphertext: {:?}", ciphertext);

    // Decrypt the ciphertext
    cipher.seek(0); // Reset the counter
    let mut decrypted = ciphertext.clone();
    cipher.apply_keystream(&mut decrypted);

    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
}
