use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};

pub fn main() {
    let key = [0u8; 32];
    let nonce= [0u8; 12];
    let mut cipher = ChaCha20Impl::new(&key, &nonce);
    cipher.seek(1);
}