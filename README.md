# ChaCha20 Stream Cipher Implementation

This is an implementation of **ChaCha20**, a modern and secure stream cipher designed by Daniel J. Bernstein. ChaCha20 is known for its speed, simplicity, and resistance to cryptographic attacks, making it a popular choice for secure communications in protocols like TLS 1.3.

---

## Features

- **Complete Implementation**: Implements the core ChaCha20 algorithm for generating keystream blocks.
- **Customizable Inputs**: Supports custom keys and nonces for flexibility.
- **Lightweight**: Designed for efficiency and easy integration into larger projects.
- **Secure**: Follows the standard ChaCha20 specifications to ensure robustness.

---

## How It Works

ChaCha20 generates a **keystream** which is XORed with the plaintext to produce the ciphertext. The process is reversible: XORing the ciphertext with the same keystream recovers the plaintext.

### Algorithm Steps:
1. Initialize a 512-bit state matrix with:
   - Constants (fixed values).
   - Key (256 bits).
   - Nonce (96 bits).
2. Apply 20 rounds of quarter-round operations (10 column rounds + 10 diagonal rounds).
3. Generate a keystream block from the state.
4. XOR the keystream block with the plaintext.

---

## Usage

### Prerequisites
- A Rust compiler (e.g., [Rustup](https://rustup.rs/)).
- Basic knowledge of ChaCha20 inputs (key, nonce, etc.).

### Installation

Clone the repository and use it in your Rust project:

```bash
git clone https://github.com/ivantdev/chacha20.git
cd chacha20
```

Add the library as a dependency in your Cargo.toml:

```toml
[dependencies]
chacha20imp = { path = "./path/to/chacha20" }
```

### Example of usage
```rust
use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
use rand::Rng;

fn main() {
    // Generate a random 256-bit key and 96-bit nonce
    let key: [u8; 32] = rand::thread_rng().gen();
    let nonce: [u8; 12] = rand::thread_rng().gen();

    let mut cipher = ChaCha20Impl::new(&key, &nonce);

    cipher.seek(1); // Optional: Set the counter position. By default it is 0

    let mut buf = [0u8; 64];
    cipher.apply_keystream(&mut buf);

    // Now `buf` contains the keystream/ciphertext or encrypted data
    println!("Keystream/Ciphertext: {:?}", buf);

    // For decryption, simply apply the keystream again
    // Reset the counter to the original position (in this case, 1, since we set it to 1)
    cipher.seek(1);
    cipher.apply_keystream(&mut buf);
    println!("Plaintext: {:?}", buf);
}
```

## Examples

 You can also run the examples provided in this repository. For instance:
 ```bash
 cargo run --example basic_usage
```

## Build and test

To build the library:

```bash
cargo build
```

To test the implementation:

```bash
cargo test
```

## Documentation
Detailed documentation is available in the code comments. You can also generate documentation locally:

```bach
cargo doc --open
```


## ⚠️ Disclaimer: Not Guaranteed to Be 100% Secure

This implementation of ChaCha20 aims to follow the standard algorithmic design. However, it has **not been formally audited or verified** to meet industry cryptographic security standards.

### Key Points to Consider:
1. **No Security Audit**:
   - This code has not undergone a thorough cryptographic security review.
   - There may be vulnerabilities or implementation flaws that could compromise its security.

2. **For Educational or Experimental Use**:
   - While ChaCha20 is considered a secure algorithm when implemented correctly, this library should be treated as a learning or experimental tool unless independently verified.

3. **Not Recommended for Sensitive Data**:
   - Avoid using this library for encrypting sensitive or confidential information in production environments without prior audit and verification.

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.