use chacha20imp::chacha20::{ChaCha20, ChaCha20Impl};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

fn main() -> std::io::Result<()> {
    let key: [u8; 32] = rand::thread_rng().gen();
    let nonce: [u8; 12] = rand::thread_rng().gen();

    let mut cipher = ChaCha20Impl::new(&key, &nonce);

    // For this example we will create a file first
    //

    // Step 1: Create example.txt with some sample content
    let mut input_file = File::create("example.txt")?;
    writeln!(input_file, "This is a sample text to demonstrate ChaCha20 encryption!")?;
    println!("Created 'example.txt' with sample content.");

    // Step 2: Encrypt the content of example.txt
    let mut input_file = File::open("example.txt")?;
    let mut output_file = OpenOptions::new().write(true).create(true).open("example.enc")?;

    let mut buffer = [0u8; 64];
    while let Ok(bytes_read) = input_file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }

        cipher.apply_keystream(&mut buffer[..bytes_read]);
        output_file.write_all(&buffer[..bytes_read])?;
    }

    println!("File encrypted successfully! Output: 'example.enc'");

    // Step 3: Decrypt the content of example.enc
    cipher.seek(0); // Reset the counter
    let mut encrypted_file = File::open("example.enc")?;
    let mut decrypted_file = OpenOptions::new().write(true).create(true).open("example_dec.txt")?;

    while let Ok(bytes_read) = encrypted_file.read(&mut buffer) {
        if bytes_read == 0 {
            break;
        }

        cipher.apply_keystream(&mut buffer[..bytes_read]);
        decrypted_file.write_all(&buffer[..bytes_read])?;
    }

    println!("File decrypted successfully! Output: 'example_dec.txt'");
    Ok(())
}
