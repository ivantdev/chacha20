use rand::RngCore;
use rand::thread_rng;

pub trait ChaCha20 {
    fn new(key: &[u32], nonce: &[u32]) -> Self;
    fn apply_keystream(&mut self, input: &[u8]) -> Vec<u8>;
    fn seek(&mut self, pos: u32);
}

pub struct ChaCha20Impl {
    key: [u32; 8],    // 256 bits / 32 bits per u32 = 8 u32 values
    nonce: [u32; 3],  // 96 bits / 32 bits per u32 = 3 u32 values
    counter: u32,
    state: [u32; 16],
}

pub fn gen_rdm_u32(size: usize) -> Vec<u32> {
    let mut rng = thread_rng();
    let mut nonce = vec![0u32; size];
    let mut byte_nonce = vec![0u8; size * 4]; // u32 = 4 bytes
    rng.fill_bytes(&mut byte_nonce);
    
    for i in 0..size {
        nonce[i] = u32::from_le_bytes([
            byte_nonce[i * 4], 
            byte_nonce[i * 4 + 1], 
            byte_nonce[i * 4 + 2], 
            byte_nonce[i * 4 + 3]
        ]);
    }

    nonce
}

pub fn u8_to_u32(s: &[u8]) -> Vec<u32> {
    if s.len() % 4 != 0 {
        panic!("Input length must be a multiple of 4");
    }
    let mut u32_array = vec![0u32; s.len() / 4];
    for i in 0..s.len() / 4 {
        u32_array[i] = u32::from_le_bytes([
            s[i * 4 + 3],
            s[i * 4 + 2],
            s[i * 4 + 1],
            s[i * 4],
        ]);
    }
    u32_array
}

const SIGMA: &str = "expand 32-byte k";

impl ChaCha20Impl {
    fn create_state(&mut self) {
        self.state[0..4].copy_from_slice(&u8_to_u32(SIGMA.as_bytes()));
        self.state[4..12].copy_from_slice(&self.key);
        self.state[12] = self.counter;
        self.state[13..16].copy_from_slice(&self.nonce);
    }

    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize) {
        let state = &mut self.state;
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[a] ^ state[d]).rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[a] ^ state[d]).rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    fn generate_keystream(&mut self) -> [u32; 16] {
        self.create_state();
        
        for _ in 0..10 {
            // column rounds
            self.quarter_round(0, 1, 2, 3);
            self.quarter_round(4, 5, 6, 7);
            self.quarter_round(8, 9, 10, 11);
            self.quarter_round(12, 13, 14, 15);

            // diagonal rounds
            self.quarter_round(0, 5, 10, 15);
            self.quarter_round(1, 6, 11, 12);
            self.quarter_round(2, 7, 8, 13);
            self.quarter_round(3, 4, 9, 14);
        }

        self.state
    }
}

impl ChaCha20 for ChaCha20Impl {
    fn new(key: &[u32], nonce: &[u32]) -> Self {
        if key.len() != 8 {
            panic!("Key must be 256 bits (8 u32 values)");
        }
        if nonce.len() != 3 {
            panic!("Nonce must be 96 bits (3 u32 values)");
        }
        
        let mut new_key = [0u32; 8];
        let mut new_nonce = [0u32; 3];
        
        new_key.copy_from_slice(&key[..8]);
        new_nonce.copy_from_slice(&nonce[..3]);
        
        ChaCha20Impl {
            key: new_key,
            nonce: new_nonce,
            counter: 0,
            state: [0u32; 16],
        }
    }

    fn apply_keystream(&mut self, input: &[u8]) -> Vec<u8> {
        let mut input_chunks = input.chunks_exact(64);
        let mut output: Vec<u8> = Vec::new();

        while let Some(chunk) = input_chunks.next() {
            let keystream = self.generate_keystream();
            for i in 0..16 {
                let keystream_u8 = keystream[i].to_le_bytes();
                for j in 0..4 {
                    output.push(keystream_u8[j] ^ chunk[i * 4 + j]);
                }
            }
            self.counter += 1;
        }

        let remaining = input_chunks.remainder();
        if !remaining.is_empty() {
            let mut remaining_padded = Vec::new();
            remaining_padded.extend_from_slice(remaining);
            let extra = remaining.len() % 4;
            for _ in 0..4 - extra {
                remaining_padded.push(0);
            }

            // encrypt the remaining padded bytes
            let keystream = self.generate_keystream();
            for i in 0..remaining_padded.len() / 4 {
                let keystream_u8 = keystream[i].to_le_bytes();
                for j in 0..4 {
                    output.push(keystream_u8[j] ^ remaining_padded[i * 4 + j]);
                }
            }
            output.truncate(input.len());
            self.counter += 1;
        }

        output
    }

    fn seek(&mut self, pos: u32) {
        self.counter = pos;
    }
}

