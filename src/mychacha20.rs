pub trait ChaCha20 {
    fn new(key: &[u8], nonce: &[u8]) -> Self;
    fn apply_keystream(&mut self, input: &mut [u8]);
    fn seek(&mut self, pos: u32);
}

pub struct ChaCha20Impl {
    state: [u32; 16],
}

const _SIGMA: &str = "expand 32-byte k";
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

impl ChaCha20Impl {
    fn quarter_round(&mut self, a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[a] ^ state[d]).rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] = (state[a] ^ state[d]).rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] = (state[b] ^ state[c]).rotate_left(7);
    }

    fn generate_keystream(&mut self) -> [u8; 64] {
        let mut state = self.state.clone();
        
        for _ in 0..10 {
            // column rounds
            self.quarter_round(0, 4, 8, 12, &mut state);
            self.quarter_round(1, 5, 9, 13, &mut state);
            self.quarter_round(2, 6, 10, 14, &mut state);
            self.quarter_round(3, 7, 11, 15, &mut state);

            // diagonal rounds
            self.quarter_round(0, 5, 10, 15, &mut state);
            self.quarter_round(1, 6, 11, 12, &mut state);
            self.quarter_round(2, 7, 8, 13, &mut state);
            self.quarter_round(3, 4, 9, 14, &mut state);
        }

        for (s1, s0) in state.iter_mut().zip(self.state.iter()) {
            *s1 = s1.wrapping_add(*s0);
        }

        let mut keystream = [0u8; 64];
        keystream.copy_from_slice(&state[0..16].iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>());

        keystream
    }
}

impl ChaCha20 for ChaCha20Impl {
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        if key.len() != 32 {
            panic!("Key must be 256 bits (8 u32 values)");
        }
        if nonce.len() != 12 {
            panic!("Nonce must be 96 bits (3 u32 values)");
        }
        
        let mut new_key = [0u32; 8];
        let mut new_nonce = [0u32; 3];
        
        let key_chunks = key.chunks_exact(4);
        for (i, chunk) in key_chunks.enumerate() {
            new_key[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let nonce_chunks = nonce.chunks_exact(4);
        for (i, chunk) in nonce_chunks.enumerate() {
            new_nonce[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let mut state = [0u32; 16];
        state[0..4].copy_from_slice(&CONSTANTS);
        state[4..12].copy_from_slice(&new_key);
        state[12] = 0;
        state[13..16].copy_from_slice(&new_nonce);
        
        ChaCha20Impl {
            state,
        }
    }

    fn apply_keystream(&mut self, input: &mut [u8]) {
        let mut keystream: [u8; 64] = [0; 64];
        for i in 0..input.len() {
            if i % 64 == 0 {
                keystream = self.generate_keystream();
                self.state[12] = self.state[12].wrapping_add(1);
            }
            input[i] ^= keystream[i % 64 as usize];
        }
    }

    fn seek(&mut self, pos: u32) {
        self.state[12] = pos;
    }
}

