use crate::rc5::RC5;
use crate::word::Word;
use std::path::Path;

pub struct RC5CBC<W: Word> {
    cipher: RC5<W>,
    iv: [W; 2],
}

impl<W: Word> RC5CBC<W> {
    pub fn new(cipher: RC5<W>, iv: [W; 2]) -> Self {
        todo!()
    }

    pub fn pad(&self, plaintext: &[[W; 2]]) -> Vec<[W;2]> {
        todo!()
    }
    /// Encrypt a sequence of plaintext blocks in CBC mode.
    /// C[i] = Encrypt(P[i] XOR C[i-1]),  where C[-1] = IV
    pub fn encrypt(&self, plaintext: &[[W; 2]]) -> Vec<[W; 2]> {
        todo!()
    }

    /// Decrypt a sequence of ciphertext blocks in CBC mode.
    /// P[i] = Decrypt(C[i]) XOR C[i-1],  where C[-1] = IV
    pub fn decrypt(&self, ciphertext: &[[W; 2]]) -> Vec<[W; 2]> {
        todo!()
    }

    /// Read a file and return its contents as a vector of word blocks.
    /// The caller is responsible for padding before encryption.
    pub fn read_file(&self, path: &Path) -> Vec<[W; 2]> {
        todo!()
    }

    /// Write a vector of word blocks to a file as raw bytes.
    pub fn write_file(&self, path: &Path, blocks: &[[W; 2]]) {
        todo!()
    }
}
