use crate::rc5::RC5;
use crate::word::{Word, bytes_to_word, word_to_bytes};
use std::fs;
use std::path::Path;

pub struct RC5CBC<W: Word> {
    cipher: RC5<W>,
    iv: [W; 2],
}

impl<W: Word> RC5CBC<W> {
    pub fn new(cipher: RC5<W>) -> Self {
        Self {
          cipher,
          iv: [Self::random_word(), Self::random_word()],
      }
    }

    pub fn pad(&self, input: &mut Vec<u8>) {
        let chunk = W::BYTES * 2;
        let iterations = (input.len() + (chunk-1))/chunk ;
        input.extend(vec![0u8; iterations*chunk - input.len()]);
    }

    pub fn unpad(&self, input: &mut Vec<u8>) {
      while input.last() == Some(&0u8) {
          input.pop();
      }
  }
    /// Encrypt a sequence of plaintext blocks in CBC mode.
    /// C[i] = Encrypt(P[i] XOR C[i-1]),  where C[-1] = IV
    pub fn encrypt(&self, plaintext: &[[W; 2]]) -> Vec<[W; 2]> {
        let iterations = plaintext.len();
        let mut ciphertext: Vec<[W; 2]> = Vec::new();
        ciphertext.push(self.iv);
        for i in 0..iterations {
            ciphertext.push(self.cipher.encrypt( Self::xor_blocks(plaintext[i], ciphertext[i]) ));
        }
        ciphertext
    }

    /// Decrypt a sequence of ciphertext blocks in CBC mode.
    /// P[i] = Decrypt(C[i]) XOR C[i-1],  where C[-1] = IV
    pub fn decrypt(&self, ciphertext: &[[W; 2]]) -> Vec<[W; 2]> {
        let iterations = ciphertext.len();
        let mut plaintext: Vec<[W; 2]> = Vec::new();
        for i in 1..iterations {
            plaintext.push(Self::xor_blocks(self.cipher.decrypt( ciphertext[i]), ciphertext[i-1]) );
        }
        plaintext
    }

    /// Read a file and return its contents as a vector of word blocks.
    /// The caller is responsible for padding before encryption.
    pub fn read_plaintext(&self, path: &Path) -> Vec<[W; 2]> {
        let mut input = fs::read(path).expect(&format!("File {} couldn't be read", path.display()));
        self.pad(&mut input);
        let blocks_input = Self::bytes_to_blocks(&input);
        blocks_input
    }

    pub fn read_ciphertext(&self, path: &Path) -> Vec<[W; 2]> {
        let  input = fs::read(path).expect(&format!("File {} couldn't be read", path.display()));
        let blocks_input = Self::bytes_to_blocks(&input);
        blocks_input
    }

    /// Write a vector of word blocks to a file as raw bytes.
    pub fn write_ciphertext(&self, path: &Path, blocks: &[[W; 2]]) {
        let output = Self::blocks_to_bytes(blocks);
        fs::write(path, output).expect(&format!("File {} couldn't be written", path.display()));
    }

    pub fn write_plaintext(&self, path: &Path, blocks: &[[W; 2]]) {
        let mut output = Self::blocks_to_bytes(blocks);
        self.unpad(&mut output);
        fs::write(path, output).expect(&format!("File {} couldn't be written", path.display()));
    }

    fn random_word() -> W {
        let bytes: Vec<u8> = (0..W::BYTES).map(|_| rand::random::<u8>()).collect();
        let mut word = W::ZERO;
        for i in bytes {
            word = word.overflow_shl(W::from_u8(8u8)).wrap_add(W::from_u8(i));
        }
        word
    }

    fn bytes_to_blocks(bytes: &[u8]) -> Vec<[W; 2]> {
        let block_size = 2 * W::BYTES;
        bytes.chunks(2 * W::BYTES).map(|chunk| {
            [bytes_to_word::<W>(&chunk[0..W::BYTES]),
            bytes_to_word::<W>(&chunk[W::BYTES..])]
        }).collect()
    }

    fn blocks_to_bytes(blocks: &[[W; 2]]) -> Vec<u8> {
      blocks.iter().flat_map(|[a, b]| {
          word_to_bytes::<W>(*a).into_iter().chain(word_to_bytes::<W>(*b))
      }).collect()
    }
    
    fn xor_blocks(a: [W; 2], b: [W; 2]) -> [W; 2] {
      [a[0] ^ b[0], a[1] ^ b[1]]
    }

}
