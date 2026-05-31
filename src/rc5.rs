use crate::word::Word;

/// RC5 block cipher
/// Parameters: w (word size), r (rounds), b (key length)
pub struct RC5<W: Word> {
    key_size: usize, //bytes
    // Number of rounds
    rounds: usize,
    // Unexpanded key bytes
    pub(crate) key: Vec<u8>,
    // Expanded key table: 2*(rounds+1) words
    pub(crate) s: Vec<W>,
}



impl<W: Word> RC5<W> {
      /// Create new RC5 instance (key not yet set)
    pub fn new(key_length: usize, rounds: usize) -> Self {
        let t = 2 * (rounds + 1);
        RC5 {
            key_size: key_length,
            rounds,
            key: Vec::new(),
            s: vec![W::ZERO; t],
        }
    }

    pub fn set_key(&mut self, key: &[u8]) {
        assert_eq!(self.key_size, key.len(), "The submitted key should be of size: {} bytes", self.key_size);
        self.key = key.to_vec();
        self.expand_key(key);
    }

    /// Generate random key and expand it
    pub fn key_gen(&mut self) {
        self.key = (0..self.key_size).map(|_| rand::random::<u8>()).collect();
        self.expand_key(&self.key.clone());
    }

    pub fn get_key(&self) -> &[u8] {
        &self.key
    }

    pub fn get_key_length(&self) -> usize {
        self.key_size
    }

    pub fn get_rounds(&self) -> usize {
        self.rounds
    }

    /// Encrypt a two-word block (A, B)
    /// A = A + S[0]
    /// B = B + S[1]
    /// for i = [1 to r+1);
    ///     A = ((A^B) << B) + S[2*i]
    ///     B = ((B^A) << A) + S[2*i +1]
    pub fn encrypt(&self, plaintext: [W;2]) -> [W;2] {
        assert!(!self.s.iter().all(|&x| x == W::ZERO), "The Key is not initialized. Run key_gen.");
        let [mut a, mut b] = plaintext;
        a = a.wrap_add(self.s[0]);
        b = b.wrap_add(self.s[1]);
        for i in 1..=self.rounds {
            a = (a ^ b).rotl(b).wrap_add(self.s[2*i]);
            b = (b ^ a).rotl(a).wrap_add(self.s[2*i + 1]);
        }
        [a, b]
    }

    /// Decrypt a two-word block (A, B)
    /// 
    /// for i = [r+1 to 1);
    ///     B = ((B - S[2*i +1]) >> A) ^ A
    ///     A = ((A - S[2*i]) >> B) ^ B
    /// B = B - S[1]
    /// A = A - S[0] 
    pub fn decrypt(&self, ciphertext: [W;2]) -> [W;2] {
        assert!(!self.s.iter().all(|&x| x == W::ZERO), "The Key is not initialized. Run set_key.");
        let [mut a, mut b] = ciphertext;
        for i in (1..(self.rounds+1)).rev() {           
            b = b.wrap_sub(self.s[2*i + 1]).rotr(a) ^ a;
            a = a.wrap_sub(self.s[2*i]).rotr(b) ^ b;
        }
        b = b.wrap_sub(self.s[1]);
        a = a.wrap_sub(self.s[0]);
        [a, b]
    }

    /// Generate key_l array from byte key
    /// This is step 1 of key expansion: Transform the original key into an array of words
    pub(crate) fn generate_key_l(key: &[u8]) -> Vec<W> {
        let b: usize = key.len();
        let w = W::BYTES;
        //ceil(b/w) = (b + (w-1)) / w
        let tmp = (b + w-1)/w;
        let c = tmp.max(1);
        let mut key_l =vec![W::ZERO; c];
        for i in (0..b).rev() {
            let ix = i/w;
            key_l[ix] = key_l[ix].overflow_shl(W::from_u8(8u8)).wrap_add(W::from_u8(key[i]));
        }
        key_l
    }

    /// Key expansion - converts user key to round subkeys
    fn expand_key(&mut self, key: &[u8]) {
        assert_eq!(key.len(), self.key_size, "The submitted key should be of size: {} bytes", self.key_size);
        //1. Transform the original key in an array of words L from array of bytes (u8) -> array of words (u8/u16/u32/u64/u128)
        let mut key_l = Self::generate_key_l(key);
        //2. Initialize expanded key table S
        self.s[0]=W::P;
        for i in 1..(self.s.len()){
            self.s[i] = self.s[i-1].wrap_add(W::Q);
        }
        //3. Mix the key_l (vector of words) with s
        let (mut i, mut j, mut a, mut b) = (0usize, 0usize, W::ZERO, W::ZERO);
        let c = key_l.len();
        let iters = 3 * self.s.len().max(c);
        for _ in 0..iters {
            self.s[i] = self.s[i].wrap_add(a).wrap_add(b).rotl(W::from_u8(3u8));
            a = self.s[i];
            key_l[j] = key_l[j].wrap_add(a).wrap_add(b).rotl(a.wrap_add(b));
            b = key_l[j];
            i = (i+1)% self.s.len();
            j = (j+1) % c;
        }
    }
}
