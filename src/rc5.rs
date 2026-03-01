/// RC5 block cipher
/// Parameters: w (word size), r (rounds), b (key length)
pub struct RC5<W: Word> {
    key_size: usize, //bytes
    // Number of rounds
    rounds: usize,
    // Expanded key table: 2*(rounds+1) words
    s: Vec<W>,

}

pub trait Word: 
Clone 
+ Copy
+ std::ops::AddAssign 
+ std::ops::Add<Output=Self> 
+ std::ops::SubAssign
+ std::ops::Sub<Output = Self>
+ std::ops::BitXor<Output = Self> 
+ std::ops::Shl<Output = Self>
+ std::ops::Shr<Output = Self>{
    const ZERO: Self;
    const P: Self;
    const Q: Self;

    const BYTES: usize;

    fn from_u8(val: u8)-> Self;
}
impl<W: Word> RC5<W> {
      /// Create new RC5 instance (key not yet set)
    pub fn new(key_length: usize, rounds: usize) -> Self {
        let t = 2 * (rounds + 1);
        RC5 {
            key_size: key_length,
            rounds,
            s: vec![W::ZERO; t],
        }
    }

    pub fn set_key(&mut self, key: &[u8]) {
        assert_eq!(self.key_size, key.len(), "The submitted key should be of size: {} bytes", self.key_size);
        self.expand_key(key);
    }

    /// Generate random key and expand it
    pub fn key_gen(&mut self) {
        let mut key: Vec<u8> = vec![0u8; self.key_size];
        for key_element in key.iter_mut() {
            *key_element = rand::random::<u8>();
        }
        self.expand_key(&key);
    }


    /// Encrypt a two-word block (A, B)
    /// A = A + S[0]
    /// B = B + S[1]
    /// for i = [1 to r+1);
    ///     A = ((A^B) << B) + S[2*i]
    ///     B = ((B^A) << A) + S[2*i +1]
    pub fn encrypt(&self, plaintext: [W;2]) -> [W;2] {
        assert_ne!(self.s.len(), 0, "The key is not initialized. Run KeyGen first.");
        let [mut a, mut b] = plaintext;
        a += self.s[0];
        b += self.s[1];
        for i in 1..=self.rounds {
            a = ((a ^ b) << b) + self.s[2*i];
            b = ((b ^ a) << a) + self.s[2*i + 1];
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
        assert_ne!(self.s.len(), 0, "The key is not initialized. Run KeyGen first.");
        let [mut a, mut b] = ciphertext;
        for i in (1..(self.rounds+1)).rev() {           
            b = ((b - self.s[2*i + 1]) >> a) ^ a;
            a = ((a - self.s[2*i]) >> b) ^ b;
        }
        b -= self.s[1];
        a -= self.s[0];
        [a, b]
    }

    /// Key expansion - converts user key to round subkeys
    fn expand_key(&mut self, key: &[u8]) {
        assert_eq!(key.len(), self.key_size, "The submitted key should be of size: {} bytes", self.key_size);
        //1. Transform the original key in an array of words L from array of bytes (u8) -> array of words (u8/u16/u32/u64/u128)
        let b: usize = key.len();
        let w = W::BYTES;
        //ceil(b/w) = (b + (w-1)) / w
        let tmp = (b + w-1)/w;
        let c = tmp.max(1);
        let mut key_l =vec![W::ZERO; c];
        for i in (0..b).rev() {
            let ix = i/w; 
            key_l[ix] = (key_l[ix] << W::from_u8(8u8)) + W::from_u8(key[i]);

        }
        //2. Initialize expanded key table S
        self.s[0]=W::P;
        for i in 1..(self.s.len()){
            self.s[i] = self.s[i-1] + W::Q;
        }
        //3. Mix the key_l (vector of words) with s
        let (mut i, mut j, mut a, mut b) = (0usize, 0usize, W::ZERO, W::ZERO);
        let iters = 3 * self.s.len().max(c);
        for _ in 0..iters {
            self.s[i] = (self.s[i] + a + b) << W::from_u8(3u8);
            a = self.s[i];
            key_l[j] = (key_l[j] + a + b) <<(a+b);
            b = key_l[j];
            i = (i+1)% self.s.len();
            j = (j+1) % c;
        }
    }
}
