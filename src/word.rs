pub trait Word: 
Clone 
+ Copy
+ std::ops::AddAssign 
+ std::cmp::Eq 
+ std::ops::Add<Output=Self> 
+ std::ops::SubAssign
+ std::ops::Sub<Output = Self>
+ std::ops::BitXor<Output = Self> 
+ std::ops::Shl<Output = Self>
+ std::ops::Shr<Output = Self>
+ std::ops::BitOr<Output = Self>
+ std::ops::BitAnd<Output = Self>{
    const ZERO: Self;
    // P = Odd((e - 2) * 2^8) = 0xB7 (183 decimal)
    const P: Self;
    // Q = Odd((φ - 1) * 2^8) = 0x9E (158 decimal)
    const Q: Self;

    const BYTES: usize;

    fn rotl(self, shift: Self) -> Self {
        let bits =Self::BYTES*8;
        let w_shift_modulus: Self =Self::from_usize(bits);
        let shift_mod = shift &  Self::from_usize(bits-1);
        if shift_mod == Self::ZERO {
            return self;
        }
        (self << shift_mod) | (self >> w_shift_modulus.wrap_sub(shift_mod))
    }

    fn rotr(self, shift: Self) -> Self {
        let bits: usize =Self::BYTES*8;
        let w_shift_modulus: Self =Self::from_usize(bits);
        let shift_mod = shift &  Self::from_usize(bits-1);
        if shift_mod == Self::ZERO {
            return self;
        }
        (self >> shift_mod) | (self << w_shift_modulus.wrap_sub(shift_mod))
    }

    fn wrap_add(self, rhs: Self) -> Self;
    fn wrap_sub(self, rhs: Self) -> Self;

    fn from_u8(val: u8)-> Self;
    fn from_usize(val: usize)-> Self;

    /// Left shift with overflow allowed (bits shifted out = 0)
    /// If shift >= bit_width, returns ZERO

    fn overflow_shl(self, shift: Self) -> Self {
        // Use checked_shl which returns None if shift >= 8
        // Convert None to ZERO (all bits shifted out)
        let bits: usize =Self::BYTES*8;
        let shift_mod = shift &  Self::from_usize(bits-1);
        if (shift != Self::ZERO) && (shift_mod!=shift) {
            return Self::ZERO
        }
        else {
            return self << shift;
        }
        //self.checked_shl(shift).unwrap_or(Self::ZERO)
    }}

impl Word for u8 {
    const ZERO: Self = 0u8;
    const P: Self = 0xB7;
    const Q: Self = 0x9E;

    const BYTES: usize = 1usize;
    fn wrap_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
    fn from_u8(val: u8)-> Self{
        val
    }
    fn from_usize(val: usize)-> Self{
        val as u8
    }
}

impl Word for u16 {
    const ZERO: Self = 0u16;
    const P: Self = 0xB7E1;
    const Q: Self = 0x9E37;

    const BYTES: usize = 2usize;
    fn wrap_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
    fn from_u8(val: u8)-> Self{
        val as u16
    }
    fn from_usize(val: usize)-> Self{
        val as u16
    }
}


impl Word for u32 {
    const ZERO: Self = 0u32;
    const P: Self = 0xB7E15163;
    const Q: Self = 0x9E3779B9;

    const BYTES: usize = 4usize;
    fn wrap_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
    fn from_u8(val: u8)-> Self{
        val as u32
    }
    fn from_usize(val: usize)-> Self{
        val as u32
    }
}

impl Word for u64 {
    const ZERO: Self = 0u64;
    const P: Self = 0xB7E151628AED2A6B;
    const Q: Self = 0x9E3779B97F4A7C15;

    const BYTES: usize = 8usize;
    fn wrap_add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    fn wrap_sub(self, rhs: Self) -> Self {
        self.wrapping_sub(rhs)
    }
    fn from_u8(val: u8)-> Self{
        val as u64
    }
    fn from_usize(val: usize)-> Self{
        val as u64
    }
}
