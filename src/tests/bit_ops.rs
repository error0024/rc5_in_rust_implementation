/// Tests for bitwise operations: rotations and shifts
use crate::rc5::Word;

#[test]
fn test_overflow_shl() {
    let a: u8 = 0x0Fu8; // 0000 1111
    // Normal shifts (< 8 bits)
    assert_eq!(a.overflow_shl(1u8), 0x1Eu8); // 0001 1110
    assert_eq!(a.overflow_shl(4u8), 0xF0u8); // 1111 0000
    // Shift by bit_width (all bits shifted out)
    assert_eq!(a.overflow_shl(8u8), 0x00u8); // All bits gone
    // Shift beyond bit_width (still returns 0)
    assert_eq!(a.overflow_shl(10u8), 0x00u8);
    assert_eq!(a.overflow_shl(255u8), 0x00u8);
    // Edge case: shift by 0
    assert_eq!(a.overflow_shl(0u8), a);
}

#[test]
fn test_rotl() {
    let a: u8 = 0x77u8; // 0111 0111
    assert_eq!(a.rotl(1u8), 0b1110_1110);
    assert_eq!(a.rotl(7u8), 0b1011_1011);
    assert_eq!(a.rotl(8u8), a); // full rotation = same
    // Test larger shifts (should wrap around)
    assert_eq!(a.rotl(15u8), a.rotl(7u8)); // 15 % 8 = 7
    assert_eq!(a.rotl(21u8), a.rotl(5u8)); // 21 % 8 = 5
    assert_eq!(a.rotl(32u8), a); // 32 % 8 = 0, no rotation
}

#[test]
fn test_rotr() {
    let a: u8 = 0x77u8; // 0111 0111
    assert_eq!(a.rotr(1u8), 0b1011_1011);
    assert_eq!(a.rotr(7u8), 0b1110_1110);
    assert_eq!(a.rotr(8u8), a); // full rotation = same
    // Test larger shifts (should wrap around)
    assert_eq!(a.rotr(15u8), a.rotr(7u8)); // 15 % 8 = 7
    assert_eq!(a.rotr(21u8), a.rotr(5u8)); // 21 % 8 = 5
    assert_eq!(a.rotr(32u8), a); // 32 % 8 = 0, no rotation
}

#[test]
fn test_rotl_rotr_roundtrip() {
    let a: u8 = 0x77u8;
    for shift in 0..=8u8 {
        assert_eq!(a.rotl(shift).rotr(shift), a);
    }
}

// --- u16 tests ---

#[test]
fn test_u16_overflow_shl() {
    let a: u16 = 0x00FFu16; // 0000 0000 1111 1111
    assert_eq!(a.overflow_shl(1u16), 0x01FEu16); // 0000 0001 1111 1110
    assert_eq!(a.overflow_shl(8u16), 0xFF00u16); // 1111 1111 0000 0000
    // Shift by bit_width (all bits shifted out)
    assert_eq!(a.overflow_shl(16u16), 0x0000u16);
    // Shift beyond bit_width
    assert_eq!(a.overflow_shl(20u16), 0x0000u16);
    // Edge case: shift by 0
    assert_eq!(a.overflow_shl(0u16), a);
}

#[test]
fn test_u16_rotl() {
    let a: u16 = 0x7777u16; // 0111 0111 0111 0111
    assert_eq!(a.rotl(1u16), 0xEEEEu16);  // 1110 1110 1110 1110
    assert_eq!(a.rotl(15u16), 0xBBBBu16); // 1011 1011 1011 1011
    assert_eq!(a.rotl(16u16), a);          // full rotation = same
    // Larger shifts wrap around
    assert_eq!(a.rotl(17u16), a.rotl(1u16)); // 17 % 16 = 1
    assert_eq!(a.rotl(32u16), a);            // 32 % 16 = 0
}

#[test]
fn test_u16_rotr() {
    let a: u16 = 0x7777u16; // 0111 0111 0111 0111
    assert_eq!(a.rotr(1u16), 0xBBBBu16);  // 1011 1011 1011 1011
    assert_eq!(a.rotr(15u16), 0xEEEEu16); // 1110 1110 1110 1110
    assert_eq!(a.rotr(16u16), a);          // full rotation = same
    // Larger shifts wrap around
    assert_eq!(a.rotr(17u16), a.rotr(1u16)); // 17 % 16 = 1
    assert_eq!(a.rotr(32u16), a);            // 32 % 16 = 0
}

#[test]
fn test_u16_rotl_rotr_roundtrip() {
    let a: u16 = 0x7777u16;
    for shift in 0..=16u16 {
        assert_eq!(a.rotl(shift).rotr(shift), a);
    }
}

// --- u32 tests ---

#[test]
fn test_u32_overflow_shl() {
    let a: u32 = 0x0FFFFFFFu32;
    assert_eq!(a.overflow_shl(1u32), 0x1FFFFFFEu32);
    assert_eq!(a.overflow_shl(4u32), 0xFFFFFFF0u32);
    assert_eq!(a.overflow_shl(32u32), 0x00000000u32);
    assert_eq!(a.overflow_shl(36u32), 0x00000000u32);
    assert_eq!(a.overflow_shl(0u32), a);
}

#[test]
fn test_u32_rotl() {
    let a: u32 = 0x77777777u32;
    assert_eq!(a.rotl(1u32), 0xEEEEEEEEu32);
    assert_eq!(a.rotl(31u32), 0xBBBBBBBBu32);
    assert_eq!(a.rotl(32u32), a);
    assert_eq!(a.rotl(33u32), a.rotl(1u32)); // 33 % 32 = 1
    assert_eq!(a.rotl(64u32), a);             // 64 % 32 = 0
}

#[test]
fn test_u32_rotr() {
    let a: u32 = 0x77777777u32;
    assert_eq!(a.rotr(1u32), 0xBBBBBBBBu32);
    assert_eq!(a.rotr(31u32), 0xEEEEEEEEu32);
    assert_eq!(a.rotr(32u32), a);
    assert_eq!(a.rotr(33u32), a.rotr(1u32)); // 33 % 32 = 1
    assert_eq!(a.rotr(64u32), a);             // 64 % 32 = 0
}

#[test]
fn test_u32_rotl_rotr_roundtrip() {
    let a: u32 = 0x77777777u32;
    for shift in 0..=32u32 {
        assert_eq!(a.rotl(shift).rotr(shift), a);
    }
}

// --- u64 tests ---

#[test]
fn test_u64_overflow_shl() {
    let a: u64 = 0x0FFFFFFFFFFFFFFFu64;
    assert_eq!(a.overflow_shl(1u64), 0x1FFFFFFFFFFFFFFEu64);
    assert_eq!(a.overflow_shl(4u64), 0xFFFFFFFFFFFFFFF0u64);
    assert_eq!(a.overflow_shl(64u64), 0x0000000000000000u64);
    assert_eq!(a.overflow_shl(68u64), 0x0000000000000000u64);
    assert_eq!(a.overflow_shl(0u64), a);
}

#[test]
fn test_u64_rotl() {
    let a: u64 = 0x7777777777777777u64;
    assert_eq!(a.rotl(1u64), 0xEEEEEEEEEEEEEEEEu64);
    assert_eq!(a.rotl(63u64), 0xBBBBBBBBBBBBBBBBu64);
    assert_eq!(a.rotl(64u64), a);
    assert_eq!(a.rotl(65u64), a.rotl(1u64)); // 65 % 64 = 1
    assert_eq!(a.rotl(128u64), a);            // 128 % 64 = 0
}

#[test]
fn test_u64_rotr() {
    let a: u64 = 0x7777777777777777u64;
    assert_eq!(a.rotr(1u64), 0xBBBBBBBBBBBBBBBBu64);
    assert_eq!(a.rotr(63u64), 0xEEEEEEEEEEEEEEEEu64);
    assert_eq!(a.rotr(64u64), a);
    assert_eq!(a.rotr(65u64), a.rotr(1u64)); // 65 % 64 = 1
    assert_eq!(a.rotr(128u64), a);            // 128 % 64 = 0
}

#[test]
fn test_u64_rotl_rotr_roundtrip() {
    let a: u64 = 0x7777777777777777u64;
    for shift in 0..=64u64 {
        assert_eq!(a.rotl(shift).rotr(shift), a);
    }
}
