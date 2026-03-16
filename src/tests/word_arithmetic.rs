/// Tests for wrapping addition and subtraction on Word types (u8, u16)
use crate::rc5::Word;

#[test]
fn test_add_no_overflow() {
    let a: u8 = 10u8;
    let b: u8 = 20u8;
    assert_eq!(a.wrap_add(b), 30u8);
}

#[test]
fn test_add_overflow_wraps() {
    let a: u8 = 200u8;
    let b: u8 = 100u8;
    assert_eq!(a.wrap_add(b), 44u8); // 300 % 256 = 44
}

#[test]
fn test_add_overflow_max_plus_one() {
    let a: u8 = 255u8;
    let b: u8 = 1u8;
    assert_eq!(a.wrap_add(b), 0u8);
}

#[test]
fn test_add_overflow_max_plus_max() {
    let a: u8 = 255u8;
    let b: u8 = 255u8;
    assert_eq!(a.wrap_add(b), 254u8); // 510 % 256 = 254
}

#[test]
fn test_add_identity() {
    let a: u8 = 42u8;
    assert_eq!(a.wrap_add(0u8), a);
}

#[test]
fn test_sub_no_underflow() {
    let a: u8 = 50u8;
    let b: u8 = 20u8;
    assert_eq!(a.wrap_sub(b), 30u8);
}

#[test]
fn test_sub_underflow_wraps() {
    let a: u8 = 10u8;
    let b: u8 = 20u8;
    assert_eq!(a.wrap_sub(b), 246u8); // (10 - 20 + 256) % 256 = 246
}

#[test]
fn test_sub_underflow_zero_minus_one() {
    let a: u8 = 0u8;
    let b: u8 = 1u8;
    assert_eq!(a.wrap_sub(b), 255u8);
}

#[test]
fn test_sub_underflow_zero_minus_max() {
    let a: u8 = 0u8;
    let b: u8 = 255u8;
    assert_eq!(a.wrap_sub(b), 1u8); // (0 - 255 + 256) = 1
}

#[test]
fn test_sub_identity() {
    let a: u8 = 42u8;
    assert_eq!(a.wrap_sub(0u8), a);
}

#[test]
fn test_sub_self() {
    let a: u8 = 42u8;
    assert_eq!(a.wrap_sub(a), 0u8);
}

#[test]
fn test_add_sub_roundtrip() {
    let a: u8 = 200u8;
    let b: u8 = 100u8;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

#[test]
fn test_add_sub_roundtrip_with_overflow() {
    let a: u8 = 255u8;
    let b: u8 = 128u8;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

// --- u16 tests ---

#[test]
fn test_u16_add_no_overflow() {
    let a: u16 = 1000u16;
    let b: u16 = 2000u16;
    assert_eq!(a.wrap_add(b), 3000u16);
}

#[test]
fn test_u16_add_overflow_wraps() {
    let a: u16 = 60000u16;
    let b: u16 = 10000u16;
    assert_eq!(a.wrap_add(b), 4464u16); // 70000 % 65536 = 4464
}

#[test]
fn test_u16_add_overflow_max_plus_one() {
    let a: u16 = 65535u16;
    let b: u16 = 1u16;
    assert_eq!(a.wrap_add(b), 0u16);
}

#[test]
fn test_u16_add_overflow_max_plus_max() {
    let a: u16 = 65535u16;
    let b: u16 = 65535u16;
    assert_eq!(a.wrap_add(b), 65534u16); // 131070 % 65536 = 65534
}

#[test]
fn test_u16_add_identity() {
    let a: u16 = 1234u16;
    assert_eq!(a.wrap_add(0u16), a);
}

#[test]
fn test_u16_sub_no_underflow() {
    let a: u16 = 5000u16;
    let b: u16 = 2000u16;
    assert_eq!(a.wrap_sub(b), 3000u16);
}

#[test]
fn test_u16_sub_underflow_wraps() {
    let a: u16 = 100u16;
    let b: u16 = 200u16;
    assert_eq!(a.wrap_sub(b), 65436u16); // (100 - 200 + 65536) = 65436
}

#[test]
fn test_u16_sub_underflow_zero_minus_one() {
    let a: u16 = 0u16;
    let b: u16 = 1u16;
    assert_eq!(a.wrap_sub(b), 65535u16);
}

#[test]
fn test_u16_sub_underflow_zero_minus_max() {
    let a: u16 = 0u16;
    let b: u16 = 65535u16;
    assert_eq!(a.wrap_sub(b), 1u16); // (0 - 65535 + 65536) = 1
}

#[test]
fn test_u16_sub_identity() {
    let a: u16 = 1234u16;
    assert_eq!(a.wrap_sub(0u16), a);
}

#[test]
fn test_u16_sub_self() {
    let a: u16 = 1234u16;
    assert_eq!(a.wrap_sub(a), 0u16);
}

#[test]
fn test_u16_add_sub_roundtrip() {
    let a: u16 = 50000u16;
    let b: u16 = 20000u16;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

#[test]
fn test_u16_add_sub_roundtrip_with_overflow() {
    let a: u16 = 65535u16;
    let b: u16 = 32768u16;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

// --- u32 tests ---

#[test]
fn test_u32_add_no_overflow() {
    let a: u32 = 100_000u32;
    let b: u32 = 200_000u32;
    assert_eq!(a.wrap_add(b), 300_000u32);
}

#[test]
fn test_u32_add_overflow_wraps() {
    let a: u32 = 4_000_000_000u32;
    let b: u32 = 1_000_000_000u32;
    assert_eq!(a.wrap_add(b), 705_032_704u32); // 5_000_000_000 % 2^32
}

#[test]
fn test_u32_add_overflow_max_plus_one() {
    assert_eq!(u32::MAX.wrap_add(1u32), 0u32);
}

#[test]
fn test_u32_add_overflow_max_plus_max() {
    assert_eq!(u32::MAX.wrap_add(u32::MAX), u32::MAX - 1);
}

#[test]
fn test_u32_add_identity() {
    let a: u32 = 123_456u32;
    assert_eq!(a.wrap_add(0u32), a);
}

#[test]
fn test_u32_sub_no_underflow() {
    let a: u32 = 500_000u32;
    let b: u32 = 200_000u32;
    assert_eq!(a.wrap_sub(b), 300_000u32);
}

#[test]
fn test_u32_sub_underflow_wraps() {
    let a: u32 = 100u32;
    let b: u32 = 200u32;
    assert_eq!(a.wrap_sub(b), 4_294_967_196u32); // 100 - 200 + 2^32
}

#[test]
fn test_u32_sub_underflow_zero_minus_one() {
    assert_eq!(0u32.wrap_sub(1u32), u32::MAX);
}

#[test]
fn test_u32_sub_underflow_zero_minus_max() {
    assert_eq!(0u32.wrap_sub(u32::MAX), 1u32);
}

#[test]
fn test_u32_sub_identity() {
    let a: u32 = 123_456u32;
    assert_eq!(a.wrap_sub(0u32), a);
}

#[test]
fn test_u32_sub_self() {
    let a: u32 = 123_456u32;
    assert_eq!(a.wrap_sub(a), 0u32);
}

#[test]
fn test_u32_add_sub_roundtrip() {
    let a: u32 = 3_000_000_000u32;
    let b: u32 = 1_500_000_000u32;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

#[test]
fn test_u32_add_sub_roundtrip_with_overflow() {
    assert_eq!(u32::MAX.wrap_add(u32::MAX / 2).wrap_sub(u32::MAX / 2), u32::MAX);
}

// --- u64 tests ---

#[test]
fn test_u64_add_no_overflow() {
    let a: u64 = 1_000_000_000_000u64;
    let b: u64 = 2_000_000_000_000u64;
    assert_eq!(a.wrap_add(b), 3_000_000_000_000u64);
}

#[test]
fn test_u64_add_overflow_wraps() {
    let a: u64 = u64::MAX - 100;
    let b: u64 = 200u64;
    assert_eq!(a.wrap_add(b), 99u64);
}

#[test]
fn test_u64_add_overflow_max_plus_one() {
    assert_eq!(u64::MAX.wrap_add(1u64), 0u64);
}

#[test]
fn test_u64_add_overflow_max_plus_max() {
    assert_eq!(u64::MAX.wrap_add(u64::MAX), u64::MAX - 1);
}

#[test]
fn test_u64_add_identity() {
    let a: u64 = 9_999_999_999_999u64;
    assert_eq!(a.wrap_add(0u64), a);
}

#[test]
fn test_u64_sub_no_underflow() {
    let a: u64 = 5_000_000_000u64;
    let b: u64 = 2_000_000_000u64;
    assert_eq!(a.wrap_sub(b), 3_000_000_000u64);
}

#[test]
fn test_u64_sub_underflow_wraps() {
    let a: u64 = 100u64;
    let b: u64 = 200u64;
    assert_eq!(a.wrap_sub(b), u64::MAX - 99); // 100 - 200 + 2^64
}

#[test]
fn test_u64_sub_underflow_zero_minus_one() {
    assert_eq!(0u64.wrap_sub(1u64), u64::MAX);
}

#[test]
fn test_u64_sub_underflow_zero_minus_max() {
    assert_eq!(0u64.wrap_sub(u64::MAX), 1u64);
}

#[test]
fn test_u64_sub_identity() {
    let a: u64 = 9_999_999_999_999u64;
    assert_eq!(a.wrap_sub(0u64), a);
}

#[test]
fn test_u64_sub_self() {
    let a: u64 = 9_999_999_999_999u64;
    assert_eq!(a.wrap_sub(a), 0u64);
}

#[test]
fn test_u64_add_sub_roundtrip() {
    let a: u64 = 10_000_000_000_000_000u64;
    let b: u64 = 9_000_000_000_000_000u64;
    assert_eq!(a.wrap_add(b).wrap_sub(b), a);
}

#[test]
fn test_u64_add_sub_roundtrip_with_overflow() {
    assert_eq!(u64::MAX.wrap_add(u64::MAX / 2).wrap_sub(u64::MAX / 2), u64::MAX);
}
