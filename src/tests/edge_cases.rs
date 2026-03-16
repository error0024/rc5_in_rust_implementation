/// Tests for edge cases and special scenarios
use crate::rc5::RC5;

#[test]
fn test_zero_key() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0x00; 16];
    rc5.set_key(&key);

    let plaintext = [0x12u8, 0x34u8];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "Zero key should still work correctly");
}

#[test]
fn test_all_ones_plaintext() {
    let mut rc5 = RC5::<u8>::new(8, 12);
    let key = [0xAA; 8];
    rc5.set_key(&key);

    let plaintext = [0xFFu8, 0xFFu8];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "All ones plaintext should roundtrip");
}

#[test]
fn test_different_rounds() {
    let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let plaintext = [0xABu8, 0xCDu8];

    // Test with different number of rounds
    for rounds in [0, 1, 8, 12, 16, 20].iter() {
        let mut rc5 = RC5::<u8>::new(8, *rounds);
        rc5.set_key(&key);

        let ciphertext = rc5.encrypt(plaintext);
        let decrypted = rc5.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted,
            "Roundtrip failed for {} rounds", rounds);
    }
}

// --- u16 tests ---

#[test]
fn test_u16_zero_key() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0x00; 16];
    rc5.set_key(&key);

    let plaintext = [0x1234u16, 0x5678u16];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "Zero key should still work correctly for u16");
}

#[test]
fn test_u16_all_ones_plaintext() {
    let mut rc5 = RC5::<u16>::new(8, 12);
    let key = [0xAA; 8];
    rc5.set_key(&key);

    let plaintext = [0xFFFFu16, 0xFFFFu16];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "All-ones plaintext should roundtrip for u16");
}

#[test]
fn test_u16_different_rounds() {
    let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let plaintext = [0xABCDu16, 0xEF01u16];

    for rounds in [0, 1, 8, 12, 16, 20].iter() {
        let mut rc5 = RC5::<u16>::new(8, *rounds);
        rc5.set_key(&key);

        let ciphertext = rc5.encrypt(plaintext);
        let decrypted = rc5.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted,
            "u16 roundtrip failed for {} rounds", rounds);
    }
}

// --- u32 tests ---

#[test]
fn test_u32_zero_key() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0x00; 16];
    rc5.set_key(&key);

    let plaintext = [0x12345678u32, 0x9ABCDEF0u32];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "Zero key should still work correctly for u32");
}

#[test]
fn test_u32_all_ones_plaintext() {
    let mut rc5 = RC5::<u32>::new(8, 12);
    let key = [0xAA; 8];
    rc5.set_key(&key);

    let plaintext = [0xFFFFFFFFu32, 0xFFFFFFFFu32];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "All-ones plaintext should roundtrip for u32");
}

#[test]
fn test_u32_different_rounds() {
    let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let plaintext = [0xDEADBEEFu32, 0xCAFEBABEu32];

    for rounds in [0, 1, 8, 12, 16, 20].iter() {
        let mut rc5 = RC5::<u32>::new(8, *rounds);
        rc5.set_key(&key);

        let ciphertext = rc5.encrypt(plaintext);
        let decrypted = rc5.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted,
            "u32 roundtrip failed for {} rounds", rounds);
    }
}

// --- u64 tests ---

#[test]
fn test_u64_zero_key() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0x00; 16];
    rc5.set_key(&key);

    let plaintext = [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "Zero key should still work correctly for u64");
}

#[test]
fn test_u64_all_ones_plaintext() {
    let mut rc5 = RC5::<u64>::new(8, 12);
    let key = [0xAA; 8];
    rc5.set_key(&key);

    let plaintext = [0xFFFFFFFFFFFFFFFFu64, 0xFFFFFFFFFFFFFFFFu64];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "All-ones plaintext should roundtrip for u64");
}

#[test]
fn test_u64_different_rounds() {
    let key = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let plaintext = [0xDEADBEEFCAFEBABEu64, 0x0102030405060708u64];

    for rounds in [0, 1, 8, 12, 16, 20].iter() {
        let mut rc5 = RC5::<u64>::new(8, *rounds);
        rc5.set_key(&key);

        let ciphertext = rc5.encrypt(plaintext);
        let decrypted = rc5.decrypt(ciphertext);

        assert_eq!(plaintext, decrypted,
            "u64 roundtrip failed for {} rounds", rounds);
    }
}
