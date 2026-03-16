/// Tests for encryption and decryption operations
use crate::rc5::RC5;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let plaintext = [0x42u8, 0x73u8];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted, "Decrypt(Encrypt(plaintext)) should equal plaintext");
}

#[test]
fn test_encrypt_decrypt_multiple_blocks() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    rc5.set_key(&key);

    let test_blocks = [
        [0x00u8, 0x00u8],
        [0xFFu8, 0xFFu8],
        [0xAAu8, 0x55u8],
        [0x12u8, 0x34u8],
        [0xDEu8, 0xADu8],
    ];

    for plaintext in test_blocks.iter() {
        let ciphertext = rc5.encrypt(*plaintext);
        let decrypted = rc5.decrypt(ciphertext);
        assert_eq!(*plaintext, decrypted,
            "Roundtrip failed for plaintext {:?}", plaintext);
    }
}

#[test]
fn test_deterministic_encryption() {
    let mut rc5 = RC5::<u8>::new(8, 12);
    let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    rc5.set_key(&key);

    let plaintext = [0xABu8, 0xCDu8];
    let ciphertext1 = rc5.encrypt(plaintext);
    let ciphertext2 = rc5.encrypt(plaintext);

    assert_eq!(ciphertext1, ciphertext2,
        "Same plaintext should produce same ciphertext");
}

#[test]
fn test_different_plaintexts_different_ciphertexts() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0xFF; 16];
    rc5.set_key(&key);

    let plaintext1 = [0x00u8, 0x00u8];
    let plaintext2 = [0x00u8, 0x01u8];

    let ciphertext1 = rc5.encrypt(plaintext1);
    let ciphertext2 = rc5.encrypt(plaintext2);

    assert_ne!(ciphertext1, ciphertext2,
        "Different plaintexts should produce different ciphertexts");
}

#[test]
fn test_different_keys_different_ciphertexts() {
    let plaintext = [0x42u8, 0x42u8];

    let mut rc5_1 = RC5::<u8>::new(8, 12);
    let key1 = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    rc5_1.set_key(&key1);

    let mut rc5_2 = RC5::<u8>::new(8, 12);
    let key2 = [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01];
    rc5_2.set_key(&key2);

    let ciphertext1 = rc5_1.encrypt(plaintext);
    let ciphertext2 = rc5_2.encrypt(plaintext);

    assert_ne!(ciphertext1, ciphertext2,
        "Different keys should produce different ciphertexts");
}

#[test]
fn test_ciphertext_different_from_plaintext() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0x01; 16];
    rc5.set_key(&key);

    let plaintext = [0x42u8, 0x73u8];
    let ciphertext = rc5.encrypt(plaintext);

    // With high probability, ciphertext should differ from plaintext
    // (it's theoretically possible but extremely unlikely they're equal)
    assert_ne!(plaintext, ciphertext,
        "Ciphertext should be different from plaintext");
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run key_gen.")]
fn test_encrypt_without_key_panics() {
    let rc5 = RC5::<u8>::new(16, 12);
    let plaintext = [0x42u8, 0x73u8];
    rc5.encrypt(plaintext);
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run set_key.")]
fn test_decrypt_without_key_panics() {
    let rc5 = RC5::<u8>::new(16, 12);
    let ciphertext = [0x42u8, 0x73u8];
    rc5.decrypt(ciphertext);
}

// --- u16 tests ---

#[test]
fn test_u16_encrypt_decrypt_roundtrip() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let plaintext = [0x1234u16, 0x5678u16];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_encrypt_decrypt_multiple_blocks() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    rc5.set_key(&key);

    let test_blocks = [
        [0x0000u16, 0x0000u16],
        [0xFFFFu16, 0xFFFFu16],
        [0xAAAAu16, 0x5555u16],
        [0x1234u16, 0x5678u16],
        [0xDEADu16, 0xBEEFu16],
    ];

    for plaintext in test_blocks.iter() {
        let ciphertext = rc5.encrypt(*plaintext);
        let decrypted = rc5.decrypt(ciphertext);
        assert_eq!(*plaintext, decrypted,
            "Roundtrip failed for plaintext {:?}", plaintext);
    }
}

#[test]
fn test_u16_deterministic_encryption() {
    let mut rc5 = RC5::<u16>::new(8, 12);
    let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    rc5.set_key(&key);

    let plaintext = [0xABCDu16, 0xEF01u16];
    assert_eq!(rc5.encrypt(plaintext), rc5.encrypt(plaintext));
}

#[test]
fn test_u16_different_plaintexts_different_ciphertexts() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0xFF; 16];
    rc5.set_key(&key);

    let ciphertext1 = rc5.encrypt([0x0000u16, 0x0000u16]);
    let ciphertext2 = rc5.encrypt([0x0000u16, 0x0001u16]);

    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_u16_different_keys_different_ciphertexts() {
    let plaintext = [0x4242u16, 0x4242u16];

    let mut rc5_1 = RC5::<u16>::new(8, 12);
    rc5_1.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let mut rc5_2 = RC5::<u16>::new(8, 12);
    rc5_2.set_key(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

    assert_ne!(rc5_1.encrypt(plaintext), rc5_2.encrypt(plaintext));
}

#[test]
fn test_u16_ciphertext_different_from_plaintext() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0x01; 16];
    rc5.set_key(&key);

    let plaintext = [0x1234u16, 0x5678u16];
    assert_ne!(plaintext, rc5.encrypt(plaintext));
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run key_gen.")]
fn test_u16_encrypt_without_key_panics() {
    let rc5 = RC5::<u16>::new(16, 12);
    rc5.encrypt([0x1234u16, 0x5678u16]);
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run set_key.")]
fn test_u16_decrypt_without_key_panics() {
    let rc5 = RC5::<u16>::new(16, 12);
    rc5.decrypt([0x1234u16, 0x5678u16]);
}

// --- u32 tests ---

#[test]
fn test_u32_encrypt_decrypt_roundtrip() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let plaintext = [0x12345678u32, 0x9ABCDEF0u32];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_encrypt_decrypt_multiple_blocks() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    rc5.set_key(&key);

    let test_blocks = [
        [0x00000000u32, 0x00000000u32],
        [0xFFFFFFFFu32, 0xFFFFFFFFu32],
        [0xAAAAAAAAu32, 0x55555555u32],
        [0x12345678u32, 0x9ABCDEF0u32],
        [0xDEADBEEFu32, 0xCAFEBABEu32],
    ];

    for plaintext in test_blocks.iter() {
        let ciphertext = rc5.encrypt(*plaintext);
        let decrypted = rc5.decrypt(ciphertext);
        assert_eq!(*plaintext, decrypted,
            "Roundtrip failed for plaintext {:?}", plaintext);
    }
}

#[test]
fn test_u32_deterministic_encryption() {
    let mut rc5 = RC5::<u32>::new(8, 12);
    let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    rc5.set_key(&key);

    let plaintext = [0xABCDEF01u32, 0x23456789u32];
    assert_eq!(rc5.encrypt(plaintext), rc5.encrypt(plaintext));
}

#[test]
fn test_u32_different_plaintexts_different_ciphertexts() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0xFF; 16];
    rc5.set_key(&key);

    let ciphertext1 = rc5.encrypt([0x00000000u32, 0x00000000u32]);
    let ciphertext2 = rc5.encrypt([0x00000000u32, 0x00000001u32]);

    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_u32_different_keys_different_ciphertexts() {
    let plaintext = [0x42424242u32, 0x42424242u32];

    let mut rc5_1 = RC5::<u32>::new(8, 12);
    rc5_1.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let mut rc5_2 = RC5::<u32>::new(8, 12);
    rc5_2.set_key(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

    assert_ne!(rc5_1.encrypt(plaintext), rc5_2.encrypt(plaintext));
}

#[test]
fn test_u32_ciphertext_different_from_plaintext() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0x01; 16];
    rc5.set_key(&key);

    let plaintext = [0x12345678u32, 0x9ABCDEF0u32];
    assert_ne!(plaintext, rc5.encrypt(plaintext));
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run key_gen.")]
fn test_u32_encrypt_without_key_panics() {
    let rc5 = RC5::<u32>::new(16, 12);
    rc5.encrypt([0x12345678u32, 0x9ABCDEF0u32]);
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run set_key.")]
fn test_u32_decrypt_without_key_panics() {
    let rc5 = RC5::<u32>::new(16, 12);
    rc5.decrypt([0x12345678u32, 0x9ABCDEF0u32]);
}

// --- u64 tests ---

#[test]
fn test_u64_encrypt_decrypt_roundtrip() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let plaintext = [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64];
    let ciphertext = rc5.encrypt(plaintext);
    let decrypted = rc5.decrypt(ciphertext);

    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_encrypt_decrypt_multiple_blocks() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
               0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    rc5.set_key(&key);

    let test_blocks = [
        [0x0000000000000000u64, 0x0000000000000000u64],
        [0xFFFFFFFFFFFFFFFFu64, 0xFFFFFFFFFFFFFFFFu64],
        [0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64],
        [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64],
        [0xDEADBEEFCAFEBABEu64, 0x0102030405060708u64],
    ];

    for plaintext in test_blocks.iter() {
        let ciphertext = rc5.encrypt(*plaintext);
        let decrypted = rc5.decrypt(ciphertext);
        assert_eq!(*plaintext, decrypted,
            "Roundtrip failed for plaintext {:?}", plaintext);
    }
}

#[test]
fn test_u64_deterministic_encryption() {
    let mut rc5 = RC5::<u64>::new(8, 12);
    let key = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    rc5.set_key(&key);

    let plaintext = [0xABCDEF0123456789u64, 0xFEDCBA9876543210u64];
    assert_eq!(rc5.encrypt(plaintext), rc5.encrypt(plaintext));
}

#[test]
fn test_u64_different_plaintexts_different_ciphertexts() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0xFF; 16];
    rc5.set_key(&key);

    let ciphertext1 = rc5.encrypt([0x0000000000000000u64, 0x0000000000000000u64]);
    let ciphertext2 = rc5.encrypt([0x0000000000000000u64, 0x0000000000000001u64]);

    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_u64_different_keys_different_ciphertexts() {
    let plaintext = [0x4242424242424242u64, 0x4242424242424242u64];

    let mut rc5_1 = RC5::<u64>::new(8, 12);
    rc5_1.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let mut rc5_2 = RC5::<u64>::new(8, 12);
    rc5_2.set_key(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

    assert_ne!(rc5_1.encrypt(plaintext), rc5_2.encrypt(plaintext));
}

#[test]
fn test_u64_ciphertext_different_from_plaintext() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0x01; 16];
    rc5.set_key(&key);

    let plaintext = [0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64];
    assert_ne!(plaintext, rc5.encrypt(plaintext));
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run key_gen.")]
fn test_u64_encrypt_without_key_panics() {
    let rc5 = RC5::<u64>::new(16, 12);
    rc5.encrypt([0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64]);
}

#[test]
#[should_panic(expected = "The Key is not initialized. Run set_key.")]
fn test_u64_decrypt_without_key_panics() {
    let rc5 = RC5::<u64>::new(16, 12);
    rc5.decrypt([0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64]);
}
