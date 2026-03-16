/// Tests for CBC mode encrypt, decrypt, pad, read_file, write_file
use crate::rc5::RC5;
use crate::cbc::RC5CBC;

// ---- helpers ----------------------------------------------------------------

fn make_u8_cbc(rounds: usize, iv: [u8; 2]) -> RC5CBC<u8> {
    let mut rc5 = RC5::<u8>::new(8, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    RC5CBC::new(rc5, iv)
}

fn make_u16_cbc(rounds: usize, iv: [u16; 2]) -> RC5CBC<u16> {
    let mut rc5 = RC5::<u16>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5, iv)
}

fn make_u32_cbc(rounds: usize, iv: [u32; 2]) -> RC5CBC<u32> {
    let mut rc5 = RC5::<u32>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5, iv)
}

fn make_u64_cbc(rounds: usize, iv: [u64; 2]) -> RC5CBC<u64> {
    let mut rc5 = RC5::<u64>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5, iv)
}

// ---- encrypt / decrypt roundtrip --------------------------------------------

#[test]
fn test_u8_cbc_roundtrip_r6() {
    let cbc = make_u8_cbc(6, [0xAAu8, 0xBBu8]);
    let plaintext = vec![[0x12u8, 0x34u8], [0x56u8, 0x78u8], [0x9Au8, 0xBCu8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u8_cbc_roundtrip_r12() {
    let cbc = make_u8_cbc(12, [0x00u8, 0xFFu8]);
    let plaintext = vec![[0xDEu8, 0xADu8], [0xBEu8, 0xEFu8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u8_cbc_roundtrip_r20() {
    let cbc = make_u8_cbc(20, [0x01u8, 0x02u8]);
    let plaintext = vec![[0xFFu8, 0xFFu8], [0x00u8, 0x00u8], [0xA5u8, 0x5Au8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r6() {
    let cbc = make_u16_cbc(6, [0xAAAAu16, 0xBBBBu16]);
    let plaintext = vec![[0x1234u16, 0x5678u16], [0x9ABCu16, 0xDEF0u16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r12() {
    let cbc = make_u16_cbc(12, [0x0000u16, 0xFFFFu16]);
    let plaintext = vec![[0xDEADu16, 0xBEEFu16], [0xCAFEu16, 0xBABEu16], [0x0102u16, 0x0304u16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r20() {
    let cbc = make_u16_cbc(20, [0x1234u16, 0x5678u16]);
    let plaintext = vec![[0xFFFFu16, 0x0000u16], [0xA5A5u16, 0x5A5Au16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r6() {
    let cbc = make_u32_cbc(6, [0xAAAAAAAAu32, 0xBBBBBBBBu32]);
    let plaintext = vec![[0x12345678u32, 0x9ABCDEF0u32], [0xDEADBEEFu32, 0xCAFEBABEu32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r12() {
    let cbc = make_u32_cbc(12, [0x00000000u32, 0xFFFFFFFFu32]);
    let plaintext = vec![[0x00000000u32, 0x00000000u32], [0xFFFFFFFFu32, 0xFFFFFFFFu32], [0xA5A5A5A5u32, 0x5A5A5A5Au32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r20() {
    let cbc = make_u32_cbc(20, [0x13579BDFu32, 0x2468ACEu32]);
    let plaintext = vec![[0x11223344u32, 0x55667788u32], [0x99AABBCCu32, 0xDDEEFF00u32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r6() {
    let cbc = make_u64_cbc(6, [0xAAAAAAAAAAAAAAAAu64, 0xBBBBBBBBBBBBBBBBu64]);
    let plaintext = vec![[0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r12() {
    let cbc = make_u64_cbc(12, [0x0000000000000000u64, 0xFFFFFFFFFFFFFFFFu64]);
    let plaintext = vec![[0xDEADBEEFCAFEBABEu64, 0x0102030405060708u64], [0xFFFFFFFFFFFFFFFFu64, 0x0000000000000000u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r20() {
    let cbc = make_u64_cbc(20, [0x123456789ABCDEFu64, 0xFEDCBA987654321u64]);
    let plaintext = vec![[0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64], [0x1111111111111111u64, 0x2222222222222222u64], [0x3333333333333333u64, 0x4444444444444444u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

// ---- CBC chaining property --------------------------------------------------
// The same plaintext block at different positions should produce different ciphertext

#[test]
fn test_u32_cbc_chaining_same_block_differs() {
    let cbc = make_u32_cbc(12, [0x00000000u32, 0x00000000u32]);
    let block = [0xDEADBEEFu32, 0xCAFEBABEu32];
    let plaintext = vec![block, block, block];
    let ciphertext = cbc.encrypt(&plaintext);
    // In CBC mode each identical plaintext block must produce a different ciphertext block
    assert_ne!(ciphertext[0], ciphertext[1]);
    assert_ne!(ciphertext[1], ciphertext[2]);
}

#[test]
fn test_u64_cbc_chaining_same_block_differs() {
    let cbc = make_u64_cbc(12, [0x0u64, 0x0u64]);
    let block = [0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64];
    let plaintext = vec![block, block];
    let ciphertext = cbc.encrypt(&plaintext);
    assert_ne!(ciphertext[0], ciphertext[1]);
}

// ---- different IV produces different ciphertext -----------------------------

#[test]
fn test_u32_cbc_different_iv() {
    let plaintext = vec![[0x12345678u32, 0x9ABCDEF0u32], [0x11111111u32, 0x22222222u32]];

    let cbc1 = make_u32_cbc(12, [0x00000000u32, 0x00000000u32]);
    let cbc2 = make_u32_cbc(12, [0xFFFFFFFFu32, 0xFFFFFFFFu32]);

    let ciphertext1 = cbc1.encrypt(&plaintext);
    let ciphertext2 = cbc2.encrypt(&plaintext);

    assert_ne!(ciphertext1, ciphertext2);
}

#[test]
fn test_u16_cbc_different_iv() {
    let plaintext = vec![[0xABCDu16, 0xEF01u16]];

    let cbc1 = make_u16_cbc(12, [0x0000u16, 0x0000u16]);
    let cbc2 = make_u16_cbc(12, [0x0001u16, 0x0000u16]);

    assert_ne!(cbc1.encrypt(&plaintext), cbc2.encrypt(&plaintext));
}

// ---- empty input ------------------------------------------------------------

#[test]
fn test_u32_cbc_encrypt_empty() {
    let cbc = make_u32_cbc(12, [0x0u32, 0x0u32]);
    let result = cbc.encrypt(&[]);
    assert!(result.is_empty());
}

#[test]
fn test_u32_cbc_decrypt_empty() {
    let cbc = make_u32_cbc(12, [0x0u32, 0x0u32]);
    let result = cbc.decrypt(&[]);
    assert!(result.is_empty());
}

// ---- pad --------------------------------------------------------------------

#[test]
fn test_u8_pad_already_aligned() {
    let cbc = make_u8_cbc(12, [0x0u8, 0x0u8]);
    // already a whole number of blocks — pad should still return valid output
    let blocks = vec![[0x01u8, 0x02u8], [0x03u8, 0x04u8]];
    let padded = cbc.pad(&blocks);
    // padded length must be >= original length
    assert!(padded.len() >= blocks.len());
}

#[test]
fn test_u32_pad_output_can_be_encrypted() {
    let cbc = make_u32_cbc(12, [0x0u32, 0x0u32]);
    let blocks = vec![[0xDEADBEEFu32, 0xCAFEBABEu32]];
    let padded = cbc.pad(&blocks);
    // Should be possible to encrypt and decrypt padded output
    let ciphertext = cbc.encrypt(&padded);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(padded, decrypted);
}

// ---- read_file / write_file -------------------------------------------------

#[test]
fn test_u8_read_write_roundtrip() {
    let cbc = make_u8_cbc(12, [0x0u8, 0x0u8]);
    let blocks = vec![[0x12u8, 0x34u8], [0x56u8, 0x78u8]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u8.bin");
    cbc.write_file(&path, &blocks);
    let read_back = cbc.read_file(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u32_read_write_roundtrip() {
    let cbc = make_u32_cbc(12, [0x0u32, 0x0u32]);
    let blocks = vec![[0xDEADBEEFu32, 0xCAFEBABEu32], [0x12345678u32, 0x9ABCDEF0u32]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u32.bin");
    cbc.write_file(&path, &blocks);
    let read_back = cbc.read_file(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u64_read_write_roundtrip() {
    let cbc = make_u64_cbc(12, [0x0u64, 0x0u64]);
    let blocks = vec![[0xDEADBEEFCAFEBABEu64, 0x123456789ABCDEF0u64]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u64.bin");
    cbc.write_file(&path, &blocks);
    let read_back = cbc.read_file(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u32_encrypt_write_read_decrypt_roundtrip() {
    let cbc = make_u32_cbc(12, [0xDEADBEEFu32, 0xCAFEBABEu32]);
    let plaintext = vec![[0x11111111u32, 0x22222222u32], [0x33333333u32, 0x44444444u32]];
    let ciphertext = cbc.encrypt(&plaintext);

    let path = std::env::temp_dir().join("rc5_cbc_test_encrypt_write_read.bin");
    cbc.write_file(&path, &ciphertext);
    let read_back = cbc.read_file(&path);
    let decrypted = cbc.decrypt(&read_back);

    assert_eq!(plaintext, decrypted);
}
