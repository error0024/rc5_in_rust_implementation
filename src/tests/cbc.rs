/// Tests for CBC mode encrypt, decrypt, pad, read_file, write_file
use crate::rc5::RC5;
use crate::cbc::RC5CBC;

// ---- helpers ----------------------------------------------------------------

fn make_u8_cbc(rounds: usize) -> RC5CBC<u8> {
    let mut rc5 = RC5::<u8>::new(8, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    RC5CBC::new(rc5)
}

fn make_u16_cbc(rounds: usize) -> RC5CBC<u16> {
    let mut rc5 = RC5::<u16>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5)
}

fn make_u32_cbc(rounds: usize) -> RC5CBC<u32> {
    let mut rc5 = RC5::<u32>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5)
}

fn make_u64_cbc(rounds: usize) -> RC5CBC<u64> {
    let mut rc5 = RC5::<u64>::new(16, rounds);
    rc5.set_key(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]);
    RC5CBC::new(rc5)
}

// ---- encrypt / decrypt roundtrip --------------------------------------------

#[test]
fn test_u8_cbc_roundtrip_r6() {
    let cbc = make_u8_cbc(6);
    let plaintext = vec![[0x12u8, 0x34u8], [0x56u8, 0x78u8], [0x9Au8, 0xBCu8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u8_cbc_roundtrip_r12() {
    let cbc = make_u8_cbc(12);
    let plaintext = vec![[0xDEu8, 0xADu8], [0xBEu8, 0xEFu8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u8_cbc_roundtrip_r20() {
    let cbc = make_u8_cbc(20);
    let plaintext = vec![[0xFFu8, 0xFFu8], [0x00u8, 0x00u8], [0xA5u8, 0x5Au8]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r6() {
    let cbc = make_u16_cbc(6);
    let plaintext = vec![[0x1234u16, 0x5678u16], [0x9ABCu16, 0xDEF0u16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r12() {
    let cbc = make_u16_cbc(12);
    let plaintext = vec![[0xDEADu16, 0xBEEFu16], [0xCAFEu16, 0xBABEu16], [0x0102u16, 0x0304u16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u16_cbc_roundtrip_r20() {
    let cbc = make_u16_cbc(20);
    let plaintext = vec![[0xFFFFu16, 0x0000u16], [0xA5A5u16, 0x5A5Au16]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r6() {
    let cbc = make_u32_cbc(6);
    let plaintext = vec![[0x12345678u32, 0x9ABCDEF0u32], [0xDEADBEEFu32, 0xCAFEBABEu32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r12() {
    let cbc = make_u32_cbc(12);
    let plaintext = vec![[0x00000000u32, 0x00000000u32], [0xFFFFFFFFu32, 0xFFFFFFFFu32], [0xA5A5A5A5u32, 0x5A5A5A5Au32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u32_cbc_roundtrip_r20() {
    let cbc = make_u32_cbc(20);
    let plaintext = vec![[0x11223344u32, 0x55667788u32], [0x99AABBCCu32, 0xDDEEFF00u32]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r6() {
    let cbc = make_u64_cbc(6);
    let plaintext = vec![[0x123456789ABCDEF0u64, 0xFEDCBA9876543210u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r12() {
    let cbc = make_u64_cbc(12);
    let plaintext = vec![[0xDEADBEEFCAFEBABEu64, 0x0102030405060708u64], [0xFFFFFFFFFFFFFFFFu64, 0x0000000000000000u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

#[test]
fn test_u64_cbc_roundtrip_r20() {
    let cbc = make_u64_cbc(20);
    let plaintext = vec![[0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64], [0x1111111111111111u64, 0x2222222222222222u64], [0x3333333333333333u64, 0x4444444444444444u64]];
    let ciphertext = cbc.encrypt(&plaintext);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(plaintext, decrypted);
}

// ---- CBC chaining property --------------------------------------------------
// The same plaintext block at different positions should produce different ciphertext.
// encrypt() prepends the IV as ciphertext[0], so encrypted blocks start at index 1.

#[test]
fn test_u32_cbc_chaining_same_block_differs() {
    let cbc = make_u32_cbc(12);
    let block = [0xDEADBEEFu32, 0xCAFEBABEu32];
    let plaintext = vec![block, block, block];
    let ciphertext = cbc.encrypt(&plaintext);
    assert_ne!(ciphertext[1], ciphertext[2]);
    assert_ne!(ciphertext[2], ciphertext[3]);
}

#[test]
fn test_u64_cbc_chaining_same_block_differs() {
    let cbc = make_u64_cbc(12);
    let block = [0xAAAAAAAAAAAAAAAAu64, 0x5555555555555555u64];
    let plaintext = vec![block, block];
    let ciphertext = cbc.encrypt(&plaintext);
    assert_ne!(ciphertext[1], ciphertext[2]);
}

// ---- random IV produces different ciphertext each run -----------------------
// Since IV is random, encrypting the same plaintext twice should differ.

#[test]
fn test_u32_cbc_random_iv_differs() {
    let plaintext = vec![[0x12345678u32, 0x9ABCDEF0u32], [0x11111111u32, 0x22222222u32]];
    let cbc1 = make_u32_cbc(12);
    let cbc2 = make_u32_cbc(12);
    assert_ne!(cbc1.encrypt(&plaintext), cbc2.encrypt(&plaintext));
}

// ---- empty input ------------------------------------------------------------

#[test]
fn test_u32_cbc_encrypt_empty() {
    let cbc = make_u32_cbc(12);
    let result = cbc.encrypt(&[]);
    // encrypt always prepends the IV block
    assert_eq!(result.len(), 1);
}

#[test]
fn test_u32_cbc_decrypt_empty() {
    let cbc = make_u32_cbc(12);
    let result = cbc.decrypt(&[]);
    assert!(result.is_empty());
}

// ---- pad --------------------------------------------------------------------

#[test]
fn test_u8_pad_already_aligned() {
    let cbc = make_u8_cbc(12);
    let mut bytes = vec![0x01u8, 0x02u8];
    let original_len = bytes.len();
    cbc.pad(&mut bytes);
    assert!(bytes.len() >= original_len);
}

#[test]
fn test_u32_pad_aligns_to_block_size() {
    let cbc = make_u32_cbc(12);
    let mut bytes = vec![0x01u8, 0x02u8, 0x03u8]; // 3 bytes, block is 8 bytes
    cbc.pad(&mut bytes);
    assert_eq!(bytes.len() % 8, 0);
}

#[test]
fn test_u32_pad_output_can_be_encrypted() {
    let cbc = make_u32_cbc(12);
    let mut bytes = vec![0xDEu8, 0xADu8, 0xBEu8]; // not block-aligned
    cbc.pad(&mut bytes);
    let blocks = vec![[u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                       u32::from_le_bytes(bytes[4..8].try_into().unwrap())]];
    let ciphertext = cbc.encrypt(&blocks);
    let decrypted = cbc.decrypt(&ciphertext);
    assert_eq!(blocks, decrypted);
}

// ---- write_ciphertext / read_ciphertext roundtrip ---------------------------

#[test]
fn test_u8_read_write_roundtrip() {
    let cbc = make_u8_cbc(12);
    let blocks = vec![[0x12u8, 0x34u8], [0x56u8, 0x78u8]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u8.bin");
    cbc.write_ciphertext(&path, &blocks);
    let read_back = cbc.read_ciphertext(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u32_read_write_roundtrip() {
    let cbc = make_u32_cbc(12);
    let blocks = vec![[0xDEADBEEFu32, 0xCAFEBABEu32], [0x12345678u32, 0x9ABCDEF0u32]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u32.bin");
    cbc.write_ciphertext(&path, &blocks);
    let read_back = cbc.read_ciphertext(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u64_read_write_roundtrip() {
    let cbc = make_u64_cbc(12);
    let blocks = vec![[0xDEADBEEFCAFEBABEu64, 0x123456789ABCDEF0u64]];
    let path = std::env::temp_dir().join("rc5_cbc_test_u64.bin");
    cbc.write_ciphertext(&path, &blocks);
    let read_back = cbc.read_ciphertext(&path);
    assert_eq!(blocks, read_back);
}

#[test]
fn test_u32_encrypt_write_read_decrypt_roundtrip() {
    let cbc = make_u32_cbc(12);
    let plaintext = vec![[0x11111111u32, 0x22222222u32], [0x33333333u32, 0x44444444u32]];
    let ciphertext = cbc.encrypt(&plaintext);

    let path = std::env::temp_dir().join("rc5_cbc_test_encrypt_write_read.bin");
    cbc.write_ciphertext(&path, &ciphertext);
    let read_back = cbc.read_ciphertext(&path);
    let decrypted = cbc.decrypt(&read_back);

    assert_eq!(plaintext, decrypted);
}
