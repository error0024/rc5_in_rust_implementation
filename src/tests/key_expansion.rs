/// Tests for key expansion and key_l generation
use crate::rc5::RC5;

#[test]
fn test_key_expansion_not_all_zeros() {
    let mut rc5 = RC5::<u8>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    // Verify that the expanded key table is not all zeros
    let all_zeros = rc5.s.iter().all(|&x| x == 0u8);
    assert!(!all_zeros, "Expanded key table should not be all zeros");
}

#[test]
fn test_key_l_generation_u8_simple() {
    // For u8 words, each byte becomes one word
    let key = [0x01u8, 0x02, 0x03, 0x04];
    let key_l = RC5::<u8>::generate_key_l(&key);

    assert_eq!(key_l.len(), 4, "key_l should have 4 elements for 4-byte key with u8 words");
    // Each byte should map directly to a word
    assert_eq!(key_l, vec![0x01u8, 0x02, 0x03, 0x04], "key_l should match input key for u8 words");
}

#[test]
fn test_key_l_generation_u8_zero_key() {
    let key = [0x00u8, 0x00, 0x00, 0x00];
    let key_l = RC5::<u8>::generate_key_l(&key);

    assert_eq!(key_l.len(), 4);
    assert_eq!(key_l, vec![0x00u8; 4], "Zero key should produce all-zero key_l");
}

#[test]
fn test_key_l_generation_u8_all_ones() {
    let key = [0xFFu8, 0xFF, 0xFF, 0xFF];
    let key_l = RC5::<u8>::generate_key_l(&key);

    assert_eq!(key_l.len(), 4);
    assert_eq!(key_l, vec![0xFFu8; 4], "All-ones key should produce all-ones key_l");
}

#[test]
fn test_key_l_generation_u8_varying_lengths() {
    // Test 1-byte key
    let key1 = [0xABu8];
    let key_l1 = RC5::<u8>::generate_key_l(&key1);
    assert_eq!(key_l1.len(), 1);
    assert_eq!(key_l1[0], 0xAB);

    // Test 2-byte key
    let key2 = [0x12u8, 0x34];
    let key_l2 = RC5::<u8>::generate_key_l(&key2);
    assert_eq!(key_l2.len(), 2);
    assert_eq!(key_l2, vec![0x12, 0x34]);

    // Test 16-byte key (standard RC5)
    let key16 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let key_l16 = RC5::<u8>::generate_key_l(&key16);
    assert_eq!(key_l16.len(), 16);
    assert_eq!(key_l16, vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
}

#[test]
fn test_key_l_generation_u8_pattern() {
    // Test with a specific pattern to verify byte ordering
    let key = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let key_l = RC5::<u8>::generate_key_l(&key);

    assert_eq!(key_l.len(), 8);
    assert_eq!(key_l[0], 0xAA, "First word should be first byte");
    assert_eq!(key_l[1], 0xBB, "Second word should be second byte");
    assert_eq!(key_l[7], 0x22, "Last word should be last byte");
}

#[test]
fn test_key_l_generation_empty_key() {
    // Empty key should result in at least 1 word (due to c = tmp.max(1))
    let key: [u8; 0] = [];
    let key_l = RC5::<u8>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "Empty key should result in 1 zero word");
    assert_eq!(key_l[0], 0x00);
}

#[test]
fn test_key_l_length_calculation() {
    // Test that c = ceil(b/w) is calculated correctly
    // For u8 (w=1): c should equal b (or 1 if b=0)

    for key_len in 1..=32 {
        let key = vec![0x42u8; key_len];
        let key_l = RC5::<u8>::generate_key_l(&key);
        assert_eq!(key_l.len(), key_len,
            "For u8 words, key_l length should equal key length");
    }
}

// --- u16 tests ---

#[test]
fn test_u16_key_expansion_not_all_zeros() {
    let mut rc5 = RC5::<u16>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let all_zeros = rc5.s.iter().all(|&x| x == 0u16);
    assert!(!all_zeros, "Expanded u16 key table should not be all zeros");
}

#[test]
fn test_u16_key_l_generation_two_bytes_per_word() {
    // For u16 words (w=2), every 2 bytes pack into one word (little-endian)
    let key = [0x01u8, 0x02, 0x03, 0x04];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2, "4-byte key should produce 2 u16 words");
    assert_eq!(key_l[0], 0x0201u16, "First word: bytes [0..1] little-endian");
    assert_eq!(key_l[1], 0x0403u16, "Second word: bytes [2..3] little-endian");
}

#[test]
fn test_u16_key_l_generation_odd_key_length() {
    // 3 bytes -> ceil(3/2) = 2 words; last word has only 1 byte
    let key = [0x01u8, 0x02, 0x03];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l[0], 0x0201u16);
    assert_eq!(key_l[1], 0x0003u16); // only low byte filled
}

#[test]
fn test_u16_key_l_generation_single_byte() {
    let key = [0xABu8];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1);
    assert_eq!(key_l[0], 0x00ABu16);
}

#[test]
fn test_u16_key_l_generation_two_bytes() {
    let key = [0xABu8, 0xCD];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1);
    assert_eq!(key_l[0], 0xCDABu16); // little-endian: low byte first
}

#[test]
fn test_u16_key_l_generation_zero_key() {
    let key = [0x00u8; 4];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l, vec![0x0000u16; 2]);
}

#[test]
fn test_u16_key_l_length_calculation() {
    // For u16 (w=2): c = ceil(key_len / 2)
    for key_len in 1..=32usize {
        let key = vec![0x42u8; key_len];
        let key_l = RC5::<u16>::generate_key_l(&key);
        let expected_len = (key_len + 1) / 2;
        assert_eq!(key_l.len(), expected_len,
            "For u16 words, key_l length should be ceil(key_len/2)");
    }
}

#[test]
fn test_u16_key_l_generation_empty_key() {
    let key: [u8; 0] = [];
    let key_l = RC5::<u16>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "Empty key should result in 1 zero word");
    assert_eq!(key_l[0], 0x0000u16);
}

// --- u32 tests ---

#[test]
fn test_u32_key_expansion_not_all_zeros() {
    let mut rc5 = RC5::<u32>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let all_zeros = rc5.s.iter().all(|&x| x == 0u32);
    assert!(!all_zeros, "Expanded u32 key table should not be all zeros");
}

#[test]
fn test_u32_key_l_generation_four_bytes_per_word() {
    // 4 bytes -> 1 u32 word (little-endian: byte 0 is LSB)
    let key = [0x01u8, 0x02, 0x03, 0x04];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "4-byte key should produce 1 u32 word");
    assert_eq!(key_l[0], 0x04030201u32, "Little-endian packing: byte 0 is LSB");
}

#[test]
fn test_u32_key_l_generation_eight_bytes() {
    let key = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l[0], 0x04030201u32);
    assert_eq!(key_l[1], 0x08070605u32);
}

#[test]
fn test_u32_key_l_generation_odd_key_length() {
    // 5 bytes -> ceil(5/4) = 2 words; last word has only 1 byte
    let key = [0x01u8, 0x02, 0x03, 0x04, 0x05];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l[0], 0x04030201u32);
    assert_eq!(key_l[1], 0x00000005u32);
}

#[test]
fn test_u32_key_l_generation_single_byte() {
    let key = [0xABu8];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1);
    assert_eq!(key_l[0], 0x000000ABu32);
}

#[test]
fn test_u32_key_l_generation_zero_key() {
    let key = [0x00u8; 8];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l, vec![0x00000000u32; 2]);
}

#[test]
fn test_u32_key_l_length_calculation() {
    // For u32 (w=4): c = ceil(key_len / 4)
    for key_len in 1..=32usize {
        let key = vec![0x42u8; key_len];
        let key_l = RC5::<u32>::generate_key_l(&key);
        let expected_len = (key_len + 3) / 4;
        assert_eq!(key_l.len(), expected_len,
            "For u32 words, key_l length should be ceil(key_len/4)");
    }
}

#[test]
fn test_u32_key_l_generation_empty_key() {
    let key: [u8; 0] = [];
    let key_l = RC5::<u32>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "Empty key should result in 1 zero word");
    assert_eq!(key_l[0], 0x00000000u32);
}

// --- u64 tests ---

#[test]
fn test_u64_key_expansion_not_all_zeros() {
    let mut rc5 = RC5::<u64>::new(16, 12);
    let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
               0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    rc5.set_key(&key);

    let all_zeros = rc5.s.iter().all(|&x| x == 0u64);
    assert!(!all_zeros, "Expanded u64 key table should not be all zeros");
}

#[test]
fn test_u64_key_l_generation_eight_bytes_per_word() {
    // 8 bytes -> 1 u64 word (little-endian: byte 0 is LSB)
    let key = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let key_l = RC5::<u64>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "8-byte key should produce 1 u64 word");
    assert_eq!(key_l[0], 0x0807060504030201u64, "Little-endian packing: byte 0 is LSB");
}

#[test]
fn test_u64_key_l_generation_nine_bytes() {
    // 9 bytes -> ceil(9/8) = 2 words; second word has only 1 byte
    let key = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
    let key_l = RC5::<u64>::generate_key_l(&key);

    assert_eq!(key_l.len(), 2);
    assert_eq!(key_l[0], 0x0807060504030201u64);
    assert_eq!(key_l[1], 0x0000000000000009u64);
}

#[test]
fn test_u64_key_l_generation_single_byte() {
    let key = [0xABu8];
    let key_l = RC5::<u64>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1);
    assert_eq!(key_l[0], 0x00000000000000ABu64);
}

#[test]
fn test_u64_key_l_generation_zero_key() {
    let key = [0x00u8; 8];
    let key_l = RC5::<u64>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1);
    assert_eq!(key_l[0], 0x0000000000000000u64);
}

#[test]
fn test_u64_key_l_length_calculation() {
    // For u64 (w=8): c = ceil(key_len / 8)
    for key_len in 1..=64usize {
        let key = vec![0x42u8; key_len];
        let key_l = RC5::<u64>::generate_key_l(&key);
        let expected_len = (key_len + 7) / 8;
        assert_eq!(key_l.len(), expected_len,
            "For u64 words, key_l length should be ceil(key_len/8)");
    }
}

#[test]
fn test_u64_key_l_generation_empty_key() {
    let key: [u8; 0] = [];
    let key_l = RC5::<u64>::generate_key_l(&key);

    assert_eq!(key_l.len(), 1, "Empty key should result in 1 zero word");
    assert_eq!(key_l[0], 0x0000000000000000u64);
}
