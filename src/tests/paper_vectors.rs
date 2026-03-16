/// Known-answer tests from Rivest's RC5 paper (RC5-32/12/16)
/// Word size: 32 bits, Rounds: 12, Key length: 16 bytes
/// Plaintext/ciphertext are [A, B] word pairs in little-endian byte order.
/// The three vectors are chained: ciphertext of each becomes plaintext of the next.
use crate::rc5::RC5;

#[test]
fn test_paper_vector1_rc5_32_12_16() {
    // Key:       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // Plaintext: 00 00 00 00 00 00 00 00
    // Ciphertext:EE DB A5 21 6D 8F 4B 15
    let mut rc5 = RC5::<u32>::new(16, 12);
    rc5.set_key(&[0x00; 16]);
    let result = rc5.encrypt([0x00000000u32, 0x00000000u32]);
    assert_eq!(
        result,
        [0xEEDBA521u32, 0x6D8F4B15u32],
        "got [{:#010X}, {:#010X}]", result[0], result[1]
    );
}

#[test]
fn test_paper_vector2_rc5_32_12_16() {
    // Key:       91 5F 46 19 BE 41 B2 51 63 55 A5 01 10 A9 CE 91
    // Plaintext: EE DB A5 21 6D 8F 4B 15  (= ciphertext of vector 1)
    // Ciphertext:AC 13 C0 F7 52 89 2B 5B
    let mut rc5 = RC5::<u32>::new(16, 12);
    rc5.set_key(&[0x91, 0x5F, 0x46, 0x19, 0xBE, 0x41, 0xB2, 0x51,
                  0x63, 0x55, 0xA5, 0x01, 0x10, 0xA9, 0xCE, 0x91]);
    let result = rc5.encrypt([0xEEDBA521u32, 0x6D8F4B15u32]);
    assert_eq!(
        result,
        [0xAC13C0F7u32, 0x52892B5Bu32],
        "got [{:#010X}, {:#010X}]", result[0], result[1]
    );
}

#[test]
fn test_paper_vector3_rc5_32_12_16() {
    // Key:       78 33 48 E7 5A EB 0F 2F D7 B1 69 BB 8D C1 67 87
    // Plaintext: AC 13 C0 F7 52 89 2B 5B  (= ciphertext of vector 2)
    // Ciphertext:B7 B3 42 2F 92 FC 69 03
    let mut rc5 = RC5::<u32>::new(16, 12);
    rc5.set_key(&[0x78, 0x33, 0x48, 0xE7, 0x5A, 0xEB, 0x0F, 0x2F,
                  0xD7, 0xB1, 0x69, 0xBB, 0x8D, 0xC1, 0x67, 0x87]);
    let result = rc5.encrypt([0xAC13C0F7u32, 0x52892B5Bu32]);
    assert_eq!(
        result,
        [0xB7B3422Fu32, 0x92FC6903u32],
        "got [{:#010X}, {:#010X}]", result[0], result[1]
    );
}
