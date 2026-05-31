/*
cargo run cipher -- [--new/--enc/--dec] <secret_key-path>.txt <input-path>.txt <output-path>.txt
*/
use rc5_implementation::cbc::RC5CBC;
use rc5_implementation::rc5::RC5;
use rc5_implementation::word::Word;
use std::env;
use std::fs;
use std::io::{self, BufRead, Bytes};
use std::path::Path;

const USIZE_BYTES: usize = std::mem::size_of::<usize>();

#[derive(Debug)]
enum Actions {
    KeyGen,
    Encrypt,
    Decrypt,
}

fn check_parameters(word_size: usize, rounds: usize, key_length: usize) -> Result<(), String> {
    if ![1, 2, 4, 8].contains(&word_size) {
        return Err(format!("The requested word size is {}. This size is not supported. Choose 1; 2; 4; or 8 bytes as a word size.", word_size));
    }
    if rounds == 0 {
        return Err(format!(
            "The requested number of rounds is {}. The number of rounds should be more than zero.",
            rounds
        ));
    }
    if key_length == 0 {
        return Err(format!(
            "The requested key size is {} bytes. The number of bytes should be more than zero.",
            key_length
        ));
    }
    Ok(())
}

fn parse_parameters(path: &Path) -> (usize, usize, usize, Vec<u8>) {
    let input: Vec<u8> =
        fs::read(path).expect(&format!("File {} could not be read", path.display()));
    assert!(
        input.len() > 3 * USIZE_BYTES,
        "The submitted input file does not contain enough data"
    );
    let word_size = usize::from_le_bytes(input[0..USIZE_BYTES].try_into().unwrap());
    let rounds = usize::from_le_bytes(input[USIZE_BYTES..2 * USIZE_BYTES].try_into().unwrap());
    let key_length =
        usize::from_le_bytes(input[2 * USIZE_BYTES..3 * USIZE_BYTES].try_into().unwrap());
    let key = input[3 * USIZE_BYTES..].to_vec();
    (word_size, rounds, key_length, key)
}

fn write_parameters(cipher: &RC5Cipher, path: &Path) {
    let (word_size, rounds, key_length, key) = match cipher {
        RC5Cipher::W8(rc5) => (
            1usize,
            rc5.get_rounds(),
            rc5.get_key_length(),
            rc5.get_key().to_vec(),
        ),
        RC5Cipher::W16(rc5) => (
            2usize,
            rc5.get_rounds(),
            rc5.get_key_length(),
            rc5.get_key().to_vec(),
        ),
        RC5Cipher::W32(rc5) => (
            4usize,
            rc5.get_rounds(),
            rc5.get_key_length(),
            rc5.get_key().to_vec(),
        ),
        RC5Cipher::W64(rc5) => (
            8usize,
            rc5.get_rounds(),
            rc5.get_key_length(),
            rc5.get_key().to_vec(),
        ),
    };
    let mut contents: Vec<u8> = Vec::new();
    contents.extend_from_slice(&word_size.to_le_bytes());
    contents.extend_from_slice(&rounds.to_le_bytes());
    contents.extend_from_slice(&key_length.to_le_bytes());
    contents.extend_from_slice(&key);
    fs::write(path, contents).expect("Failed to write key file");
}

enum RC5Cipher {
    W8(RC5<u8>),
    W16(RC5<u16>),
    W32(RC5<u32>),
    W64(RC5<u64>),
}

fn create_cipher(word_size: usize, key_length: usize, rounds: usize) -> RC5Cipher {
    match word_size {
        1 => RC5Cipher::W8(RC5::new(key_length, rounds)),
        2 => RC5Cipher::W16(RC5::new(key_length, rounds)),
        4 => RC5Cipher::W32(RC5::new(key_length, rounds)),
        8 => RC5Cipher::W64(RC5::new(key_length, rounds)),
        _ => panic!("unknown word_size"),
    }
}

fn generate_key(cipher: &mut RC5Cipher) {
    match cipher {
        RC5Cipher::W8(rc5) => rc5.key_gen(),
        RC5Cipher::W16(rc5) => rc5.key_gen(),
        RC5Cipher::W32(rc5) => rc5.key_gen(),
        RC5Cipher::W64(rc5) => rc5.key_gen(),
        _ => panic!("unknown cipher"),
    }
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!(
            "RC5-CBC Block Cipher
================
Usage: rc5-cbc [ACTION] [OPTIONS]

Actions:
  --new   Generate a new key
            Options: [key_file] [word_size] [rounds] [key_length]
            Defaults: new_key.txt, 4 bytes, 12 rounds, 16 bytes

  --enc   Encrypt a file
            Required: <key_file> <input_file> <output_file>

  --dec   Decrypt a file
            Required: <key_file> <input_file> <output_file>
"
        );
        print!("> ");
        let stdin = io::stdin();
        let line = stdin
            .lock()
            .lines()
            .next()
            .expect("Failed to read input")
            .expect("Failed to read input");
        args = std::iter::once(args[0].clone())
            .chain(line.split_whitespace().map(String::from))
            .collect();
    }

    let action = match args[1].as_str() {
        "--new" => Actions::KeyGen,
        "--enc" => Actions::Encrypt,
        "--dec" => Actions::Decrypt,
        _ => panic!("Bad argument as action, provide [--new/--enc/--dec]"),
    };
    let mut key_path_str: &str = "new_key.txt";
    let mut input_path_str: &str = "new_input.txt";
    let mut output_path_str: &str = "new_output.txt";
    let mut word_size: usize = 4;
    let mut rounds: usize = 12;
    let mut key_length: usize = 16;
    let mut key: Vec<u8> = Vec::new();
    match action {
        Actions::KeyGen => {
            match args.len() {
                3 => {
                    key_path_str = args[2].as_str();
                }
                4 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                }
                5 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                    rounds = args[4].parse().expect("rounds must be a number");
                }
                6 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                    rounds = args[4].parse().expect("rounds must be a number");
                    key_length = args[5].parse().expect("key_length must be a number");
                }
                _ => {}
            }
            check_parameters(word_size, rounds, key_length).unwrap_or_else(|e| panic!("{}", e));
            let mut cipher = create_cipher(word_size, key_length, rounds);
            generate_key(&mut cipher);
            write_parameters(&cipher, Path::new(key_path_str));
        }
        _ => {
            match args.len() {
                2 => {
                    panic!("No key, no input, no output specified. Specify path to the files.")
                }
                3 => {
                    panic!("No input, no output specified. Specify path to the files.")
                }
                4 => {
                    panic!("No output specified. Specify path to the file.")
                }
                _ => {
                    key_path_str = args[2].as_str();
                    input_path_str = args[3].as_str();
                    output_path_str = args[4].as_str();
                }
            }
            (word_size, rounds, key_length, key) = parse_parameters(&Path::new(&key_path_str));
            /*print!("word size: {}, rounds: {}, key_length: {}, key: {:?}", word_size, rounds, key_length, key); */
            check_parameters(word_size, rounds, key_length).unwrap_or_else(|e| panic!("{}", e));
            if key_length != key.len() {
                panic!("The key file is corrupted. The key length parameter does match the actual length of the key.")
            }
            todo!("Initialize the cipher algorithm from the parsed parameters. Depending on the action run encryption/decryption procedure.")
        }
    }
}
