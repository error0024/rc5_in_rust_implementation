/*
cargo run cipher -- [--new/--enc/--dec] <secret_key-path>.txt <input-path>.txt <output-path>.txt 
*/
use std::env;
use std::io::{self, BufRead};

enum Actions{
    KeyGen,
    Encrypt,
    Decrypt,
}
fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len() == 1 {
        println!("RC5-CBC Block Cipher
================
Usage: rc5 [ACTION] [OPTIONS]

Actions:
  --new   Generate a new key
            Options: [key_file] [word_size] [rounds] [key_length]
            Defaults: new_key.txt, 4 bytes, 12 rounds, 16 bytes

  --enc   Encrypt a file
            Required: <key_file> <input_file> <output_file>

  --dec   Decrypt a file
            Required: <key_file> <input_file> <output_file>
");
        print!("> ");
        let stdin = io::stdin();
        let line = stdin.lock().lines().next().expect("Failed to read input").expect("Failed to read input");
        args = std::iter::once(args[0].clone()).chain(line.split_whitespace().map(String::from)).collect();
    }

    let option = match args[1].as_str() {
        "--new" => Actions::KeyGen,
        "--enc" => Actions::Encrypt,
        "--dec" => Actions::Decrypt,
        _ => panic!("Bad argument as action, provide [--new/--enc/--dec]")
    };
    let mut key_path_str: &str = "new_key.txt";
    let mut input_path_str: &str = "new_input.txt";
    let mut output_path_str: &str = "new_output.txt";
    let mut word_size: usize = 4;
    let mut rounds: usize = 12;
    let mut key_length: usize = 16;
    match option {
        Actions::KeyGen => {
            match args.len() {
                2 => { key_path_str = args[2].as_str(); }
                3 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                }
                4 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                    rounds = args[4].parse().expect("rounds must be a number");
                }
                5 => {
                    key_path_str = args[2].as_str();
                    word_size = args[3].parse().expect("word_size must be a number");
                    rounds = args[4].parse().expect("rounds must be a number");
                    key_length = args[5].parse().expect("key_length must be a number");
                }
                _ => {}
            }
        }
        _ => {
            match args.len() {
                2 => { panic!("No key, no input, no output specified. Specify path to the files.") }
                3 => { panic!("No input, no output specified. Specify path to the files.") }
                4 => { panic!("No output specified. Specify path to the file.") }
                _ => {
                    key_path_str = args[2].as_str();
                    input_path_str = args[3].as_str();
                    output_path_str = args[4].as_str();
                }
            }
        }
    }
    match option {
        Actions::KeyGen => {
            match word_size {
                1 => {todo!()}
                2 => {}
                4 => {}
                8 => {}
                _ => {}
            }
            if key_length == 0 {
                todo!()
            }
        }
        _ => {
            todo!()
        }
    }
}