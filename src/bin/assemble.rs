use std::{env, fs};

use hex::encode;
// use plonky2_evm::cpu::kernel::assemble_to_bytes;

pub mod generate_recursive_circuit;
pub mod prove_recursive;
pub mod verify_recursive;

fn main() {
    let mut args = env::args();
    args.next();
    let file_contents: Vec<_> = args.map(|path| fs::read_to_string(path).unwrap()).collect();
    // let assembled = assemble_to_bytes(&file_contents[..]);
    println!("{}", encode(assembled));
}
