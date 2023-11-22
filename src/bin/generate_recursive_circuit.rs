use std::fs::File;
use std::{env, io};
use std::io::BufReader;
use std::marker::PhantomData;
use std::ops::Range;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::{error, info};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use serde::{Deserialize, Serialize};
use maru_volume_stark::all_stark::AllStark;
use maru_volume_stark::config::StarkConfig;
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;
use maru_volume_stark::patricia_merkle_trie::str_to_u8_array;


type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct ConfigJson {
    pub min_degree_bits: String,
    pub max_degree_bits: String,
}

fn read_config_from_file(file_name: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let file = File::open(file_name)?;
    let reader = BufReader::new(file);
    let json_data: ConfigJson = serde_json::from_reader(reader)?;
    let min_degree_bits = str_to_u8_array(&json_data.min_degree_bits)?;
    let max_degree_bits = str_to_u8_array(&json_data.max_degree_bits)?;
    Ok((min_degree_bits, max_degree_bits))
}

pub fn generate_circuit_data(degree_bits: (&[u8], &[u8]), config_file: &str) -> io::Result<()> {
    let config = StarkConfig::standard_fast_config();
    let all_stark = AllStark::<F, D>::default();
    let min_degree_bits = degree_bits.0;
    let max_degree_bits = degree_bits.1;
    let mut degree_bit_ranges: [Range<usize>; 8] = Default::default();
    for i in 0..min_degree_bits.len() {
        degree_bit_ranges[i] = min_degree_bits[i] as usize..max_degree_bits[i] as usize;
    }
    let recursive_circuit: AllRecursiveCircuits<GoldilocksField, C, D> = AllRecursiveCircuits::new(
        &all_stark,
        &degree_bit_ranges,
        &config,
    );
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };
    let circuits_data = recursive_circuit.to_bytes(&gate_serializer, &generator_serializer);
    std::fs::write(config_file, circuits_data.unwrap())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: {} <config_file> <output_file>", args[0]);
        std::process::exit(1);
    }
    let config_file = &args[1];
    let output_file = &args[2];
    let degree_data = read_config_from_file(config_file)?;
    let degree_ranges = (&degree_data.0[..], &degree_data.1[..]);

    generate_circuit_data(degree_ranges, output_file)?;
    info!("OK");
    Ok(())
}
