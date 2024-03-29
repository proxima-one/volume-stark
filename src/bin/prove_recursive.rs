use std::fs::File;
use std::{env, fs};
use std::io::{ Write, BufWriter};
use std::marker::PhantomData;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::{error, info};
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;
use maru_volume_stark::circom_verifier::{generate_verifier_config, generate_proof_base64};
use serde::{Deserialize, Serialize};
use maru_volume_stark::all_stark::AllStark;
use maru_volume_stark::block_header::read_headers_from_file;
use maru_volume_stark::config::StarkConfig;
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;
use maru_volume_stark::generation::PatriciaInputs;
use maru_volume_stark::patricia_merkle_trie::{convert_to_tree, read_paths_from_file};

type F = GoldilocksField;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct ConfigJson {
    pub degree_bits: String,
}



pub fn generate_proof(
    file_name: &str,
    path_file: &str,
    blockheaders_file: &str,
    proof_file: &str,
) -> Result<()> {
    let binary_data = fs::read(file_name).unwrap();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };

    let all_paths = read_paths_from_file(path_file).expect("Reading paths error");
    let block_headers = read_headers_from_file(blockheaders_file).expect("Reading block headers error");
    let tries = convert_to_tree(&all_paths)?;
    let patricia_inputs = PatriciaInputs {
        pmt: tries,
        starting_blockhash: block_headers[0].parent_hash.clone(),
        blockheaders: block_headers,
    };

    let config = StarkConfig::standard_fast_config();
    let all_stark = AllStark::<F, D>::default();
    let recursive_circuit:  AllRecursiveCircuits<GoldilocksField, C, 2> = AllRecursiveCircuits::from_bytes(
        &binary_data,
        &gate_serializer,
        &generator_serializer,
    ).unwrap();
    let mut timing = TimingTree::new("Generate recursive proof", log::Level::Error);
    let (root_proof, pis) = recursive_circuit.prove_root(
        &all_stark,
        &config,
        Default::default(),
        patricia_inputs.clone(),
        &mut timing,
    ).expect("Proving error");
    timing.print();

    let final_proof_path = format!("{}", proof_file);
    let is_aggregated = 0u8;
    let mut proof_bytes = root_proof.to_bytes();
    proof_bytes.push(is_aggregated);
    fs::write(final_proof_path, &proof_bytes).expect("Proof writing error");
    // let conf = generate_verifier_config(&root_proof).expect("Generate verifier config error");
    // let proof_base64_json = generate_proof_base64(&root_proof, &conf).expect("Generate proof Base64 error");
    // let pretty_proof_path = format!("{}.json", final_proof_path);
    // fs::write(pretty_proof_path, proof_base64_json.as_bytes())?;
    //
    // let hex_input_file_name = format!("{}.public.json", final_proof_path);
    // let hex_input_file = File::create(hex_input_file_name)?;
    // let mut writer = BufWriter::new(hex_input_file);
    // serde_json::to_writer(&mut writer, &pis)?;

    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        error!("Usage: {} <circuit_file> <path_file> <blockheaders_file> <proof_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_file = &args[1];
    let path_file = &args[2];
    let blockheaders_file = &args[3];
    let proof_file = &args[4];
    generate_proof(circuit_file, path_file, blockheaders_file, proof_file).expect("Proof generation error");
    info!("OK");
    Ok(())
}