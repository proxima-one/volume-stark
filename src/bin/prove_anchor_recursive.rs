use std::sync::Arc;
use std::{env, fs};
use std::io::{ Write};
use std::marker::PhantomData;
use ethereum_types::H256;
use ethereum_types::U256;
use itertools::Itertools;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::fri::FriParams;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::{error, info};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;
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
    header_file: &str,
    prev_proof_file: &str,
    proof_file: &str,
) -> Result<()> {
    let binary_data = fs::read(file_name).unwrap();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };

    let all_paths = read_paths_from_file(path_file)?;
    let block_headers = read_headers_from_file(header_file)?;

    let config = StarkConfig::standard_fast_config();
    let all_stark = AllStark::<F, D>::default();

    let mut timing = TimingTree::new("generate recursive proof", log::Level::Error);

    let recursive_circuit:  AllRecursiveCircuits<GoldilocksField, C, 2> = AllRecursiveCircuits::from_bytes(
        &binary_data,
        &gate_serializer,
        &generator_serializer,
    ).unwrap();

    let prev_proof_data = fs::read(prev_proof_file).expect("File not found");

    let common_data = CommonCircuitData {
        fri_params: FriParams {
            degree_bits: recursive_circuit.root.circuit.common.degree_bits(),
            ..recursive_circuit.root.circuit.common.fri_params.clone()
        },
        ..recursive_circuit.root.circuit.common.clone()
    };

    let prev_proof: ProofWithPublicInputs<GoldilocksField, C, 2> = ProofWithPublicInputs::from_bytes(prev_proof_data, &common_data)
        .expect("Error loading proof data");

    let pi = prev_proof.public_inputs.iter().take(32).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
    let mut starting_blockhash = H256::from_slice(&pi[32..64]);
    starting_blockhash.0.reverse();
    let tries = convert_to_tree(&all_paths)?;
    let patricia_inputs = PatriciaInputs {
        pmt: tries,
        starting_blockhash,
        blockheaders: block_headers,
    };

    let root_proof = recursive_circuit.prove_root(
        &all_stark,
        &config,
        Default::default(),
        patricia_inputs.clone(),
        &mut timing,
    );
    let actual_proof = root_proof.as_ref().unwrap().0.to_bytes();
    println!("Public values: {:?}", root_proof.unwrap().1);
    fs::write(proof_file, actual_proof)?;

    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        error!("Usage: {} <circuit_file> <path_file> <header_file> <previous_proof_file> <proof_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_file = &args[1];
    let path_file = &args[2];
    let header_file = &args[3];
    let prev_proof_file = &args[4];
    let proof_file = &args[4];
    generate_proof(circuit_file, path_file, header_file, prev_proof_file, proof_file)?;
    info!("OK");
    Ok(())
}
