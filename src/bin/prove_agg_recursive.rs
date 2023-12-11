use std::fs::File;
use std::path::Path;
use std::io::{BufRead, BufWriter};
use std::sync::Arc;
use std::{env, fs, io};
use std::io::Write;
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
use maru_volume_stark::proof::PublicValues;
use serde::{Deserialize, Serialize};
use maru_volume_stark::all_stark::AllStark;
use maru_volume_stark::circom_verifier::{generate_proof_base64, generate_verifier_config};
use maru_volume_stark::config::StarkConfig;
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;
use maru_volume_stark::generation::{ PatriciaInputs};
use maru_volume_stark::patricia_merkle_trie::read_paths_from_file;
type F = GoldilocksField;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct ConfigJson {
    pub degree_bits: String,
}


pub fn generate_agg_proof(
    recursive_circuit: &AllRecursiveCircuits<GoldilocksField, C, 2>,
    first_proof_path: &str,
    second_proof_path: &str,
    resulting_proof_path: &str
) -> Result<()> {
    let mut first_proof_data = fs::read(first_proof_path).expect("File not found");
    let mut second_proof_data = fs::read(second_proof_path).expect("File not found");

    let lhs_is_agg = first_proof_data.last().unwrap().clone() != 0;
    let rhs_is_agg = second_proof_data.last().unwrap().clone() != 0;
    first_proof_data.pop();
    second_proof_data.pop();
    let common_data = CommonCircuitData {
        fri_params: FriParams {
            degree_bits: recursive_circuit.root.circuit.common.degree_bits(),
            ..recursive_circuit.root.circuit.common.fri_params.clone()
        },
        ..recursive_circuit.root.circuit.common.clone()
    };


    let mut timing = TimingTree::new("Proof aggregation", log::Level::Error);
    let first_proof: ProofWithPublicInputs<GoldilocksField, C, 2> = ProofWithPublicInputs::from_bytes(first_proof_data, &common_data)
        .expect("Error loading proof data");
    let second_proof: ProofWithPublicInputs<GoldilocksField, C, 2> = ProofWithPublicInputs::from_bytes(second_proof_data, &common_data)
        .expect("Error loading proof data");

    // recursive_circuit.verify_root(first_proof.clone())?;
    // recursive_circuit.verify_root(second_proof.clone())?;

    let pi_1 = first_proof.public_inputs.iter().take(24).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
    let starting_sum = U256::from_little_endian(&pi_1[0..32]);
    let mut starting_blockhash = H256::from_slice(&pi_1[32..64]);
    starting_blockhash.0.reverse();

    let pi_2 = second_proof.public_inputs.iter().take(24).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
    let ending_sum = U256::from_little_endian(&pi_2[0..32]);
    let mut ending_blockhash = H256::from_slice(&pi_2[64..96]);
    let total_sum = starting_sum + ending_sum;
    ending_blockhash.0.reverse();
    let pv = PublicValues {
        total_sum,
        starting_blockhash,
        ending_blockhash
    };
    let agg_proof = recursive_circuit.prove_aggregation(
        lhs_is_agg,
        &first_proof,
        rhs_is_agg,
        &second_proof,
        pv

    ).unwrap();
    timing.print();
    let mut actual_proof = agg_proof.0.to_bytes();
    info!("Public values: {:?}", agg_proof.1);
    actual_proof.push(1u8);
    fs::write(resulting_proof_path, actual_proof.clone())?;
    actual_proof.pop();
    let conf = generate_verifier_config(&agg_proof.0)?;
    let proof_base64_json = generate_proof_base64(&agg_proof.0, &conf)?;
    let pretty_proof_path = format!("{}.json", resulting_proof_path);
    fs::write(pretty_proof_path, proof_base64_json.as_bytes())?;

    let hex_input_file_name = format!("{}.public.json", resulting_proof_path);
    let hex_input_file = File::create(hex_input_file_name)?;
    let mut writer = BufWriter::new(hex_input_file);
    serde_json::to_writer(&mut writer, &agg_proof.1)?;

    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        error!("Usage: {} <circuit_file> <proof_list> <proof_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_path = &args[1];
    let proof_list = &args[2];
    let proof_file = &args[3];
    info!("Starting aggregation");
    let binary_data = fs::read(circuit_path).unwrap();

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };
    let recursive_circuit:  AllRecursiveCircuits<GoldilocksField, C, 2> = AllRecursiveCircuits::from_bytes(
        &binary_data,
        &gate_serializer,
        &generator_serializer,
    ).unwrap();
    info!("Circuit loaded");
    let temp_proof_file = "tmp.proof";
    if let Ok(mut lines) = read_lines(proof_list) {
        let first_proof_file = lines.next().unwrap()?;
        let second_proof_file = lines.next().unwrap()?;
        generate_agg_proof(&recursive_circuit, &first_proof_file, &second_proof_file, &temp_proof_file)?;
        for next_proof_file in lines {
            generate_agg_proof(&recursive_circuit, &temp_proof_file, &next_proof_file.unwrap(), &temp_proof_file)?;
        }
    } else {
        panic!("Could not read {:?}", proof_list);
    }
    let temp_proof_path = format!("{}.json", temp_proof_file);
    let correct_path_name = format!("{}.json", proof_file);
    let old_pis_name = format!("{}.public.json", temp_proof_file);
    let correct_pis_name = format!("{}.public.json", proof_file);
    let final_proof = format!("{}.bin", proof_file);
    std::fs::rename(temp_proof_file, final_proof)?;
    std::fs::rename(temp_proof_path, correct_path_name)?;
    std::fs::rename(old_pis_name, correct_pis_name)?;
    info!("OK");
    Ok(())
}
