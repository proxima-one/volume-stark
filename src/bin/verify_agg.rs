use std::{env, fs};
use std::marker::PhantomData;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use log::{error, info};
use plonky2::fri::FriParams;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use serde::{Deserialize, Serialize};
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;

type F = GoldilocksField;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct ConfigJson {
    pub degree_bits: String,
}



pub fn verify_proof(
    circuit_file: &str,
    proof_file: &str,
) -> Result<()> {
    let mut binary_data = fs::read(circuit_file).expect("File not found");

    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };

    let recursive_circuit: AllRecursiveCircuits<GoldilocksField, C, 2>= AllRecursiveCircuits::from_bytes(
        &binary_data,
        &gate_serializer,
        &generator_serializer,
    )
        .expect("Error loading recursive circuit");

    let mut proof_data = fs::read(proof_file).expect("File not found");
    binary_data.pop();
    proof_data.pop();
    let common_data = CommonCircuitData {
        fri_params: FriParams {
            degree_bits: recursive_circuit.root.circuit.common.degree_bits(),
            ..recursive_circuit.root.circuit.common.fri_params.clone()
        },
        ..recursive_circuit.root.circuit.common.clone()
    };

    let proof = ProofWithPublicInputs::from_bytes(proof_data, &common_data)
        .expect("Error loading proof data");

    recursive_circuit.verify_aggregation(&proof)
        .expect("Error verifying aggregation proof");
    Ok(())
}



fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Usage: {} <circuit_file> <proof_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_file = &args[1];
    let proof_file = &args[2];
    verify_proof(circuit_file, proof_file)?;
    info!("OK");
    Ok(())
}
