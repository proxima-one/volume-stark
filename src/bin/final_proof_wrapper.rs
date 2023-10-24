use std::{env, fs};
use std::io::{Write};
use std::marker::PhantomData;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use anyhow::Result;
use env_logger::{DEFAULT_FILTER_ENV, Env, try_init_from_env};
use itertools::Itertools;
use log::{error, info};
use plonky2::field::types::Field;
use plonky2::hash::hashing::compress;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;
use maru_volume_stark::fixed_recursive_verifier::AllRecursiveCircuits;


type F = GoldilocksField;

const D: usize = 2;

type C = PoseidonGoldilocksConfig;


pub fn wrap_proof(
    circuit_file: &str,
    root_proof_file: &str,
    final_proof_file: &str,
) -> Result<()> {
    let binary_data = fs::read(circuit_file).unwrap();
    const PIS_NUM: usize = 24;
    let gate_serializer = DefaultGateSerializer;
    let generator_serializer = DefaultGeneratorSerializer {
        _phantom: PhantomData::<C>,
    };
    let recursive_circuit: AllRecursiveCircuits<GoldilocksField, C, 2> = AllRecursiveCircuits::from_bytes(
        &binary_data,
        &gate_serializer,
        &generator_serializer,
    ).unwrap();
    info!("Circuit loaded");

    let prover_circuit_data = recursive_circuit.aggregation.circuit.prover_only;
    let common_data = recursive_circuit.aggregation.circuit.common;
    let verifier_circuit_data = recursive_circuit.aggregation.circuit.verifier_only;

    let first_proof_data = fs::read(root_proof_file).expect("File not found");
    let first_proof: ProofWithPublicInputs<GoldilocksField, C, 2> = ProofWithPublicInputs::from_bytes(first_proof_data, &common_data.clone())
        .expect("Error loading proof data");
    let pis = first_proof.public_inputs.iter().take(PIS_NUM).map(|x| x.0.to_le_bytes()[0..4].to_vec()).concat();
    let mut pis_u64 = Vec::new();
    for i in (0..pis.len()).step_by(4) {
        let u64_value = u32::from_le_bytes([
            pis[i],
            pis[i + 1],
            pis[i + 2],
            pis[i + 3],
        ]);
        pis_u64.push(u64_value);
    }
    let mut input = [F::ZERO; PIS_NUM];
    for i in 0..PIS_NUM {
        input[i] = F::from_canonical_u32(pis_u64[i]);
    }

    let input_hash = PoseidonHash::hash_or_noop(&input);
    let mut timing = TimingTree::new("prove wrapper", log::Level::Info);
    let mut builder =
        CircuitBuilder::new(CircuitConfig::standard_recursion_config());

    let input_hash_targets = builder.add_virtual_hash();
    builder.register_public_inputs(&input_hash_targets.elements);
    let virtual_targets = builder.add_virtual_targets(PIS_NUM);
    let output_hash = builder.hash_or_noop::<PoseidonHash>(
        virtual_targets.clone()
    );
    let user_proof_with_pis_targets = builder.add_virtual_proof_with_pis(&common_data.clone());
    let all_pis_targets = user_proof_with_pis_targets.public_inputs.clone();
    let needed_pis_targets = all_pis_targets.iter().take(24).cloned().collect_vec();
    let user_verifier_data_targets = builder.add_virtual_verifier_data(common_data.fri_params.config.cap_height);
    builder.verify_proof::<C>(&user_proof_with_pis_targets, &user_verifier_data_targets, &common_data);
    for i in 0..PIS_NUM {
        builder.connect(needed_pis_targets[i], virtual_targets[i]);
    }
    let inner_proof_circuit_hash = user_verifier_data_targets.circuit_digest.clone();
    let out_inner_proof_circuit_hash = builder.add_virtual_hash();
    let inner_merkle_cap_target = user_verifier_data_targets.constants_sigmas_cap.clone();
    let out_merkle_cap_target = builder.add_virtual_cap(common_data.fri_params.config.cap_height);
    builder.connect_merkle_caps(&out_merkle_cap_target, &inner_merkle_cap_target);
    builder.connect_hashes(inner_proof_circuit_hash, out_inner_proof_circuit_hash);
    builder.connect_hashes(output_hash, input_hash_targets);
    let mut partial_witness = PartialWitness::<F>::new();
    partial_witness.set_hash_target(input_hash_targets, input_hash);
    partial_witness.set_target_arr(&virtual_targets, &input);
    partial_witness.set_proof_with_pis_target(&user_proof_with_pis_targets, &first_proof.clone());
    partial_witness.set_verifier_data_target(&user_verifier_data_targets, &verifier_circuit_data);
    partial_witness.set_hash_target(out_inner_proof_circuit_hash, prover_circuit_data.circuit_digest);
    partial_witness.set_cap_target(&out_merkle_cap_target, &prover_circuit_data.constants_sigmas_commitment.merkle_tree.cap);


    let circuit_data = builder.build::<C>();
    let proof_with_pis = circuit_data
        .prove(partial_witness)
        .expect("Failed to prove hash");
    timing.print();
    info!("PIs : {:?}", proof_with_pis.public_inputs);
    check_cyclic_proof_verifier_data(&first_proof, &verifier_circuit_data, &common_data).expect("Aggregation not verified");
    circuit_data.verify(proof_with_pis.clone())?;
    let actual_proof = proof_with_pis.to_bytes();
    fs::write(final_proof_file, actual_proof)?;
    Ok(())
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "INFO"));
}

fn main() -> Result<()> {
    init_logger();
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        error!("Usage: {} <circuit_file> <root_proof_file> <final_proof_file>", args[0]);
        std::process::exit(1);
    }
    let circuit_file = &args[1];
    let root_proof_file = &args[2];
    let final_proof_file = &args[3];
    wrap_proof(circuit_file, root_proof_file, final_proof_file)?;
    info!("OK");
    Ok(())
}
