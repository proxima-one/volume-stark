use std::fmt::Write;

use anyhow::Result;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_util::log2_strict;
use serde::Serialize;

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
#[derive(Serialize)]
pub struct VerifierConfig {
    pub hash_size: usize,
    pub field_size: usize,
    pub ext_field_size: usize,
    pub merkle_height_size: usize,

    pub num_wires_cap: usize,
    pub num_plonk_zs_partial_products_cap: usize,
    pub num_quotient_polys_cap: usize,

    // openings
    pub num_openings_constants: usize,
    pub num_openings_plonk_sigmas: usize,
    pub num_openings_wires: usize,
    pub num_openings_plonk_zs: usize,
    pub num_openings_plonk_zs_next: usize,
    pub num_openings_partial_products: usize,
    pub num_openings_quotient_polys: usize,

    // fri proof
    // .commit phase
    pub num_fri_commit_round: usize,
    pub fri_commit_merkle_cap_height: usize,
    // .query round
    pub num_fri_query_round: usize,
    // ..init
    pub num_fri_query_init_constants_sigmas_v: usize,
    pub num_fri_query_init_constants_sigmas_p: usize,
    pub num_fri_query_init_wires_v: usize,
    pub num_fri_query_init_wires_p: usize,
    pub num_fri_query_init_zs_partial_v: usize,
    pub num_fri_query_init_zs_partial_p: usize,
    pub num_fri_query_init_quotient_v: usize,
    pub num_fri_query_init_quotient_p: usize,
    // ..steps
    pub num_fri_query_step_v: Vec<usize>,
    pub num_fri_query_step_p: Vec<usize>,
    // .final poly
    pub num_fri_final_poly_ext_v: usize,
    // public inputs
    pub num_public_inputs: usize,
}

#[derive(Serialize)]
pub struct ProofForCircom {
    pub wires_cap: Vec<Vec<String>>,
    pub plonk_zs_partial_products_cap: Vec<Vec<String>>,
    pub quotient_polys_cap: Vec<Vec<String>>,

    pub openings_constants: Vec<Vec<String>>,
    pub openings_plonk_sigmas: Vec<Vec<String>>,
    pub openings_wires: Vec<Vec<String>>,
    pub openings_plonk_zs: Vec<Vec<String>>,
    pub openings_plonk_zs_next: Vec<Vec<String>>,
    pub openings_partial_products: Vec<Vec<String>>,
    pub openings_quotient_polys: Vec<Vec<String>>,

    pub fri_commit_phase_merkle_caps: Vec<Vec<Vec<String>>>,

    pub fri_query_init_constants_sigmas_v: Vec<Vec<String>>,
    pub fri_query_init_constants_sigmas_p: Vec<Vec<Vec<String>>>,
    pub fri_query_init_wires_v: Vec<Vec<String>>,
    pub fri_query_init_wires_p: Vec<Vec<Vec<String>>>,
    pub fri_query_init_zs_partial_v: Vec<Vec<String>>,
    pub fri_query_init_zs_partial_p: Vec<Vec<Vec<String>>>,
    pub fri_query_init_quotient_v: Vec<Vec<String>>,
    pub fri_query_init_quotient_p: Vec<Vec<Vec<String>>>,

    pub fri_query_step_v: Vec<String>,
    pub fri_query_step_p: Vec<String>,

    pub fri_final_poly_ext_v: Vec<Vec<String>>,
    pub fri_pow_witness: String,

    pub public_inputs: Vec<String>,
}

pub fn generate_verifier_config<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    pwpi: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<VerifierConfig> {
    let proof = &pwpi.proof;

    const HASH_SIZE: usize = 32;
    const FIELD_SIZE: usize = 8;
    const EXT_FIELD_SIZE: usize = 16;
    const MERKLE_HEIGHT_SIZE: usize = 1;

    let query_round_init_trees = &proof.opening_proof.query_round_proofs[0]
        .initial_trees_proof
        .evals_proofs;
    let query_round_steps = &proof.opening_proof.query_round_proofs[0].steps;

    let num_fri_query_step_v: Vec<usize> =
        query_round_steps.iter().map(|x| x.evals.len()).collect();
    let num_fri_query_step_p: Vec<usize> = query_round_steps
        .iter()
        .map(|x| x.merkle_proof.siblings.len())
        .collect();

    let conf = VerifierConfig {
        hash_size: HASH_SIZE,
        field_size: FIELD_SIZE,
        ext_field_size: EXT_FIELD_SIZE,
        merkle_height_size: MERKLE_HEIGHT_SIZE,

        num_wires_cap: proof.wires_cap.0.len(),
        num_plonk_zs_partial_products_cap: proof.plonk_zs_partial_products_cap.0.len(),
        num_quotient_polys_cap: proof.quotient_polys_cap.0.len(),

        num_openings_constants: proof.openings.constants.len(),
        num_openings_plonk_sigmas: proof.openings.plonk_sigmas.len(),
        num_openings_wires: proof.openings.wires.len(),
        num_openings_plonk_zs: proof.openings.plonk_zs.len(),
        num_openings_plonk_zs_next: proof.openings.plonk_zs_next.len(),
        num_openings_partial_products: proof.openings.partial_products.len(),
        num_openings_quotient_polys: proof.openings.quotient_polys.len(),

        num_fri_commit_round: proof.opening_proof.commit_phase_merkle_caps.len(),
        fri_commit_merkle_cap_height: proof.opening_proof.commit_phase_merkle_caps[0].0.len(),
        num_fri_query_round: proof.opening_proof.query_round_proofs.len(),
        num_fri_query_init_constants_sigmas_v: query_round_init_trees[0].0.len(),
        num_fri_query_init_constants_sigmas_p: query_round_init_trees[0].1.siblings.len(),
        num_fri_query_init_wires_v: query_round_init_trees[1].0.len(),
        num_fri_query_init_wires_p: query_round_init_trees[1].1.siblings.len(),
        num_fri_query_init_zs_partial_v: query_round_init_trees[2].0.len(),
        num_fri_query_init_zs_partial_p: query_round_init_trees[2].1.siblings.len(),
        num_fri_query_init_quotient_v: query_round_init_trees[3].0.len(),
        num_fri_query_init_quotient_p: query_round_init_trees[3].1.siblings.len(),
        num_fri_query_step_v,
        num_fri_query_step_p,
        num_fri_final_poly_ext_v: proof.opening_proof.final_poly.coeffs.len(),

        num_public_inputs: pwpi.public_inputs.len(),
    };
    Ok(conf)
}

pub fn generate_proof_base64<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    pwpi: &ProofWithPublicInputs<F, C, D>,
    conf: &VerifierConfig,
    //) -> anyhow::Result<String> {
) -> anyhow::Result<ProofForCircom> {
    let mut proof_size: usize =
        (conf.num_wires_cap + conf.num_plonk_zs_partial_products_cap + conf.num_quotient_polys_cap)
            * conf.hash_size;

    let mut wires_cap = vec![vec!["0".to_string(); 4]; conf.num_wires_cap];
    for i in 0..conf.num_wires_cap {
        let h = pwpi.proof.wires_cap.0[i].to_vec();
        for j in 0..h.len() {
            wires_cap[i][j] = h[j].to_canonical_u64().to_string();
        }
    }

    let mut plonk_zs_partial_products_cap =
        vec![vec!["0".to_string(); 4]; conf.num_plonk_zs_partial_products_cap];
    for i in 0..conf.num_plonk_zs_partial_products_cap {
        let h = pwpi.proof.plonk_zs_partial_products_cap.0[i].to_vec();
        for j in 0..h.len() {
            plonk_zs_partial_products_cap[i][j] = h[j].to_canonical_u64().to_string();
        }
    }

    let mut quotient_polys_cap = vec![vec!["0".to_string(); 4]; conf.num_quotient_polys_cap];
    for i in 0..conf.num_quotient_polys_cap {
        let h = pwpi.proof.quotient_polys_cap.0[i].to_vec();
        for j in 0..h.len() {
            quotient_polys_cap[i][j] = h[j].to_canonical_u64().to_string();
        }
    }

    proof_size += (conf.num_openings_constants
        + conf.num_openings_plonk_sigmas
        + conf.num_openings_wires
        + conf.num_openings_plonk_zs
        + conf.num_openings_plonk_zs_next
        + conf.num_openings_partial_products
        + conf.num_openings_quotient_polys)
        * conf.ext_field_size;

    let mut openings_constants = vec![vec!["0".to_string(); 2]; conf.num_openings_constants];
    for i in 0..conf.num_openings_constants {
        openings_constants[i][0] = pwpi.proof.openings.constants[i].to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_constants[i][1] = pwpi.proof.openings.constants[i].to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_plonk_sigmas = vec![vec!["0".to_string(); 2]; conf.num_openings_plonk_sigmas];
    for i in 0..conf.num_openings_plonk_sigmas {
        openings_plonk_sigmas[i][0] = pwpi.proof.openings.plonk_sigmas[i].to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_plonk_sigmas[i][1] = pwpi.proof.openings.plonk_sigmas[i].to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_wires = vec![vec!["0".to_string(); 2]; conf.num_openings_wires];
    for i in 0..conf.num_openings_wires {
        openings_wires[i][0] = pwpi.proof.openings.wires[i].to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_wires[i][1] = pwpi.proof.openings.wires[i].to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_plonk_zs = vec![vec!["0".to_string(); 2]; conf.num_openings_plonk_zs];
    for i in 0..conf.num_openings_plonk_zs {
        openings_plonk_zs[i][0] = pwpi.proof.openings.plonk_zs[i].to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_plonk_zs[i][1] = pwpi.proof.openings.plonk_zs[i].to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_plonk_zs_next =
        vec![vec!["0".to_string(); 2]; conf.num_openings_plonk_zs_next];
    for i in 0..conf.num_openings_plonk_zs_next {
        openings_plonk_zs_next[i][0] = pwpi.proof.openings.plonk_zs_next[i].to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_plonk_zs_next[i][1] = pwpi.proof.openings.plonk_zs_next[i].to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_partial_products =
        vec![vec!["0".to_string(); 2]; conf.num_openings_partial_products];
    for i in 0..conf.num_openings_partial_products {
        openings_partial_products[i][0] = pwpi.proof.openings.partial_products[i]
            .to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        openings_partial_products[i][1] = pwpi.proof.openings.partial_products[i]
            .to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }
    let mut openings_quotient_polys =
        vec![vec!["0".to_string(); 2]; conf.num_openings_quotient_polys];
    for i in 0..conf.num_openings_quotient_polys {
        openings_quotient_polys[i][0] = pwpi.proof.openings.quotient_polys[i].to_basefield_array()
            [0]
        .to_canonical_u64()
        .to_string();
        openings_quotient_polys[i][1] = pwpi.proof.openings.quotient_polys[i].to_basefield_array()
            [1]
        .to_canonical_u64()
        .to_string();
    }

    proof_size += (conf.num_fri_commit_round * conf.fri_commit_merkle_cap_height) * conf.hash_size;

    let mut fri_commit_phase_merkle_caps =
        vec![
            vec![vec!["0".to_string(); 4]; conf.fri_commit_merkle_cap_height];
            conf.num_fri_commit_round
        ];
    for i in 0..conf.num_fri_commit_round {
        let h = pwpi.proof.opening_proof.commit_phase_merkle_caps[i].flatten();
        assert_eq!(h.len(), 4 * conf.fri_commit_merkle_cap_height);
        for j in 0..conf.fri_commit_merkle_cap_height {
            for k in 0..4 {
                fri_commit_phase_merkle_caps[i][j][k] = h[j * 4 + k].to_canonical_u64().to_string();
            }
        }
    }

    proof_size += conf.num_fri_query_round
        * ((conf.num_fri_query_init_constants_sigmas_v
            + conf.num_fri_query_init_wires_v
            + conf.num_fri_query_init_zs_partial_v
            + conf.num_fri_query_init_quotient_v)
            * conf.field_size
            + (conf.num_fri_query_init_constants_sigmas_p
                + conf.num_fri_query_init_wires_p
                + conf.num_fri_query_init_zs_partial_p
                + conf.num_fri_query_init_quotient_p)
                * conf.hash_size
            + conf.merkle_height_size * 4);

    let mut sum: usize = 0;
    for i in conf
        .num_fri_query_step_v
        .iter()
        .zip_eq(conf.num_fri_query_step_p.clone())
    {
        sum += i.0 * conf.ext_field_size;
        sum += i.1 * conf.hash_size;
        sum += conf.merkle_height_size;
    }
    proof_size += conf.num_fri_query_round * sum;

    let mut fri_query_init_constants_sigmas_v =
        vec![
            vec!["0".to_string(); conf.num_fri_query_init_constants_sigmas_v];
            conf.num_fri_query_round
        ];
    let mut fri_query_init_wires_v =
        vec![vec!["0".to_string(); conf.num_fri_query_init_wires_v]; conf.num_fri_query_round];
    let mut fri_query_init_zs_partial_v =
        vec![vec!["0".to_string(); conf.num_fri_query_init_zs_partial_v]; conf.num_fri_query_round];
    let mut fri_query_init_quotient_v =
        vec![vec!["0".to_string(); conf.num_fri_query_init_quotient_v]; conf.num_fri_query_round];

    let mut fri_query_init_constants_sigmas_p =
        vec![
            vec![vec!["0".to_string(); 4]; conf.num_fri_query_init_constants_sigmas_p];
            conf.num_fri_query_round
        ];
    let mut fri_query_init_wires_p =
        vec![
            vec![vec!["0".to_string(); 4]; conf.num_fri_query_init_wires_p];
            conf.num_fri_query_round
        ];
    let mut fri_query_init_zs_partial_p =
        vec![
            vec![vec!["0".to_string(); 4]; conf.num_fri_query_init_zs_partial_p];
            conf.num_fri_query_round
        ];
    let mut fri_query_init_quotient_p =
        vec![
            vec![vec!["0".to_string(); 4]; conf.num_fri_query_init_quotient_p];
            conf.num_fri_query_round
        ];

    let mut fri_query_step_v: Vec<String> = vec![];
    let mut fri_query_step_p: Vec<String> = vec![];
    for i in conf
        .num_fri_query_step_v
        .iter()
        .zip_eq(conf.num_fri_query_step_p.clone())
    {
        fri_query_step_v.append(&mut vec![
            "0".to_string();
            2 * (*i.0) * conf.num_fri_query_round
        ]);
        fri_query_step_p.append(&mut vec![
            "0".to_string();
            4 * (i.1) * conf.num_fri_query_round
        ]);
    }

    let mut sv1: usize = 0;
    let mut sv2: usize = 0;
    let mut sp1: usize = 0;
    let mut sp2: usize = 0;
    for i in 0..conf.num_fri_query_round {
        assert_eq!(
            pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs
                .len(),
            4
        );
        for j in 0..conf.num_fri_query_init_constants_sigmas_v {
            fri_query_init_constants_sigmas_v[i][j] = pwpi.proof.opening_proof.query_round_proofs
                [i]
                .initial_trees_proof
                .evals_proofs[0]
                .0[j]
                .to_canonical_u64()
                .to_string();
        }

        for j in 0..conf.num_fri_query_init_wires_v {
            fri_query_init_wires_v[i][j] = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[1]
                .0[j]
                .to_canonical_u64()
                .to_string();
        }
        for j in 0..conf.num_fri_query_init_zs_partial_v {
            fri_query_init_zs_partial_v[i][j] = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[2]
                .0[j]
                .to_canonical_u64()
                .to_string();
        }
        for j in 0..conf.num_fri_query_init_quotient_v {
            fri_query_init_quotient_v[i][j] = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[3]
                .0[j]
                .to_canonical_u64()
                .to_string();
        }
        for j in 0..conf.num_fri_query_init_constants_sigmas_p {
            let h = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[0]
                .1
                .siblings[j]
                .to_vec();
            assert_eq!(h.len(), 4);
            for k in 0..4 {
                fri_query_init_constants_sigmas_p[i][j][k] = h[k].to_canonical_u64().to_string();
            }
        }
        for j in 0..conf.num_fri_query_init_wires_p {
            let h = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[1]
                .1
                .siblings[j]
                .to_vec();
            assert_eq!(h.len(), 4);
            for k in 0..4 {
                fri_query_init_wires_p[i][j][k] = h[k].to_canonical_u64().to_string();
            }
        }
        for j in 0..conf.num_fri_query_init_zs_partial_p {
            let h = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[2]
                .1
                .siblings[j]
                .to_vec();
            assert_eq!(h.len(), 4);
            for k in 0..4 {
                fri_query_init_zs_partial_p[i][j][k] = h[k].to_canonical_u64().to_string();
            }
        }
        for j in 0..conf.num_fri_query_init_quotient_p {
            let h = pwpi.proof.opening_proof.query_round_proofs[i]
                .initial_trees_proof
                .evals_proofs[3]
                .1
                .siblings[j]
                .to_vec();
            assert_eq!(h.len(), 4);
            for k in 0..4 {
                fri_query_init_quotient_p[i][j][k] = h[k].to_canonical_u64().to_string();
            }
        }
        for n in 0..conf.num_fri_query_step_v.len() {
            for j in 0..conf.num_fri_query_step_v[n] {
                fri_query_step_v[sv1 + sv2 + j * 2 + 0] =
                    pwpi.proof.opening_proof.query_round_proofs[i].steps[n].evals[j]
                        .to_basefield_array()[0]
                        .to_canonical_u64()
                        .to_string();
                fri_query_step_v[sv1 + sv2 + j * 2 + 1] =
                    pwpi.proof.opening_proof.query_round_proofs[i].steps[n].evals[j]
                        .to_basefield_array()[1]
                        .to_canonical_u64()
                        .to_string();
            }
            sv2 += 2 * conf.num_fri_query_step_v[n];
        }
        sv1 += sv2;
        sv2 = 0;
        for n in 0..conf.num_fri_query_step_p.len() {
            for j in 0..conf.num_fri_query_step_p[n] {
                let vec = pwpi.proof.opening_proof.query_round_proofs[i].steps[n]
                    .merkle_proof
                    .siblings[j]
                    .to_vec();
                assert_eq!(vec.len(), 4);
                for k in 0..4 {
                    fri_query_step_p[sp1 + sp2 + j * 4 + k] = vec[k].to_canonical_u64().to_string();
                }
            }
            sp2 += 4 * conf.num_fri_query_step_p[n];
        }
        sp1 += sp2;
        sp2 = 0;
    }

    proof_size += conf.num_fri_final_poly_ext_v * conf.ext_field_size;

    let mut fri_final_poly_ext_v = vec![vec!["0".to_string(); 2]; conf.num_fri_final_poly_ext_v];
    for i in 0..conf.num_fri_final_poly_ext_v {
        fri_final_poly_ext_v[i][0] = pwpi.proof.opening_proof.final_poly.coeffs[i]
            .to_basefield_array()[0]
            .to_canonical_u64()
            .to_string();
        fri_final_poly_ext_v[i][1] = pwpi.proof.opening_proof.final_poly.coeffs[i]
            .to_basefield_array()[1]
            .to_canonical_u64()
            .to_string();
    }

    proof_size += conf.field_size;

    proof_size += conf.num_public_inputs * conf.field_size;

    let mut public_inputs = vec!["0".to_string(); conf.num_public_inputs];
    for i in 0..conf.num_public_inputs {
        public_inputs[i] = pwpi.public_inputs[i].to_canonical_u64().to_string();
    }

    let circom_proof = ProofForCircom {
        wires_cap,
        plonk_zs_partial_products_cap,
        quotient_polys_cap,
        openings_constants,
        openings_plonk_sigmas,
        openings_wires,
        openings_plonk_zs,
        openings_plonk_zs_next,
        openings_partial_products,
        openings_quotient_polys,
        fri_commit_phase_merkle_caps,
        fri_query_init_constants_sigmas_v,
        fri_query_init_constants_sigmas_p,
        fri_query_init_wires_v,
        fri_query_init_wires_p,
        fri_query_init_zs_partial_v,
        fri_query_init_zs_partial_p,
        fri_query_init_quotient_v,
        fri_query_init_quotient_p,
        fri_query_step_v,
        fri_query_step_p,
        fri_final_poly_ext_v,
        fri_pow_witness: pwpi
            .proof
            .opening_proof
            .pow_witness
            .to_canonical_u64()
            .to_string(),
        public_inputs,
    };

    let proof_bytes = pwpi.to_bytes();
    assert_eq!(proof_bytes.len(), proof_size);
    println!("proof size: {}", proof_size);

    //Ok(serde_json::to_string(&circom_proof).unwrap())
    Ok(circom_proof)
}

pub fn generate_circom_verifier<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    conf: &VerifierConfig,
    common: &CommonCircuitData<F, D>,
    verifier_only: &VerifierOnlyCircuitData<C, D>,
    sv_len: usize,
    sp_len: usize,
) -> anyhow::Result<(String, String)> {
    assert_eq!(F::BITS, 64);
    assert_eq!(F::Extension::BITS, 128);
    println!("Generating Circom files ...");

    // Load template contract
    let mut constants = std::fs::read_to_string("./src/template_constants.circom")
        .expect("Something went wrong reading the file");

    let k_is = &common.k_is;
    let mut k_is_str = "".to_owned();
    for i in 0..k_is.len() {
        k_is_str += &*("  k_is[".to_owned()
            + &*i.to_string()
            + "] = "
            + &*k_is[i].to_canonical_u64().to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_K_IS;\n", &*k_is_str);

    let reduction_arity_bits = &common.fri_params.reduction_arity_bits;
    let mut reduction_arity_bits_str = "".to_owned();
    for i in 0..reduction_arity_bits.len() {
        reduction_arity_bits_str += &*("  bits[".to_owned()
            + &*i.to_string()
            + "] = "
            + &*reduction_arity_bits[i].to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_REDUCTION_ARITY_BITS;\n", &*reduction_arity_bits_str);
    constants = constants.replace(
        "$NUM_REDUCTION_ARITY_BITS",
        &*reduction_arity_bits.len().to_string(),
    );

    constants = constants.replace("$NUM_PUBLIC_INPUTS", &*conf.num_public_inputs.to_string());
    constants = constants.replace("$NUM_WIRES_CAP", &*conf.num_wires_cap.to_string());
    constants = constants.replace(
        "$NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP",
        &*conf.num_plonk_zs_partial_products_cap.to_string(),
    );
    constants = constants.replace(
        "$NUM_QUOTIENT_POLYS_CAP",
        &*conf.num_quotient_polys_cap.to_string(),
    );
    constants = constants.replace(
        "$NUM_OPENINGS_CONSTANTS",
        &*conf.num_openings_constants.to_string(),
    );
    constants = constants.replace(
        "$NUM_OPENINGS_PLONK_SIGMAS",
        &*conf.num_openings_plonk_sigmas.to_string(),
    );
    constants = constants.replace("$NUM_OPENINGS_WIRES", &*conf.num_openings_wires.to_string());
    constants = constants.replace(
        "$NUM_OPENINGS_PLONK_ZS0",
        &*conf.num_openings_plonk_zs.to_string(),
    );
    constants = constants.replace(
        "$NUM_OPENINGS_PLONK_ZS_NEXT",
        &*conf.num_openings_plonk_zs_next.to_string(),
    );
    constants = constants.replace(
        "$NUM_OPENINGS_PARTIAL_PRODUCTS",
        &*conf.num_openings_partial_products.to_string(),
    );
    constants = constants.replace(
        "$NUM_OPENINGS_QUOTIENT_POLYS",
        &*conf.num_openings_quotient_polys.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_COMMIT_ROUND",
        &*conf.num_fri_commit_round.to_string(),
    );
    constants = constants.replace(
        "$FRI_COMMIT_MERKLE_CAP_HEIGHT",
        &*conf.fri_commit_merkle_cap_height.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_ROUND",
        &*conf.num_fri_query_round.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V",
        &*conf.num_fri_query_init_constants_sigmas_v.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P",
        &*conf.num_fri_query_init_constants_sigmas_p.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_WIRES_V",
        &*conf.num_fri_query_init_wires_v.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_WIRES_P",
        &*conf.num_fri_query_init_wires_p.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_ZS_PARTIAL_V",
        &*conf.num_fri_query_init_zs_partial_v.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_ZS_PARTIAL_P",
        &*conf.num_fri_query_init_zs_partial_p.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_QUOTIENT_V",
        &*conf.num_fri_query_init_quotient_v.to_string(),
    );
    constants = constants.replace(
        "$NUM_FRI_QUERY_INIT_QUOTIENT_P",
        &*conf.num_fri_query_init_quotient_p.to_string(),
    );

    constants = constants.replace("$FRI_QUERY_STEP_V_LEN", &*sv_len.to_string());
    constants = constants.replace("$FRI_QUERY_STEP_P_LEN", &*sp_len.to_string());

    let fri_query_step_v = &conf.num_fri_query_step_v;
    let mut fri_query_step_v_str = "".to_owned();
    for i in 0..fri_query_step_v.len() {
        fri_query_step_v_str += &*("  bits[".to_owned()
            + &*i.to_string()
            + "] = "
            + &*fri_query_step_v[i].to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_FRI_QUERY_STEP_V;\n", &*fri_query_step_v_str);
    constants = constants.replace(
        "$NUM_FRI_QUERY_STEP_V",
        &*fri_query_step_v.len().to_string(),
    );

    let fri_query_step_p = &conf.num_fri_query_step_p;
    let mut fri_query_step_p_str = "".to_owned();
    for i in 0..fri_query_step_p.len() {
        fri_query_step_p_str += &*("  bits[".to_owned()
            + &*i.to_string()
            + "] = "
            + &*fri_query_step_p[i].to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_FRI_QUERY_STEP_P;\n", &*fri_query_step_p_str);
    constants = constants.replace(
        "$NUM_FRI_QUERY_STEP_P",
        &*fri_query_step_p.len().to_string(),
    );

    constants = constants.replace(
        "$NUM_FRI_FINAL_POLY_EXT_V",
        &*conf.num_fri_final_poly_ext_v.to_string(),
    );
    constants = constants.replace(
        "$NUM_CHALLENGES",
        &*common.config.num_challenges.to_string(),
    );

    let circuit_digest = verifier_only.circuit_digest.to_vec();
    let mut circuit_digest_str = "".to_owned();
    for i in 0..circuit_digest.len() {
        circuit_digest_str += &*("  cd[".to_owned()
            + &*i.to_string()
            + "] = "
            + &*circuit_digest[i].to_canonical_u64().to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_CIRCUIT_DIGEST;\n", &*circuit_digest_str);

    constants = constants.replace(
        "$FRI_RATE_BITS",
        &*common.config.fri_config.rate_bits.to_string(),
    );
    constants = constants.replace("$DEGREE_BITS", &*common.degree_bits().to_string());
    constants = constants.replace(
        "$NUM_GATE_CONSTRAINTS",
        &*common.num_gate_constraints.to_string(),
    );
    constants = constants.replace(
        "$QUOTIENT_DEGREE_FACTOR",
        &*common.quotient_degree_factor.to_string(),
    );
    constants = constants.replace(
        "$MIN_FRI_POW_RESPONSE",
        &*(common.config.fri_config.proof_of_work_bits + (64 - F::order().bits()) as u32)
            .to_string(),
    );
    let g = F::Extension::primitive_root_of_unity(common.degree_bits());
    constants = constants.replace(
        "$G_FROM_DEGREE_BITS_0",
        &g.to_basefield_array()[0].to_string(),
    );
    constants = constants.replace(
        "$G_FROM_DEGREE_BITS_1",
        &g.to_basefield_array()[1].to_string(),
    );
    let log_n = log2_strict(common.fri_params.lde_size());
    constants = constants.replace("$LOG_SIZE_OF_LDE_DOMAIN", &*log_n.to_string());
    constants = constants.replace(
        "$MULTIPLICATIVE_GROUP_GENERATOR",
        &*F::MULTIPLICATIVE_GROUP_GENERATOR.to_string(),
    );
    constants = constants.replace(
        "$PRIMITIVE_ROOT_OF_UNITY_LDE",
        &*F::primitive_root_of_unity(log_n).to_string(),
    );
    // TODO: add test with config zero_knoledge = true
    constants = constants.replace(
        "$ZERO_KNOWLEDGE",
        &*common.config.zero_knowledge.to_string(),
    );
    let g = F::primitive_root_of_unity(1);
    constants = constants.replace("$G_ARITY_BITS_1", &g.to_string());
    let g = F::primitive_root_of_unity(2);
    constants = constants.replace("$G_ARITY_BITS_2", &g.to_string());
    let g = F::primitive_root_of_unity(3);
    constants = constants.replace("$G_ARITY_BITS_3", &g.to_string());
    let g = F::primitive_root_of_unity(4);
    constants = constants.replace("$G_ARITY_BITS_4", &g.to_string());

    // Load gate template
    let mut gates_lib = std::fs::read_to_string("./src/template_gates.circom")
        .expect("Something went wrong reading the file");

    let num_selectors = common.selectors_info.num_selectors();
    constants = constants.replace("$NUM_SELECTORS", &num_selectors.to_string());
    let mut evaluate_gate_constraints_str = "".to_owned();
    let mut last_component_name = "".to_owned();
    for (row, gate) in common.gates.iter().enumerate() {
        if gate.0.id().eq("NoopGate") {
            continue;
        }
        let selector_index = common.selectors_info.selector_indices[row];
        let group_range = common.selectors_info.groups[selector_index].clone();
        let mut c = 0;

        evaluate_gate_constraints_str = evaluate_gate_constraints_str + "\n";
        let mut filter_str = "filter <== ".to_owned();
        let filter_chain = group_range
            .filter(|&i| i != row)
            .chain((num_selectors > 1).then_some(u32::MAX as usize));
        for i in filter_chain {
            filter_str += &*("GlExtMul()(GlExtSub()(GlExt(".to_owned()
                + &i.to_string()
                + ", 0)(), "
                + "constants["
                + &*selector_index.to_string()
                + "]), ");
            c = c + 1;
        }
        filter_str += &*("GlExt(1, 0)()".to_owned());
        for _ in 0..c {
            filter_str = filter_str + ")";
        }
        filter_str = filter_str + ";";

        let mut eval_str = "  // ".to_owned() + &*gate.0.id() + "\n";
        let gate_name = gate.0.id();
        if gate_name.eq("PublicInputGate")
            || gate_name[0..11].eq("BaseSumGate")
            || gate_name[0..12].eq("ConstantGate")
            || gate_name[0..12].eq("PoseidonGate")
            || gate_name[0..12].eq("ReducingGate")
            || gate_name[0..14].eq("ArithmeticGate")
            || gate_name[0..15].eq("PoseidonMdsGate")
            || gate_name[0..16].eq("MulExtensionGate")
            || gate_name[0..16].eq("RandomAccessGate")
            || gate_name[0..18].eq("ExponentiationGate")
            || gate_name[0..21].eq("ReducingExtensionGate")
            || gate_name[0..23].eq("ArithmeticExtensionGate")
            || gate_name[0..26].eq("LowDegreeInterpolationGate")
        {
            //TODO: use num_coeff as a param (same TODO for other gates)
            let mut code_str = gate.0.export_circom_verification_code();
            code_str = code_str.replace("$SET_FILTER;", &*filter_str);
            let v: Vec<&str> = code_str.split(' ').collect();
            let template_name = &v[1][0..v[1].len() - 2];
            let component_name = "c_".to_owned() + template_name;
            eval_str +=
                &*("  component ".to_owned() + &*component_name + " = " + template_name + "();\n");
            eval_str += &*("  ".to_owned() + &*component_name + ".constants <== constants;\n");
            eval_str += &*("  ".to_owned() + &*component_name + ".wires <== wires;\n");
            eval_str += &*("  ".to_owned()
                + &*component_name
                + ".public_input_hash <== public_input_hash;\n");
            if last_component_name == "" {
                eval_str +=
                    &*("  ".to_owned() + &*component_name + ".constraints <== constraints;\n");
            } else {
                eval_str += &*("  ".to_owned()
                    + &*component_name
                    + ".constraints <== "
                    + &*last_component_name
                    + ".out;\n");
            }
            gates_lib += &*(code_str + "\n");
            last_component_name = component_name.clone();
        } else {
            todo!("{}", "gate not implemented: ".to_owned() + &gate_name)
        }
        evaluate_gate_constraints_str += &*eval_str;
    }

    evaluate_gate_constraints_str += &*("  out <== ".to_owned() + &*last_component_name + ".out;");
    gates_lib = gates_lib.replace(
        "  $EVALUATE_GATE_CONSTRAINTS;",
        &evaluate_gate_constraints_str,
    );

    gates_lib = gates_lib.replace(
        "$NUM_GATE_CONSTRAINTS",
        &*common.num_gate_constraints.to_string(),
    );
    gates_lib = gates_lib.replace("$NUM_SELECTORS", &num_selectors.to_string());
    gates_lib = gates_lib.replace(
        "$NUM_OPENINGS_CONSTANTS",
        &*conf.num_openings_constants.to_string(),
    );
    gates_lib = gates_lib.replace("$NUM_OPENINGS_WIRES", &*conf.num_openings_wires.to_string());
    gates_lib = gates_lib.replace("$F_EXT_W", &*F::W.to_basefield_array()[0].to_string());

    let sigma_cap_count = 1 << common.config.fri_config.cap_height;
    constants = constants.replace("$SIGMA_CAP_COUNT", &*sigma_cap_count.to_string());

    let mut sigma_cap_str = "".to_owned();
    for i in 0..sigma_cap_count {
        let cap = verifier_only.constants_sigmas_cap.0[i];
        let hash = cap.to_vec();
        assert_eq!(hash.len(), 4);
        sigma_cap_str += &*("  sc[".to_owned()
            + &*i.to_string()
            + "][0] = "
            + &*hash[0].to_canonical_u64().to_string()
            + ";\n");
        sigma_cap_str += &*("  sc[".to_owned()
            + &*i.to_string()
            + "][1] = "
            + &*hash[1].to_canonical_u64().to_string()
            + ";\n");
        sigma_cap_str += &*("  sc[".to_owned()
            + &*i.to_string()
            + "][2] = "
            + &*hash[2].to_canonical_u64().to_string()
            + ";\n");
        sigma_cap_str += &*("  sc[".to_owned()
            + &*i.to_string()
            + "][3] = "
            + &*hash[3].to_canonical_u64().to_string()
            + ";\n");
    }
    constants = constants.replace("  $SET_SIGMA_CAP;\n", &*sigma_cap_str);

    Ok((constants, gates_lib))
}

/*#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use crate::config::PoseidonBN128GoldilocksConfig;
    use anyhow::Result;
    use plonky2::field::extension::Extendable;
    use plonky2::fri::reduction_strategies::FriReductionStrategy;
    use plonky2::fri::FriConfig;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
    use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::{
        gates::noop::NoopGate,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig,
        },
    };

    use crate::circom_verifier::{
        generate_circom_verifier, generate_proof_base64, generate_verifier_config, recursive_proof,
    };

    /// Creates a dummy proof which should have roughly `num_dummy_gates` gates.
    fn dummy_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        config: &CircuitConfig,
        num_dummy_gates: u64,
        num_public_inputs: u64,
    ) -> Result<(
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
        CommonCircuitData<F, D>,
    )>
    where
        [(); C::Hasher::HASH_SIZE]:,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for _ in 0..num_dummy_gates {
            builder.add_gate(NoopGate, vec![]);
        }
        let mut pi = Vec::new();
        if num_public_inputs > 0 {
            pi = builder.add_virtual_targets(num_public_inputs as usize);
            builder.register_public_inputs(&pi);
        }

        let data = builder.build::<C>();
        let mut inputs = PartialWitness::new();
        if num_public_inputs > 0 {
            for i in 0..num_public_inputs {
                inputs.set_target(pi[i as usize], F::from_canonical_u64(i));
            }
        }
        let proof = data.prove(inputs)?;
        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }

    #[test]
    fn test_verifier_without_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonBN128GoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let standard_config = CircuitConfig::standard_recursion_config();
        // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
        let high_rate_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..standard_config.fri_config.clone()
            },
            ..standard_config
        };
        // A final proof, optimized for size.
        let final_config = CircuitConfig {
            num_routed_wires: 37,
            fri_config: FriConfig {
                rate_bits: 8,
                cap_height: 0,
                proof_of_work_bits: 20,
                reduction_strategy: FriReductionStrategy::MinSize(None),
                num_query_rounds: 10,
            },
            ..high_rate_config
        };

        let (proof, vd, cd) = dummy_proof::<F, C, D>(&final_config, 4_000, 0)?;

        let conf = generate_verifier_config(&proof)?;
        let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd)?;

        let mut circom_file = File::create("./circom/circuits/constants.circom")?;
        circom_file.write_all(circom_constants.as_bytes())?;
        circom_file = File::create("./circom/circuits/gates.circom")?;
        circom_file.write_all(circom_gates.as_bytes())?;

        let proof_json = generate_proof_base64(&proof, &conf)?;

        if !Path::new("./circom/test/data").is_dir() {
            std::fs::create_dir("./circom/test/data")?;
        }

        let mut proof_file = File::create("./circom/test/data/proof.json")?;
        //proof_file.write_all(proof_json.as_bytes())?;
        proof_file.write_all(serde_json::to_string(&proof_json).unwrap().as_bytes())?;

        let mut conf_file = File::create("./circom/test/data/conf.json")?;
        conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

        Ok(())
    }

    #[test]
    fn test_verifier_with_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonBN128GoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let standard_config = CircuitConfig::standard_recursion_config();
        let (proof, vd, cd) = dummy_proof::<F, C, D>(&standard_config, 4_000, 4)?;

        let conf = generate_verifier_config(&proof)?;
        let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd)?;

        let mut circom_file = File::create("./circom/circuits/constants.circom")?;
        circom_file.write_all(circom_constants.as_bytes())?;
        circom_file = File::create("./circom/circuits/gates.circom")?;
        circom_file.write_all(circom_gates.as_bytes())?;

        let proof_json = generate_proof_base64(&proof, &conf)?;

        if !Path::new("./circom/test/data").is_dir() {
            std::fs::create_dir("./circom/test/data")?;
        }

        let mut proof_file = File::create("./circom/test/data/proof.json")?;
        //proof_file.write_all(proof_json.as_bytes())?;
        proof_file.write_all(serde_json::to_string(&proof_json).unwrap().as_bytes())?;

        let mut conf_file = File::create("./circom/test/data/conf.json")?;
        conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

        Ok(())
    }

    #[test]
    fn test_recursive_verifier() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let standard_config = CircuitConfig::standard_recursion_config();

        let (proof, vd, cd) = dummy_proof::<F, C, D>(&standard_config, 4_000, 4)?;
        let (proof, vd, cd) =
            recursive_proof::<F, C, C, D>(proof, vd, cd, &standard_config, None, true, true)?;

        type CBn128 = PoseidonBN128GoldilocksConfig;
        let (proof, vd, cd) =
            recursive_proof::<F, CBn128, C, D>(proof, vd, cd, &standard_config, None, true, true)?;

        let conf = generate_verifier_config(&proof)?;
        let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd)?;

        let mut circom_file = File::create("./circom/circuits/constants.circom")?;
        circom_file.write_all(circom_constants.as_bytes())?;
        circom_file = File::create("./circom/circuits/gates.circom")?;
        circom_file.write_all(circom_gates.as_bytes())?;

        let proof_json = generate_proof_base64(&proof, &conf)?;

        if !Path::new("./circom/test/data").is_dir() {
            std::fs::create_dir("./circom/test/data")?;
        }

        let mut proof_file = File::create("./circom/test/data/proof.json")?;
        //proof_file.write_all(proof_json.as_bytes())?;
        proof_file.write_all(serde_json::to_string(&proof_json).unwrap().as_bytes())?;

        let mut conf_file = File::create("./circom/test/data/conf.json")?;
        conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

        Ok(())
    }

    #[test]
    fn test_aggregation_verifier() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let standard_config = CircuitConfig::standard_recursion_config();

        let proof1 = fib_proof::<F, C, D>(1)?;
        let proof2 = fib_proof::<F, C, D>(2)?;

        let agg_proof =
            aggregation_proof::<F, C, C, D>(&proof1, Some(proof2), &standard_config, None)?;
        let (agg_p, vd, cd) = agg_proof;

        // let (proof, vd, cd) =
        //     recursive_proof::<F, C, C, D>(proof, vd, cd, &standard_config, None, true, true)?;

        type CBn128 = PoseidonBN128GoldilocksConfig;
        let (recursive_proof, recursive_vd, recursive_cd) =
            recursive_proof::<F, CBn128, C, D>(agg_p, vd, cd, &standard_config, None, true, true)?;

        let conf = generate_verifier_config(&recursive_proof)?;
        let (circom_constants, circom_gates) =
            generate_circom_verifier(&conf, &recursive_cd, &recursive_vd)?;

        let mut circom_file = File::create("./circom/circuits/constants.circom")?;
        circom_file.write_all(circom_constants.as_bytes())?;
        circom_file = File::create("./circom/circuits/gates.circom")?;
        circom_file.write_all(circom_gates.as_bytes())?;

        let proof_json = generate_proof_base64(&recursive_proof, &conf)?;

        if !Path::new("./circom/test/data").is_dir() {
            std::fs::create_dir("./circom/test/data")?;
        }

        let mut proof_file = File::create("./circom/test/data/proof.json")?;
        //proof_file.write_all(proof_json.as_bytes())?;
        proof_file.write_all(serde_json::to_string(&proof_json).unwrap().as_bytes())?;

        let mut conf_file = File::create("./circom/test/data/conf.json")?;
        conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

        Ok(())
    }
}
*/
