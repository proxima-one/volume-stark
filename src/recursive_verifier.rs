use std::fmt::Debug;

use anyhow::{ensure, Result};
use ethereum_types::BigEndianHash;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::fri::witness_util::set_fri_proof_target;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::gate::GateRef;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::challenger::{Challenger, RecursiveChallenger};
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::reducing::ReducingFactorTarget;
use plonky2::util::serialization::{
    Buffer, GateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2::with_context;
use plonky2_util::log2_ceil;

use crate::all_stark::{Table, NUM_TABLES};
use crate::config::StarkConfig;
use crate::constraint_consumer::RecursiveConstraintConsumer;
use crate::cross_table_lookup::{verify_cross_table_lookups, CrossTableLookup, CtlCheckVarsTarget};
use crate::permutation::{
    get_grand_product_challenge_set, GrandProductChallenge, GrandProductChallengeSet,
    PermutationCheckDataTarget,
};
use crate::proof::{
    // BlockMetadata,
    // BlockMetadataTarget,
    PublicValues,
    PublicValuesTarget,
    StarkOpeningSetTarget,
    StarkProof,
    StarkProofChallengesTarget,
    StarkProofTarget,
    StarkProofWithMetadata,
    // TrieRoots,
    // TrieRootsTarget,
};
use crate::stark::Stark;
use crate::util::u256_limbs;
use crate::vanishing_poly::eval_vanishing_poly_circuit;
use crate::vars::StarkEvaluationTargets;

/// Table-wise recursive proofs of an `AllProof`.
pub struct RecursiveAllProof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub recursive_proofs: [ProofWithPublicInputs<F, C, D>; NUM_TABLES],
}

pub(crate) struct PublicInputs<
    T: Copy + Default + Eq + PartialEq + Debug,
    P: PlonkyPermutation<T, HC>,
> {
    pub(crate) trace_cap: Vec<Vec<T>>,
    pub(crate) ctl_zs_last: Vec<T>,
    pub(crate) ctl_challenges: GrandProductChallengeSet<T>,
    pub(crate) challenger_state_before: P,
    pub(crate) challenger_state_after: P,
}

impl<T: Copy + Debug + Default + Eq + PartialEq, P: PlonkyPermutation<T, HC>> PublicInputs<T, P> {
    pub(crate) fn from_vec(v: &[T], config: &StarkConfig) -> Self {
        // TODO: Document magic number 4; probably comes from
        // Ethereum 256 bits = 4 * Goldilocks 64 bits
        let nelts = config.fri_config.num_cap_elements();
        let mut trace_cap = Vec::with_capacity(nelts);
        for i in 0..nelts {
            trace_cap.push(v[4 * i..4 * (i + 1)].to_vec());
        }
        let mut iter = v.iter().copied().skip(4 * nelts);
        let ctl_challenges = GrandProductChallengeSet {
            challenges: (0..config.num_challenges)
                .map(|_| GrandProductChallenge {
                    beta: iter.next().unwrap(),
                    gamma: iter.next().unwrap(),
                })
                .collect(),
        };
        let challenger_state_before = P::new(&mut iter);
        let challenger_state_after = P::new(&mut iter);
        let ctl_zs_last: Vec<_> = iter.collect();

        Self {
            trace_cap,
            ctl_zs_last,
            ctl_challenges,
            challenger_state_before,
            challenger_state_after,
        }
    }
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    RecursiveAllProof<F, C, D>
{
    /// Verify every recursive proof.
    pub fn verify(
        self,
        verifier_data: &[VerifierCircuitData<F, C, D>; NUM_TABLES],
        cross_table_lookups: Vec<CrossTableLookup<F>>,
        inner_config: &StarkConfig,
    ) -> Result<()> {
        let pis: [_; NUM_TABLES] = core::array::from_fn(|i| {
            PublicInputs::<F, <C::Hasher as Hasher<F>>::Permutation>::from_vec(
                &self.recursive_proofs[i].public_inputs,
                inner_config,
            )
        });

        let mut challenger = Challenger::<F, C::Hasher>::new();
        for pi in &pis {
            for h in &pi.trace_cap {
                challenger.observe_elements(h);
            }
        }
        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, inner_config.num_challenges);
        // Check that the correct CTL challenges are used in every proof.
        for pi in &pis {
            ensure!(ctl_challenges == pi.ctl_challenges);
        }

        let state = challenger.compact();
        ensure!(state == pis[0].challenger_state_before);
        // Check that the challenger state is consistent between proofs.
        for i in 1..NUM_TABLES {
            ensure!(pis[i].challenger_state_before == pis[i - 1].challenger_state_after);
        }

        // Dummy values which will make the check fail.
        // TODO: Fix this if the code isn't deprecated.
        let mut extra_looking_products = Vec::new();
        for i in 0..NUM_TABLES {
            extra_looking_products.push(Vec::new());
            for _ in 0..inner_config.num_challenges {
                extra_looking_products[i].push(F::ONE);
            }
        }

        // Verify the CTL checks.
        verify_cross_table_lookups::<F, D>(
            &cross_table_lookups,
            pis.map(|p| p.ctl_zs_last),
            extra_looking_products,
            inner_config,
        )?;

        // Verify the proofs.
        for (proof, verifier_data) in self.recursive_proofs.into_iter().zip(verifier_data) {
            verifier_data.verify(proof)?;
        }
        Ok(())
    }
}

/// Represents a circuit which recursively verifies a STARK proof.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct StarkWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F, HC>,
{
    pub(crate) circuit: CircuitData<F, C, D>,
    pub(crate) stark_proof_target: StarkProofTarget<D>,
    pub(crate) ctl_challenges_target: GrandProductChallengeSet<Target>,
    pub(crate) init_challenger_state_target:
        <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation,
    pub(crate) zero_target: Target,
}

impl<F, C, const D: usize> StarkWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F, HC>,
{
    pub fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_vec(self.init_challenger_state_target.as_ref())?;
        buffer.write_target(self.zero_target)?;
        self.stark_proof_target.to_buffer(buffer)?;
        self.ctl_challenges_target.to_buffer(buffer)?;
        Ok(())
    }

    pub fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let target_vec = buffer.read_target_vec()?;
        let init_challenger_state_target =
            <C::Hasher as AlgebraicHasher<F, HC>>::AlgebraicPermutation::new(
                target_vec.into_iter(),
            );
        let zero_target = buffer.read_target()?;
        let stark_proof_target = StarkProofTarget::from_buffer(buffer)?;
        let ctl_challenges_target = GrandProductChallengeSet::from_buffer(buffer)?;
        Ok(Self {
            circuit,
            stark_proof_target,
            ctl_challenges_target,
            init_challenger_state_target,
            zero_target,
        })
    }

    pub(crate) fn prove(
        &self,
        proof_with_metadata: &StarkProofWithMetadata<F, C, D>,
        ctl_challenges: &GrandProductChallengeSet<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut inputs = PartialWitness::new();

        set_stark_proof_target(
            &mut inputs,
            &self.stark_proof_target,
            &proof_with_metadata.proof,
            self.zero_target,
        );

        for (challenge_target, challenge) in self
            .ctl_challenges_target
            .challenges
            .iter()
            .zip(&ctl_challenges.challenges)
        {
            inputs.set_target(challenge_target.beta, challenge.beta);
            inputs.set_target(challenge_target.gamma, challenge.gamma);
        }

        inputs.set_target_arr(
            self.init_challenger_state_target.as_ref(),
            proof_with_metadata.init_challenger_state.as_ref(),
        );

        self.circuit.prove(inputs)
    }
}

/// Represents a circuit which recursively verifies a PLONK proof.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct PlonkWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) circuit: CircuitData<F, C, D>,
    pub(crate) proof_with_pis_target: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> PlonkWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F, HC>,
{
    pub(crate) fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut inputs = PartialWitness::new();
        inputs.set_proof_with_pis_target(&self.proof_with_pis_target, proof);
        self.circuit.prove(inputs)
    }
}

/// Returns the recursive Stark circuit.
pub(crate) fn recursive_stark_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    table: Table,
    stark: &S,
    degree_bits: usize,
    cross_table_lookups: &[CrossTableLookup<F>],
    inner_config: &StarkConfig,
    circuit_config: &CircuitConfig,
    min_degree_bits: usize,
) -> StarkWrapperCircuit<F, C, D>
where
    [(); S::COLUMNS]:,
    C::Hasher: AlgebraicHasher<F, HC>,
{
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config.clone());
    let zero_target = builder.zero();

    let num_permutation_zs = stark.num_permutation_batches(inner_config);
    let num_permutation_batch_size = stark.permutation_batch_size();
    let num_ctl_zs =
        CrossTableLookup::num_ctl_zs(cross_table_lookups, table, inner_config.num_challenges);
    let proof_target =
        add_virtual_stark_proof(&mut builder, stark, inner_config, degree_bits, num_ctl_zs);
    builder.register_public_inputs(
        &proof_target
            .trace_cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .collect::<Vec<_>>(),
    );

    let ctl_challenges_target = GrandProductChallengeSet {
        challenges: (0..inner_config.num_challenges)
            .map(|_| GrandProductChallenge {
                beta: builder.add_virtual_public_input(),
                gamma: builder.add_virtual_public_input(),
            })
            .collect(),
    };

    let ctl_vars = CtlCheckVarsTarget::from_proof(
        table,
        &proof_target,
        cross_table_lookups,
        &ctl_challenges_target,
        num_permutation_zs,
    );

    let init_challenger_state_target =
        <C::Hasher as AlgebraicHasher<F, HC>>::AlgebraicPermutation::new(std::iter::from_fn(
            || Some(builder.add_virtual_public_input()),
        ));
    let mut challenger =
        RecursiveChallenger::<F, C::Hasher, D>::from_state(init_challenger_state_target);
    let challenges = proof_target.get_challenges::<F, C>(
        &mut builder,
        &mut challenger,
        num_permutation_zs > 0,
        num_permutation_batch_size,
        inner_config,
    );
    let challenger_state = challenger.compact(&mut builder);
    builder.register_public_inputs(challenger_state.as_ref());

    builder.register_public_inputs(&proof_target.openings.ctl_zs_last);

    verify_stark_proof_with_challenges_circuit::<F, C, _, D>(
        &mut builder,
        stark,
        &proof_target,
        &challenges,
        &ctl_vars,
        inner_config,
    );

    add_common_recursion_gates(&mut builder);

    // Pad to the minimum degree.
    while log2_ceil(builder.num_gates()) < min_degree_bits {
        builder.add_gate(NoopGate, vec![]);
    }

    let circuit = builder.build::<C>();
    StarkWrapperCircuit {
        circuit,
        stark_proof_target: proof_target,
        ctl_challenges_target,
        init_challenger_state_target,
        zero_target,
    }
}

/// Add gates that are sometimes used by recursive circuits, even if it's not actually used by this
/// particular recursive circuit. This is done for uniformity. We sometimes want all recursion
/// circuits to have the same gate set, so that we can do 1-of-n conditional recursion efficiently.
pub(crate) fn add_common_recursion_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) {
    builder.add_gate_to_gate_set(GateRef::new(ExponentiationGate::new_from_config(
        &builder.config,
    )));
}

/// Recursively verifies an inner proof.
fn verify_stark_proof_with_challenges_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    proof: &StarkProofTarget<D>,
    challenges: &StarkProofChallengesTarget<D>,
    ctl_vars: &[CtlCheckVarsTarget<F, D>],
    inner_config: &StarkConfig,
) where
    C::Hasher: AlgebraicHasher<F, HC>,
    [(); S::COLUMNS]:,
{
    let zero = builder.zero();
    let one = builder.one_extension();

    let StarkOpeningSetTarget {
        local_values,
        next_values,
        permutation_ctl_zs,
        permutation_ctl_zs_next,
        ctl_zs_last,
        quotient_polys,
    } = &proof.openings;
    let vars = StarkEvaluationTargets {
        local_values: &local_values.to_vec().try_into().unwrap(),
        next_values: &next_values.to_vec().try_into().unwrap(),
    };

    let degree_bits = proof.recover_degree_bits(inner_config);
    let zeta_pow_deg = builder.exp_power_of_2_extension(challenges.stark_zeta, degree_bits);
    let z_h_zeta = builder.sub_extension(zeta_pow_deg, one);
    let (l_0, l_last) =
        eval_l_0_and_l_last_circuit(builder, degree_bits, challenges.stark_zeta, z_h_zeta);
    let last =
        builder.constant_extension(F::Extension::primitive_root_of_unity(degree_bits).inverse());
    let z_last = builder.sub_extension(challenges.stark_zeta, last);

    let mut consumer = RecursiveConstraintConsumer::<F, D>::new(
        builder.zero_extension(),
        challenges.stark_alphas.clone(),
        z_last,
        l_0,
        l_last,
    );

    let num_permutation_zs = stark.num_permutation_batches(inner_config);
    let permutation_data = stark
        .uses_permutation_args()
        .then(|| PermutationCheckDataTarget {
            local_zs: permutation_ctl_zs[..num_permutation_zs].to_vec(),
            next_zs: permutation_ctl_zs_next[..num_permutation_zs].to_vec(),
            permutation_challenge_sets: challenges.permutation_challenge_sets.clone().unwrap(),
        });

    with_context!(
        builder,
        "evaluate vanishing polynomial",
        eval_vanishing_poly_circuit::<F, S, D>(
            builder,
            stark,
            inner_config,
            vars,
            permutation_data,
            ctl_vars,
            &mut consumer,
        )
    );
    let vanishing_polys_zeta = consumer.accumulators();

    // Check each polynomial identity, of the form `vanishing(x) = Z_H(x) quotient(x)`, at zeta.
    let mut scale = ReducingFactorTarget::new(zeta_pow_deg);
    for (i, chunk) in quotient_polys
        .chunks(stark.quotient_degree_factor())
        .enumerate()
    {
        let recombined_quotient = scale.reduce(chunk, builder);
        let computed_vanishing_poly = builder.mul_extension(z_h_zeta, recombined_quotient);
        builder.connect_extension(vanishing_polys_zeta[i], computed_vanishing_poly);
    }

    let merkle_caps = vec![
        proof.trace_cap.clone(),
        proof.permutation_ctl_zs_cap.clone(),
        proof.quotient_polys_cap.clone(),
    ];

    let fri_instance = stark.fri_instance_target(
        builder,
        challenges.stark_zeta,
        F::primitive_root_of_unity(degree_bits),
        degree_bits,
        ctl_zs_last.len(),
        inner_config,
    );
    builder.verify_fri_proof::<C>(
        &fri_instance,
        &proof.openings.to_fri_openings(zero),
        &challenges.fri_challenges,
        &merkle_caps,
        &proof.opening_proof,
        &inner_config.fri_params(degree_bits),
    );
}

fn eval_l_0_and_l_last_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    log_n: usize,
    x: ExtensionTarget<D>,
    z_x: ExtensionTarget<D>,
) -> (ExtensionTarget<D>, ExtensionTarget<D>) {
    let n = builder.constant_extension(F::Extension::from_canonical_usize(1 << log_n));
    let g = builder.constant_extension(F::Extension::primitive_root_of_unity(log_n));
    let one = builder.one_extension();
    let l_0_deno = builder.mul_sub_extension(n, x, n);
    let l_last_deno = builder.mul_sub_extension(g, x, one);
    let l_last_deno = builder.mul_extension(n, l_last_deno);

    (
        builder.div_extension(z_x, l_0_deno),
        builder.div_extension(z_x, l_last_deno),
    )
}

pub(crate) fn add_virtual_public_values<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> PublicValuesTarget {
    // CREATE PUBLIC VALUES TRAGETS HERE
    PublicValuesTarget {
        total_sum: builder.add_virtual_public_input_arr(),
        starting_blockhash: builder.add_virtual_public_input_arr(),
        ending_blockhash: builder.add_virtual_public_input_arr(),
    }
}

pub(crate) fn add_virtual_stark_proof<
    F: RichField + Extendable<D>,
    S: Stark<F, D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    config: &StarkConfig,
    degree_bits: usize,
    num_ctl_zs: usize,
) -> StarkProofTarget<D> {
    let fri_params = config.fri_params(degree_bits);
    let cap_height = fri_params.config.cap_height;

    let num_leaves_per_oracle = vec![
        S::COLUMNS,
        stark.num_permutation_batches(config) + num_ctl_zs,
        stark.quotient_degree_factor() * config.num_challenges,
    ];

    let permutation_zs_cap = builder.add_virtual_cap(cap_height);

    StarkProofTarget {
        trace_cap: builder.add_virtual_cap(cap_height),
        permutation_ctl_zs_cap: permutation_zs_cap,
        quotient_polys_cap: builder.add_virtual_cap(cap_height),
        openings: add_virtual_stark_opening_set::<F, S, D>(builder, stark, num_ctl_zs, config),
        opening_proof: builder.add_virtual_fri_proof(&num_leaves_per_oracle, &fri_params),
    }
}

fn add_virtual_stark_opening_set<F: RichField + Extendable<D>, S: Stark<F, D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    stark: &S,
    num_ctl_zs: usize,
    config: &StarkConfig,
) -> StarkOpeningSetTarget<D> {
    let num_challenges = config.num_challenges;
    StarkOpeningSetTarget {
        local_values: builder.add_virtual_extension_targets(S::COLUMNS),
        next_values: builder.add_virtual_extension_targets(S::COLUMNS),
        permutation_ctl_zs: builder
            .add_virtual_extension_targets(stark.num_permutation_batches(config) + num_ctl_zs),
        permutation_ctl_zs_next: builder
            .add_virtual_extension_targets(stark.num_permutation_batches(config) + num_ctl_zs),
        ctl_zs_last: builder.add_virtual_targets(num_ctl_zs),
        quotient_polys: builder
            .add_virtual_extension_targets(stark.quotient_degree_factor() * num_challenges),
    }
}

pub(crate) fn set_stark_proof_target<F, C: GenericConfig<D, F = F>, W, const D: usize>(
    witness: &mut W,
    proof_target: &StarkProofTarget<D>,
    proof: &StarkProof<F, C, D>,
    zero: Target,
) where
    F: RichField + Extendable<D>,
    C::Hasher: AlgebraicHasher<F, HC>,
    W: Witness<F>,
{
    witness.set_cap_target(&proof_target.trace_cap, &proof.trace_cap);
    witness.set_cap_target(&proof_target.quotient_polys_cap, &proof.quotient_polys_cap);

    witness.set_fri_openings(
        &proof_target.openings.to_fri_openings(zero),
        &proof.openings.to_fri_openings(),
    );

    witness.set_cap_target(
        &proof_target.permutation_ctl_zs_cap,
        &proof.permutation_ctl_zs_cap,
    );

    set_fri_proof_target(witness, &proof_target.opening_proof, &proof.opening_proof);
}

pub(crate) fn set_public_value_targets<F, W, const D: usize>(
    witness: &mut W,
    public_values_target: &PublicValuesTarget,
    public_values: &PublicValues,
) where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    for (i, limb) in public_values.total_sum.0.into_iter().enumerate() {
        witness.set_target(
            public_values_target.total_sum[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            public_values_target.total_sum[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }
    for (i, limb) in public_values
        .starting_blockhash
        .into_uint()
        .0
        .into_iter()
        .enumerate()
    {
        witness.set_target(
            public_values_target.starting_blockhash[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            public_values_target.starting_blockhash[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }
    for (i, limb) in public_values
        .ending_blockhash
        .into_uint()
        .0
        .into_iter()
        .enumerate()
    {
        witness.set_target(
            public_values_target.ending_blockhash[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            public_values_target.ending_blockhash[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }
}
