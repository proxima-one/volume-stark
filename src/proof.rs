use ethereum_types::{Address, H256, U256};
use itertools::Itertools;
use log::info;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::proof::{FriChallenges, FriChallengesTarget, FriProof, FriProofTarget};
use plonky2::fri::structure::{
    FriOpeningBatch, FriOpeningBatchTarget, FriOpenings, FriOpeningsTarget,
};
use plonky2::hash::hash_types::{MerkleCapTarget, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::target::Target::VirtualTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2_maybe_rayon::*;
use serde::{Deserialize, Serialize};

use crate::all_stark::NUM_TABLES;
use crate::config::StarkConfig;
use crate::permutation::GrandProductChallengeSet;

/// A STARK proof for each table, plus some metadata used to create recursive wrapper proofs.
#[derive(Debug, Clone)]
pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize> {
    pub stark_proofs: [StarkProofWithMetadata<F, C, D>; NUM_TABLES],
    pub(crate) ctl_challenges: GrandProductChallengeSet<F>,
    pub public_values: PublicValues,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize> AllProof<F, C, D> {
    pub fn degree_bits(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        core::array::from_fn(|i| self.stark_proofs[i].proof.recover_degree_bits(config))
    }
}

pub(crate) struct AllProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    pub stark_challenges: [StarkProofChallenges<F, D>; NUM_TABLES],
    pub ctl_challenges: GrandProductChallengeSet<F>,
}

#[allow(unused)] // TODO: should be used soon
pub(crate) struct AllChallengerState<F: RichField + Extendable<D>, H: Hasher<F>, const D: usize> {
    /// Sponge state of the challenger before starting each proof,
    /// along with the final state after all proofs are done. This final state isn't strictly needed.
    pub states: [H::Permutation; NUM_TABLES + 1],
    pub ctl_challenges: GrandProductChallengeSet<F>,
}

/// Memory values which are public.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicValues {
    pub total_sum: U256,
    pub starting_blockhash: H256,
    // parent block hash
    pub ending_blockhash: H256,
}


/// Memory values which are public.
/// Note: All the larger integers are encoded with 32-bit limbs in little-endian order.
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct PublicValuesTarget {
    pub total_sum: [Target; 8],
    pub starting_blockhash: [Target; 8],
    pub ending_blockhash: [Target; 8],
    // pub trie_roots_before: TrieRootsTarget,
    // pub trie_roots_after: TrieRootsTarget,
    // pub block_metadata: BlockMetadataTarget,
}

impl PublicValuesTarget {
    const SIZE: usize = 24;

    pub fn from_public_inputs(pis: &[Target]) -> Self {
        let total_sum = pis[0..8].try_into().unwrap();
        let starting_blockhash = pis[8..16].try_into().unwrap();
        let ending_blockhash = pis[16..24].try_into().unwrap();
        Self {
            total_sum,
            starting_blockhash,
            ending_blockhash,
        }
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        tr0: Self,
        tr1: Self,
    ) -> Self {
        Self {
            total_sum: core::array::from_fn(|i| {
                builder.select(condition, tr0.total_sum[i], tr1.total_sum[i])
            }),
            starting_blockhash: core::array::from_fn(|i| {
                builder.select(condition, tr0.starting_blockhash[i], tr1.starting_blockhash[i])
            }),
            ending_blockhash: core::array::from_fn(|i| {
                builder.select(condition, tr0.ending_blockhash[i], tr1.ending_blockhash[i])
            }),
        }
    }

    // XOR: a + b - 2 * a * b === a^b
    pub fn bits_xor<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        lhs: BoolTarget,
        rhs: BoolTarget,
    ) -> BoolTarget {
        let addition = builder.add(lhs.target, rhs.target);
        let two = builder.two();
        let mul_a_b = builder.mul(lhs.target, rhs.target);
        let mul_two = builder.mul(two, mul_a_b);
        BoolTarget::new_unsafe(builder.sub(addition, mul_two))
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        front: Self,
        back: Self,
        root: Self,
    ){
        let mut first_volume_bits = vec![];
        let mut second_volume_bits = vec![];
        let mut total_volume_bits = vec![];
        for i in 0..8 {
            first_volume_bits.extend(builder.split_le(front.total_sum[i], 32));
            second_volume_bits.extend(builder.split_le(back.total_sum[i], 32));
            total_volume_bits.extend(builder.split_le(root.total_sum[i], 32));
            builder.connect(front.starting_blockhash[i], root.starting_blockhash[i]);
            builder.connect(root.ending_blockhash[i], back.ending_blockhash[i]);
            builder.connect(front.ending_blockhash[i], back.starting_blockhash[i]);
        }

        first_volume_bits.reverse();
        second_volume_bits.reverse();
        let mut carry_list = vec![builder._false()];
        let mut result = vec![];
        let mut carry_index = 0;

        for i in (0..256).rev() {
            let carry_target = &mut carry_list[carry_index];

            // Computes the sum without carry: b1 ^ b2 ^ carry
            let first_bits_addition = Self::bits_xor(builder, first_volume_bits[i], second_volume_bits[i]);
            let sum_bits = Self::bits_xor(builder, first_bits_addition.clone(), *carry_target);

            // Use bitwise AND, XOR, OR to compute the carry: (b1 & b2) | (carry & (b1 ^ b2))
            let and_bits = builder.and(first_volume_bits[i], second_volume_bits[i]);
            let and_carry = builder.and(*carry_target, first_bits_addition);
            let carry = builder.or(and_bits, and_carry);

            carry_list.push(carry);
            result.push(sum_bits);
            carry_index += 1;
        }
        builder.assert_zero(carry_list.first().unwrap().target);
        builder.assert_zero(carry_list.last().unwrap().target);
        for (b1, b2) in result.iter().zip(total_volume_bits.iter()) {
            builder.connect(b1.target, b2.target);
        }
    }

    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_vec(&self.total_sum)?;
        buffer.write_target_vec(&self.starting_blockhash)?;
        buffer.write_target_vec(&self.ending_blockhash)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        Ok(Self {
            total_sum: buffer.read_target_vec()?.try_into().unwrap(),
            starting_blockhash: buffer.read_target_vec()?.try_into().unwrap(),
            ending_blockhash: buffer.read_target_vec()?.try_into().unwrap(),
        })
    }
}


#[derive(Debug, Clone)]
pub struct StarkProof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of permutation Z values.
    pub permutation_ctl_zs_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of trace values.
    pub quotient_polys_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: FriProof<F, C::Hasher, D>,
}

/// A `StarkProof` along with some metadata about the initial Fiat-Shamir state, which is used when
/// creating a recursive wrapper proof around a STARK proof.
#[derive(Debug, Clone)]
pub struct StarkProofWithMetadata<F, C, const D: usize>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F=F>,
{
    pub(crate) init_challenger_state: <C::Hasher as Hasher<F>>::Permutation,
    // TODO: set it back to pub(crate) when cpu trace len is a public input
    pub proof: StarkProof<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize> StarkProof<F, C, D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }

    pub fn num_ctl_zs(&self) -> usize {
        self.openings.ctl_zs_last.len()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct StarkProofTarget<const D: usize> {
    pub trace_cap: MerkleCapTarget,
    pub permutation_ctl_zs_cap: MerkleCapTarget,
    pub quotient_polys_cap: MerkleCapTarget,
    pub openings: StarkOpeningSetTarget<D>,
    pub opening_proof: FriProofTarget<D>,
}

impl<const D: usize> StarkProofTarget<D> {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_merkle_cap(&self.trace_cap)?;
        buffer.write_target_merkle_cap(&self.permutation_ctl_zs_cap)?;
        buffer.write_target_merkle_cap(&self.quotient_polys_cap)?;
        buffer.write_target_fri_proof(&self.opening_proof)?;
        self.openings.to_buffer(buffer)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let trace_cap = buffer.read_target_merkle_cap()?;
        let permutation_ctl_zs_cap = buffer.read_target_merkle_cap()?;
        let quotient_polys_cap = buffer.read_target_merkle_cap()?;
        let opening_proof = buffer.read_target_fri_proof()?;
        let openings = StarkOpeningSetTarget::from_buffer(buffer)?;

        Ok(Self {
            trace_cap,
            permutation_ctl_zs_cap,
            quotient_polys_cap,
            openings,
            opening_proof,
        })
    }

    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

pub(crate) struct StarkProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    /// Randomness used in any permutation arguments.
    pub permutation_challenge_sets: Option<Vec<GrandProductChallengeSet<F>>>,

    /// Random values used to combine STARK constraints.
    pub stark_alphas: Vec<F>,

    /// Point at which the STARK polynomials are opened.
    pub stark_zeta: F::Extension,

    pub fri_challenges: FriChallenges<F, D>,
}

pub(crate) struct StarkProofChallengesTarget<const D: usize> {
    pub permutation_challenge_sets: Option<Vec<GrandProductChallengeSet<Target>>>,
    pub stark_alphas: Vec<Target>,
    pub stark_zeta: ExtensionTarget<D>,
    pub fri_challenges: FriChallengesTarget<D>,
}

/// Purported values of each polynomial at the challenge point.
#[derive(Debug, Clone)]
pub struct StarkOpeningSet<F: RichField + Extendable<D>, const D: usize> {
    /// Openings of trace polynomials at `zeta`.
    pub local_values: Vec<F::Extension>,
    /// Openings of trace polynomials at `g * zeta`.
    pub next_values: Vec<F::Extension>,
    /// Openings of permutations and cross-table lookups `Z` polynomials at `zeta`.
    pub permutation_ctl_zs: Vec<F::Extension>,
    /// Openings of permutations and cross-table lookups `Z` polynomials at `g * zeta`.
    pub permutation_ctl_zs_next: Vec<F::Extension>,
    /// Openings of cross-table lookups `Z` polynomials at `g^-1`.
    pub ctl_zs_last: Vec<F>,
    /// Openings of quotient polynomials at `zeta`.
    pub quotient_polys: Vec<F::Extension>,
}

impl<F: RichField + Extendable<D>, const D: usize> StarkOpeningSet<F, D> {
    pub fn new<C: GenericConfig<D, F=F>>(
        zeta: F::Extension,
        g: F,
        trace_commitment: &PolynomialBatch<F, C, D>,
        permutation_ctl_zs_commitment: &PolynomialBatch<F, C, D>,
        quotient_commitment: &PolynomialBatch<F, C, D>,
        degree_bits: usize,
        num_permutation_zs: usize,
    ) -> Self {
        let eval_commitment = |z: F::Extension, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.to_extension().eval(z))
                .collect::<Vec<_>>()
        };
        let eval_commitment_base = |z: F, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.eval(z))
                .collect::<Vec<_>>()
        };
        let zeta_next = zeta.scalar_mul(g);
        Self {
            local_values: eval_commitment(zeta, trace_commitment),
            next_values: eval_commitment(zeta_next, trace_commitment),
            permutation_ctl_zs: eval_commitment(zeta, permutation_ctl_zs_commitment),
            permutation_ctl_zs_next: eval_commitment(zeta_next, permutation_ctl_zs_commitment),
            ctl_zs_last: eval_commitment_base(
                F::primitive_root_of_unity(degree_bits).inverse(),
                permutation_ctl_zs_commitment,
            )[num_permutation_zs..]
                .to_vec(),
            quotient_polys: eval_commitment(zeta, quotient_commitment),
        }
    }

    pub(crate) fn to_fri_openings(&self) -> FriOpenings<F, D> {
        let zeta_batch = FriOpeningBatch {
            values: self
                .local_values
                .iter()
                .chain(&self.permutation_ctl_zs)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatch {
            values: self
                .next_values
                .iter()
                .chain(&self.permutation_ctl_zs_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_last.is_empty());
        let ctl_last_batch = FriOpeningBatch {
            values: self
                .ctl_zs_last
                .iter()
                .copied()
                .map(F::Extension::from_basefield)
                .collect(),
        };

        FriOpenings {
            batches: vec![zeta_batch, zeta_next_batch, ctl_last_batch],
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct StarkOpeningSetTarget<const D: usize> {
    pub local_values: Vec<ExtensionTarget<D>>,
    pub next_values: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs: Vec<ExtensionTarget<D>>,
    pub permutation_ctl_zs_next: Vec<ExtensionTarget<D>>,
    pub ctl_zs_last: Vec<Target>,
    pub quotient_polys: Vec<ExtensionTarget<D>>,
}

impl<const D: usize> StarkOpeningSetTarget<D> {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_ext_vec(&self.local_values)?;
        buffer.write_target_ext_vec(&self.next_values)?;
        buffer.write_target_ext_vec(&self.permutation_ctl_zs)?;
        buffer.write_target_ext_vec(&self.permutation_ctl_zs_next)?;
        buffer.write_target_vec(&self.ctl_zs_last)?;
        buffer.write_target_ext_vec(&self.quotient_polys)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let local_values = buffer.read_target_ext_vec::<D>()?;
        let next_values = buffer.read_target_ext_vec::<D>()?;
        let permutation_ctl_zs = buffer.read_target_ext_vec::<D>()?;
        let permutation_ctl_zs_next = buffer.read_target_ext_vec::<D>()?;
        let ctl_zs_last = buffer.read_target_vec()?;
        let quotient_polys = buffer.read_target_ext_vec::<D>()?;

        Ok(Self {
            local_values,
            next_values,
            permutation_ctl_zs,
            permutation_ctl_zs_next,
            ctl_zs_last,
            quotient_polys,
        })
    }

    pub(crate) fn to_fri_openings(&self, zero: Target) -> FriOpeningsTarget<D> {
        let zeta_batch = FriOpeningBatchTarget {
            values: self
                .local_values
                .iter()
                .chain(&self.permutation_ctl_zs)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatchTarget {
            values: self
                .next_values
                .iter()
                .chain(&self.permutation_ctl_zs_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_last.is_empty());
        let ctl_last_batch = FriOpeningBatchTarget {
            values: self
                .ctl_zs_last
                .iter()
                .copied()
                .map(|t| t.to_ext_target(zero))
                .collect(),
        };

        FriOpeningsTarget {
            batches: vec![zeta_batch, zeta_next_batch, ctl_last_batch],
        }
    }
}