use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::{BoolTarget, Target};
use serde::Serialize;

use core::mem::size_of;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::hashing::{
    compress, hash_n_to_hash_no_pad, PlonkyPermutation, SPONGE_RATE, SPONGE_WIDTH,
};
use plonky2::hash::poseidon::{Permuter, Poseidon, PoseidonHash, PoseidonPermutation};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use poseidon_permutation::bindings::permute;
use std::fmt::Debug;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PoseidonBN128Permutation<T> {
    state: [T; SPONGE_WIDTH],
}

impl<T> AsRef<[T]> for PoseidonBN128Permutation<T> {
    fn as_ref(&self) -> &[T] {
        &self.state
    }
}

impl<T: Copy + Debug + Default + Eq + Permuter + Send + Sync> PlonkyPermutation<T>
    for PoseidonBN128Permutation<T>
{
    const RATE: usize = SPONGE_RATE;
    const WIDTH: usize = SPONGE_WIDTH;

    /*fn permute(input: [F; SPONGE_WIDTH]) -> [F; SPONGE_WIDTH] {
        assert_eq!(SPONGE_WIDTH, 12);
        unsafe {
            let h = permute(
                input[0].to_canonical_u64(),
                input[1].to_canonical_u64(),
                input[2].to_canonical_u64(),
                input[3].to_canonical_u64(),
                input[4].to_canonical_u64(),
                input[5].to_canonical_u64(),
                input[6].to_canonical_u64(),
                input[7].to_canonical_u64(),
                input[8].to_canonical_u64(),
                input[9].to_canonical_u64(),
                input[10].to_canonical_u64(),
                input[11].to_canonical_u64(),
            );

            [
                F::from_canonical_u64(if h.r0 >= F::ORDER {
                    h.r0 - F::ORDER
                } else {
                    h.r0
                }),
                F::from_canonical_u64(if h.r1 >= F::ORDER {
                    h.r1 - F::ORDER
                } else {
                    h.r1
                }),
                F::from_canonical_u64(if h.r2 >= F::ORDER {
                    h.r2 - F::ORDER
                } else {
                    h.r2
                }),
                F::from_canonical_u64(if h.r3 >= F::ORDER {
                    h.r3 - F::ORDER
                } else {
                    h.r3
                }),
                F::from_canonical_u64(if h.r4 >= F::ORDER {
                    h.r4 - F::ORDER
                } else {
                    h.r4
                }),
                F::from_canonical_u64(if h.r5 >= F::ORDER {
                    h.r5 - F::ORDER
                } else {
                    h.r5
                }),
                F::from_canonical_u64(if h.r6 >= F::ORDER {
                    h.r6 - F::ORDER
                } else {
                    h.r6
                }),
                F::from_canonical_u64(if h.r7 >= F::ORDER {
                    h.r7 - F::ORDER
                } else {
                    h.r7
                }),
                F::from_canonical_u64(if h.r8 >= F::ORDER {
                    h.r8 - F::ORDER
                } else {
                    h.r8
                }),
                F::from_canonical_u64(if h.r9 >= F::ORDER {
                    h.r9 - F::ORDER
                } else {
                    h.r9
                }),
                F::from_canonical_u64(if h.r10 >= F::ORDER {
                    h.r10 - F::ORDER
                } else {
                    h.r10
                }),
                F::from_canonical_u64(if h.r11 >= F::ORDER {
                    h.r11 - F::ORDER
                } else {
                    h.r11
                }),
            ]
        }
    }*/

    /*fn permute(&mut self) {
        unsafe {
            permute(
                self.state.get_unchecked_mut(0),
                self.state[1],
                self.state[2],
                self.state[3],
                self.state[4],
                self.state[5],
                self.state[6],
                self.state[7],
                self.state[8],
                self.state[9],
                self.state[10],
                self.state[11],
            )
        };
    }*/

    fn permute(&mut self) {
        self.state = T::permute(self.state);
    }

    fn new<I: IntoIterator<Item = T>>(iter: I) -> Self {
        todo!()
    }

    fn set_elt(&mut self, elt: T, idx: usize) {
        todo!()
    }

    fn set_from_iter<I: IntoIterator<Item = T>>(&mut self, elts: I, start_idx: usize) {
        todo!()
    }

    fn set_from_slice(&mut self, elts: &[T], start_idx: usize) {
        todo!()
    }

    fn squeeze(&self) -> &[T] {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBN128Hash;
impl<F: RichField> Hasher<F> for PoseidonBN128Hash {
    const HASH_SIZE: usize = 4 * 8;
    type Hash = HashOut<F>;
    type Permutation = PoseidonBN128Permutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        hash_n_to_hash_no_pad::<F, Self::Permutation>(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        compress::<F, Self::Permutation>(left, right)
    }
}

// TODO: this is a work around. Still use Goldilocks based Poseidon for algebraic PoseidonBN128Hash.
impl<F: RichField> AlgebraicHasher<F> for PoseidonBN128Hash {
    type AlgebraicPermutation = PoseidonPermutation<Target>;

    fn permute_swapped<const D: usize>(
        inputs: Self::AlgebraicPermutation,
        swap: BoolTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self::AlgebraicPermutation
    where
        F: RichField + Extendable<D>,
    {
        PoseidonHash::permute_swapped(inputs, swap, builder)
    }
}

/// Configuration using Poseidon over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBN128GoldilocksConfig;

impl GenericConfig<2> for PoseidonBN128GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBN128Hash;
    type InnerHasher = PoseidonBN128Hash;
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};

    use crate::configbn::PoseidonBN128Hash;

    #[test]
    fn test_poseidon_bn128() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut v = Vec::new();
        v.push(F::from_canonical_u64(8917524657281059100u64));
        v.push(F::from_canonical_u64(13029010200779371910u64));
        v.push(F::from_canonical_u64(16138660518493481604u64));
        v.push(F::from_canonical_u64(17277322750214136960u64));
        v.push(F::from_canonical_u64(1441151880423231822u64));
        let h = PoseidonBN128Hash::hash_no_pad(&v);
        assert_eq!(h.elements[0].0, 16736853722845225729u64);
        assert_eq!(h.elements[1].0, 1446699130810517790u64);
        assert_eq!(h.elements[2].0, 15445626857806971868u64);
        assert_eq!(h.elements[3].0, 6331160477881736675u64);

        Ok(())
    }
}
