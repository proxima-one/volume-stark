use std::marker::PhantomData;
use itertools::Itertools;

use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use tiny_keccak::Hasher;
use crate::bloom_stark::columns::{BLOOM_REGISTER, ID, IS_INCLUDED, NOT_DUMMY, TOPIC_REGISTER};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::Column;
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};


pub const ADDRESS_SIZE: usize = 20;
pub const TOPIC_SIZE: usize = 32;
pub const BLOOM_SIZE_BYTES: usize = 256;

pub(crate) mod columns {
    use std::ops::Range;
    use crate::bloom_stark::{ADDRESS_SIZE, BLOOM_SIZE_BYTES, TOPIC_SIZE};

    pub(crate) const NOT_DUMMY: usize = 0;
    pub(crate) const IS_INCLUDED: usize = NOT_DUMMY + 1;
    pub(crate) const ID: usize = IS_INCLUDED + 1;
    pub(crate) const BLOOM_REGISTER: Range<usize> = ID + 1..ID + 1 + BLOOM_SIZE_BYTES;
    pub(crate) const TOPIC_REGISTER: Range<usize> = BLOOM_REGISTER.end..BLOOM_REGISTER.end + TOPIC_SIZE;
}

pub(crate) const NUM_COLUMNS: usize = TOPIC_REGISTER.end;


pub(crate) fn ctl_looking_topic<F: Field>() -> Vec<Column<F>> {
    let indices = [TOPIC_REGISTER, ID..ID + 1, IS_INCLUDED..IS_INCLUDED + 1];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}

pub(crate) fn ctl_not_dummy_filter<F: Field>() -> Column<F> {
    Column::single(NOT_DUMMY)
}



struct Bloom([u8; BLOOM_SIZE_BYTES]);

impl Bloom {
    fn set_bytes(&mut self, data: &[u8]) {
        if data.len() > BLOOM_SIZE_BYTES {
            panic!(
                "bloom bytes too big {} {}",
                BLOOM_SIZE_BYTES,
                data.len()
            );
        }
        let start = BLOOM_SIZE_BYTES - data.len();
        self.0[start..].copy_from_slice(data);
    }

    fn add(&mut self, data: &[u8]) {
        let mut hashbuf = [0u8; 6];
        let (i1, v1, i2, v2, i3, v3) = Self::bloom_values(data, &mut hashbuf);
        self.0[i1] |= v1;
        self.0[i2] |= v2;
        self.0[i3] |= v3;
    }

    fn bloom_values(data: &[u8], hashbuf: &mut [u8; 6]) -> (usize, u8, usize, u8, usize, u8) {
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(data);
        keccak.finalize(hashbuf);
        let v1 = 1u8 << (hashbuf[1] & 0x7);
        let v2 = 1u8 << (hashbuf[3] & 0x7);
        let v3 = 1u8 << (hashbuf[5] & 0x7);
        let i1 = BLOOM_SIZE_BYTES - ((u16::from_be_bytes(hashbuf[..2].try_into().unwrap()) & 0x7ff) >> 3) as usize - 1;
        let i2 = BLOOM_SIZE_BYTES - ((u16::from_be_bytes(hashbuf[2..4].try_into().unwrap()) & 0x7ff) >> 3) as usize - 1;
        let i3 = BLOOM_SIZE_BYTES - ((u16::from_be_bytes(hashbuf[4..].try_into().unwrap()) & 0x7ff) >> 3) as usize - 1;

        (i1, v1, i2, v2, i3, v3)
    }

    fn check_inclusion(&self, topic: &[u8]) -> bool {
        let (i1, v1, i2, v2, i3, v3) = Self::bloom_values(topic, &mut [0u8; 6]);
        v1 == (v1 & self.0[i1])
            && v2 == (v2 & self.0[i2])
            && v3 == (v3 & self.0[i3])
    }

    fn set_bloom(data: &[u8]) -> Self {
        let mut b = Bloom([0u8; BLOOM_SIZE_BYTES]);
        b.set_bytes(data);
        b
    }

}


#[derive(Copy, Clone, Default)]
pub struct BloomStark<F, const D: usize> {
    f: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct BloomOp {
    pub(crate) bloom: [u8; BLOOM_SIZE_BYTES],
    pub(crate) address: Option<[u8; TOPIC_SIZE]>,
    pub(crate) topic: Option<[u8; TOPIC_SIZE]>,
    pub(crate) id: usize
}


impl<F: RichField, const D: usize> BloomStark<F, D> {
    pub(crate) fn generate_trace(&self, ops: Vec<BloomOp>, timing: &mut TimingTree) -> Vec<PolynomialValues<F>> {
        let trace_rows = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(ops)
        );
        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows_to_poly_values(trace_rows)
        );
        trace_polys
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<BloomOp>,
    ) -> Vec<[F; NUM_COLUMNS]> {
        const MIN_CAP_TREE_SIZE: usize = 8;
        let mut rows: Vec<[F; NUM_COLUMNS]> = Vec::new();
        for op in operations {
            rows.extend(self.generate_rows_for_op(op));
        }

        for _ in rows.len()..MIN_CAP_TREE_SIZE {
            rows.push(self.generate_padding_row())
        }
        let padded_len = rows.len().next_power_of_two();
        for _ in rows.len()..padded_len {
            rows.push(self.generate_padding_row());
        }
        rows
    }

    fn generate_input_row(&self, op: &BloomOp) -> [F; NUM_COLUMNS]{
        let bloom_data = op.bloom.iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>();
        let mut row = [F::ZERO; NUM_COLUMNS];
        row[NOT_DUMMY] = F::ONE;
        row[ID] = F::from_canonical_usize(op.id);
        row[BLOOM_REGISTER.start..BLOOM_REGISTER.start + BLOOM_SIZE_BYTES].copy_from_slice(&bloom_data);
        row
    }

    fn generate_rows_for_op(&self, op: BloomOp) -> Vec<[F; NUM_COLUMNS]> {
        let mut rows: Vec<[F; NUM_COLUMNS]> = Vec::new();
        match op.topic {
            None => {}
            Some(topic) => {let bloom = Bloom::set_bloom(&op.bloom);
                let mut topic_row = self.generate_input_row(&op);
                let topic_data = topic.iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>();
                topic_row[TOPIC_REGISTER.start..TOPIC_REGISTER.start + TOPIC_SIZE].copy_from_slice(&topic_data);
                if bloom.check_inclusion(&topic){
                    topic_row[IS_INCLUDED] = F::ONE;
                }
                rows.push(topic_row);
            }

        }
        match op.address {
            None => {}
            Some(address) => {
                let bloom = Bloom::set_bloom(&op.bloom);
                let mut address_row = self.generate_input_row(&op);
                let address_data = address.iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>();
                address_row[TOPIC_REGISTER.start..TOPIC_REGISTER.start + TOPIC_SIZE].copy_from_slice(&address_data);
                if bloom.check_inclusion(&address[..20]){
                    address_row[IS_INCLUDED] = F::ONE;
                }
                rows.push(address_row);
            }
        }
        rows
    }

    fn generate_padding_row(&self) -> [F; NUM_COLUMNS] {
        [F::ZERO; NUM_COLUMNS]
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for BloomStark<F, D> {
    const COLUMNS: usize = NUM_COLUMNS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>,
    {
        let local_values = vars.local_values;
        let not_dummy_filter = local_values[NOT_DUMMY];
        let one = P::ONES;
        let included = local_values[IS_INCLUDED];
        yield_constr.constraint(not_dummy_filter * (included - one))
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let local_values = vars.local_values;
        let not_dummy_filter = local_values[NOT_DUMMY];
        let one = builder.one_extension();
        let included = local_values[IS_INCLUDED];
        let sub = builder.sub_extension(included, one);
        let constr = builder.mul_extension(not_dummy_filter, sub);
        yield_constr.constraint(builder, constr);
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}


