use std::marker::PhantomData;
use itertools::Itertools;
use log::info;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::Column;
use crate::search_substring::search_stark::columns::{DUMMY_ROW, HAYSTACK_REGISTER, HAYSTACK_SIZE, ID, IS_IN, IS_OUT, IS_SHIFT, NEEDLE_REGISTER, NEEDLE_SIZE, OFFSET};
use crate::stark::Stark;
use crate::util::trace_rows_to_poly_values;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};
use std::ops::Range;

pub(crate) mod columns {
    use std::ops::Range;

    pub(crate) const HAYSTACK_SIZE: usize = 168;
    pub(crate) const NEEDLE_SIZE: usize = 32;
    pub(crate) const IS_IN: usize = 0;
    pub(crate) const IS_OUT: usize = IS_IN + 1;
    pub(crate) const DUMMY_ROW: usize = IS_OUT + 1;
    pub(crate) const OFFSET: usize = DUMMY_ROW + 1;
    pub(crate) const IS_SHIFT: usize = OFFSET + 1;
    pub(crate) const ID: usize = IS_SHIFT + 1;
    pub(crate) const HAYSTACK_REGISTER: Range<usize> = ID + 1..ID + 1 + HAYSTACK_SIZE;
    pub(crate) const NEEDLE_REGISTER: Range<usize> = HAYSTACK_REGISTER.end..HAYSTACK_REGISTER.end + NEEDLE_SIZE;
}

pub(crate) const NUM_COLUMNS: usize = NEEDLE_REGISTER.end;


pub(crate) fn ctl_looked_filter_out<F: Field>() -> Column<F> {
    Column::single(IS_OUT)
}

pub(crate) fn ctl_looking_filter_in<F: Field>() -> Column<F> {
    Column::single(IS_IN)
}

pub(crate) fn ctl_looked_filter_shifts<F: Field>() -> Column<F> {
    Column::single(IS_SHIFT)
}

pub(crate) fn ctl_looked_needle<F: Field>() -> Vec<Column<F>> {
    let indices = [NEEDLE_REGISTER, Range { start: OFFSET, end: OFFSET + 1 }, ID..ID + 1];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}

pub(crate) fn ctl_looked_haystack<F: Field>() -> Vec<Column<F>> {
    let indices = [HAYSTACK_REGISTER, Range { start: OFFSET, end: OFFSET + 1 }, ID..ID + 1];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}


#[derive(Copy, Clone, Default)]
pub struct SearchStark<F, const D: usize> {
    f: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct SearchOp {
    pub(crate) input: [u8; HAYSTACK_SIZE],
    pub(crate) sub_string: [u8; NEEDLE_SIZE],
    pub(crate) offset: usize,
    pub(crate) id: usize,

}


impl<F: RichField, const D: usize> SearchStark<F, D> {
    pub(crate) fn generate_trace(&self, ops: Vec<SearchOp>, timing: &mut TimingTree) -> Vec<PolynomialValues<F>> {
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

    fn cyclic_shift_right(&self, arr: &mut [F], shift: usize) {
        let n = arr.len();
        let shift = shift % n;
        arr.rotate_right(shift);
    }

    fn convert_to_fixed_array(&self, vec: &[F]) -> [F; NUM_COLUMNS] {
        let mut row: [F; NUM_COLUMNS] = [F::ZERO; NUM_COLUMNS];
        for (i, &value) in vec.iter().enumerate() {
            row[i] = value;
        }
        row
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<SearchOp>,
    ) -> Vec<[F; NUM_COLUMNS]> {
        const MIN_CAP_TREE_SIZE: usize = 8;
        let mut rows: Vec<[F; NUM_COLUMNS]> = Vec::new();
        for op in operations {
            let shifts_num: usize = HAYSTACK_SIZE - op.offset;
            let sub_string = op.sub_string.iter().map(|x| F::from_canonical_u8(*x)).collect::<Vec<F>>();
            let input: Vec<F> = op.input.iter().map(|&x| F::from_canonical_u8(x)).collect();
            let mut row: [F; NUM_COLUMNS] = [F::ZERO; NUM_COLUMNS];
            row[IS_IN] = F::ONE;
            row[ID] = F::from_canonical_usize(op.id);
            row[OFFSET] = F::from_canonical_usize(HAYSTACK_SIZE - op.offset);
            row[NEEDLE_REGISTER.start..NEEDLE_REGISTER.end].copy_from_slice(&sub_string);
            row[HAYSTACK_REGISTER.start..HAYSTACK_REGISTER.start + HAYSTACK_SIZE].copy_from_slice(&input[..HAYSTACK_SIZE]);
            rows.push(row);
            let mut shifted_haystack = input.clone();
            for offset in 1..=shifts_num {
                self.cyclic_shift_right(&mut shifted_haystack, 1);
                let mut new_row: [F; NUM_COLUMNS] = [F::ZERO; NUM_COLUMNS];
                new_row[IS_SHIFT] = F::ONE;
                new_row[NEEDLE_REGISTER.start..NEEDLE_REGISTER.start + NEEDLE_SIZE].copy_from_slice(&sub_string);
                new_row[HAYSTACK_REGISTER.start..HAYSTACK_REGISTER.start + HAYSTACK_SIZE].copy_from_slice(&shifted_haystack);
                new_row[OFFSET] = F::from_canonical_usize(shifts_num - offset);
                if shifted_haystack.starts_with(&new_row[NEEDLE_REGISTER.start..NEEDLE_REGISTER.start + NEEDLE_SIZE]) && (shifts_num == offset) {
                    new_row[IS_OUT] = F::ONE;
                    new_row[ID] = F::from_canonical_usize(op.id);
                    rows.push(new_row);
                    break;
                } else {
                    rows.push(new_row);
                }
            }
        }
        let mut row = [F::ZERO; NUM_COLUMNS];
        row[DUMMY_ROW] = F::ONE;
        if rows.len() < MIN_CAP_TREE_SIZE {
            for _ in rows.len()..MIN_CAP_TREE_SIZE - rows.len() {
                rows.push(row);
            }
        }
        let padded_len = rows.len().next_power_of_two();
        for _ in rows.len()..padded_len {
            rows.push(row);
        }
        rows
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for SearchStark<F, D> {
    const COLUMNS: usize = NUM_COLUMNS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>,
    {
        let lv = vars.local_values;
        let nv = vars.next_values;
        let is_out = lv[IS_OUT];
        let is_dummy1 = lv[DUMMY_ROW];
        let is_dummy2 = nv[DUMMY_ROW];
        let is_shift = nv[IS_SHIFT];
        let offset1 = lv[OFFSET];
        let offset2 = nv[OFFSET];
        let is_in1 = lv[IS_IN];
        let is_in2 = nv[IS_IN];
        let haystack1 = &lv[HAYSTACK_REGISTER];
        let haystack2 = &nv[HAYSTACK_REGISTER];
        let needle = &lv[NEEDLE_REGISTER];
        let haystack_substr = &lv[HAYSTACK_REGISTER.start..HAYSTACK_REGISTER.start + NEEDLE_SIZE];

        //Check that is_in and is_out flags are in {0,1}
        yield_constr.constraint(is_in1 * (is_in1 - P::ONES));
        yield_constr.constraint(is_out * (is_out - P::ONES));

        //Check that first 32 elements in haystack equal to substring of 32 elements in needle
        for (&xi, &yi) in haystack_substr.iter().zip_eq(needle.iter()) {
            yield_constr.constraint(is_out * (xi - yi));
        }

        //Check that the last element of haystack first row equals to first element in next row of cyclic shift when is_in = 1, is_in in next row = 0
        let filter = (P::ONES - is_in2) * (is_in1 - P::ONES);
        yield_constr.constraint(filter * (haystack1[HAYSTACK_SIZE - 1] - haystack2[0]));
        // //yield_constr.constraint(is_in1 * (haystack1[HAYSTACK_SIZE - 1] - haystack2[0]));
        //Check that previous element in row of cyclic shift equals to next element of next row when is_in = 0 and rows are not dummy
        let filter = P::ONES - is_in1 - is_in2;
        let filter2 = P::ONES - is_dummy1 - is_dummy2;
        for i in 1..HAYSTACK_SIZE - 1 {
            yield_constr.constraint(filter2 * filter * (haystack1[i] - haystack2[i + 1]));
        }

        // //Check that offset in row equal to 0 when is_out = 0 (subarr in arr)
        yield_constr.constraint(is_out * (P::ZEROS - offset1));
        //
        // //Check that offset of previous row are + 1 corresponding to next row
        yield_constr.constraint(is_shift * (offset1 - (offset2 + P::ONES)));
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv = vars.local_values;
        let nv = vars.next_values;
        let is_out = lv[IS_OUT];
        let is_in1 = lv[IS_IN];
        let is_in2 = nv[IS_IN];
        let is_shift = nv[IS_SHIFT];
        let offset1 = lv[OFFSET];
        let offset2 = nv[OFFSET];
        let is_dummy1 = lv[DUMMY_ROW];
        let is_dummy2 = nv[DUMMY_ROW];
        let haystack1 = &lv[HAYSTACK_REGISTER];
        let haystack2 = &nv[HAYSTACK_REGISTER];
        let needle = &lv[NEEDLE_REGISTER];
        let haystack_substr = &lv[HAYSTACK_REGISTER.start..HAYSTACK_REGISTER.start + NEEDLE_SIZE];
        let one = builder.one_extension();

        //Check that is_in and is_out flags are in {0,1}
        let t = builder.sub_extension(is_in1, one);
        let mul_is_in = builder.mul_extension(is_in1, t);
        yield_constr.constraint(builder, mul_is_in);
        let t = builder.sub_extension(is_out, one);
        let mul_is_out = builder.mul_extension(is_out, t);
        yield_constr.constraint(builder, mul_is_out);

        //Check that first 32 elements in haystack equal to substring of 32 elements in needle
        for (&xi, &yi) in haystack_substr.iter().zip_eq(needle.iter()) {
            let t = builder.sub_extension(xi, yi);
            let constraint = builder.mul_extension(is_out, t);
            yield_constr.constraint(builder, constraint);
        }

        //Check that the last element of haystack first row equals to first element in next row of cyclic shift when is_in = 1, is_in in next row = 0
        let constraint = {
            let sub = builder.sub_extension(haystack1[HAYSTACK_SIZE - 1], haystack2[0]);
            let filter = {
                let sub = builder.sub_extension(is_in2, one);
                let sub2 = builder.sub_extension(one, is_in1);
                builder.mul_extension(sub, sub2)
            };
            builder.mul_extension(filter, sub)
        };
        yield_constr.constraint(builder, constraint);
        //
        // //Check that previous element in row of cyclic shift equals to next element of next row when is_in = 0 and rows are not dummy
        let filter = {
            let sub = builder.sub_extension(one, is_in1);
            builder.sub_extension(sub, is_in2)
        };
        let filter2 = {
            let sub = builder.sub_extension(one, is_dummy1);
            builder.sub_extension(sub, is_dummy2)
        };
        for i in 1..HAYSTACK_SIZE - 1 {
            let constraint = {
                let sub = builder.sub_extension(haystack1[i], haystack2[i + 1]);
                let mul = builder.mul_extension(filter, sub);
                builder.mul_extension(filter2, mul)
            };
            yield_constr.constraint(builder, constraint);
        }
        //
        // //Check that offset in row equal to 0 when is_out = 0 (subarr in arr)
        let constraint = {
            let zero = builder.zero_extension();
            let sub = builder.sub_extension(zero, offset1);
            builder.mul_extension(is_out, sub)
        };
        yield_constr.constraint(builder, constraint);

        // //Check that offset of previous row are + 1 corresponding to next row
        let constraint = {
            let diff = builder.add_extension(offset2, one);
            let sub = builder.sub_extension(offset1, diff);
            builder.mul_extension(is_shift, sub)
        };
        yield_constr.constraint(builder, constraint);
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use crate::search_substring::search_stark::{SearchOp, SearchStark};
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::util::timing::TimingTree;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};


    type F = GoldilocksField;

    const D: usize = 2;

    type C = PoseidonGoldilocksConfig;


    fn init_logger() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }

    #[test]
    fn degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = SearchStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_low_degree(stark)
    }

    #[test]
    fn circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = SearchStark<F, D>;

        let stark = S {
            f: Default::default(),
        };
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }
}