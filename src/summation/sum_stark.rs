use std::borrow::Borrow;
use std::marker::PhantomData;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::Column;
use crate::stark::Stark;
use crate::summation::{ChainResult};
use crate::util::trace_rows_to_poly_values;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};


pub(crate) mod columns {
    use std::ops::Range;
    pub const IS_INPUT: usize = 0;
    pub const IS_OUTPUT: usize = IS_INPUT + 1;
    pub const CALCULATION_ID: usize = IS_OUTPUT + 1;
    pub const NOT_INIT: usize = CALCULATION_ID + 1;
    pub const ACUM_SUM: Range<usize> = NOT_INIT + 1..NOT_INIT + 1 + 16;
    pub const VALUE: Range<usize> = ACUM_SUM.end..ACUM_SUM.end + 16;
    pub const MULTIPLIER: Range<usize> = VALUE.end..VALUE.end + 16;
    pub const MULT_RESULT: Range<usize> = MULTIPLIER.end..MULTIPLIER.end + 16;
    pub const TOKEN_ID: Range<usize> = MULT_RESULT.end..MULT_RESULT.end + 16;
}

pub(crate) const NUM_COLUMNS:usize = columns::TOKEN_ID.end;

pub(crate) fn ctl_looking_filter_output<F: Field>() -> Column<F> {
    Column::single(columns::IS_OUTPUT)
}

pub(crate) fn ctl_looking_filter_input<F: Field>() -> Column<F> {
    Column::single(columns::IS_INPUT)
}

pub fn ctl_looking_mult<F: Field>() -> Vec<Column<F>> {
    let indices = [columns::VALUE, columns::MULTIPLIER, columns::MULT_RESULT];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}

pub fn ctl_looking_token_id<F: Field>() -> Vec<Column<F>> {
    let indices = [columns::TOKEN_ID, columns::CALCULATION_ID..columns::CALCULATION_ID + 1];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}

pub fn ctl_looking_value<F: Field>() -> Vec<Column<F>> {
    let indices = [columns::VALUE, columns::CALCULATION_ID..columns::CALCULATION_ID + 1];
    let combined_indices: Vec<usize> = indices.iter().flat_map(|range| range.clone()).collect();
    Column::singles(combined_indices).collect()
}




pub(crate) fn ctl_filter_none<F: Field>() -> Column<F> {
    Column::constant(F::ZERO)
}

pub(crate) fn ctl_filter_not_init<F: Field>() -> Column<F> {
    Column::single(columns::NOT_INIT)
}

pub(crate) fn ctl_looked_acum_sum<F: Field>() -> Vec<Column<F>> {
    Column::singles(columns::ACUM_SUM).collect()
}


pub fn ctl_full_data<F: Field>() -> Vec<Column<F>> {
    let sum_cols = columns::ACUM_SUM.collect::<Vec<_>>();
    let mut outputs = vec![];
    for i in 0..8 {
        let cur_col = Column::linear_combination(
            sum_cols[i * 2..(i + 1) * 2]
                .iter()
                .enumerate()
                .map(|(j, &c)| (c, F::from_canonical_u64(1 << (16 * j)))),
        );
        outputs.push(cur_col);
    }
    outputs
}


#[derive(Copy, Clone, Default)]
pub struct SumStark<F, const D: usize> {
    f: PhantomData<F>,
}


const RANGE_MAX: usize = 1usize << 7;//1usize << 16;

impl<F: RichField, const D: usize> SumStark<F, D> {

    pub(crate) fn generate_trace(&self, result_ops: Vec<ChainResult>) -> Vec<PolynomialValues<F>> {
        let max_rows = std::cmp::max(result_ops.len(), RANGE_MAX);
        let mut trace_rows = Vec::with_capacity(max_rows);
        for op in result_ops {
            let rows = op.to_rows();
            for row in rows{
                trace_rows.push(row);
            }
        }

        let padded_len = trace_rows.len().next_power_of_two();
        for _ in trace_rows.len()..std::cmp::max(padded_len, RANGE_MAX) {
            trace_rows.push([F::ZERO; NUM_COLUMNS]);
        };


        trace_rows_to_poly_values(trace_rows)
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for SumStark<F, D> {
    const COLUMNS: usize = NUM_COLUMNS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField = F>,
        P: PackedField<Scalar = FE>,
    {
        let lv = vars.local_values;
        let nv = vars.next_values;
        let lv_is_input = lv[columns::IS_INPUT];
        let nv_is_input = nv[columns::IS_INPUT];
        let lv_is_output = lv[columns::IS_OUTPUT];
        let nv_is_output = nv[columns::IS_OUTPUT];
        let token_id = &lv[columns::TOKEN_ID];
        let multiplier = &lv[columns::MULTIPLIER];
        let not_init = lv[columns::NOT_INIT];
        yield_constr.constraint_first_row(lv_is_input * lv_is_input - lv_is_input);
        yield_constr.constraint_first_row(lv_is_output);
        yield_constr.constraint_transition(nv_is_input * nv_is_input - nv_is_input);
        yield_constr.constraint_transition(nv_is_output * nv_is_output - nv_is_output);
        yield_constr.constraint_last_row(nv_is_output * nv_is_output - nv_is_output);
        yield_constr.constraint_last_row(lv_is_input);
        if let Some(last_el)  = token_id.last(){
            let token_id_el = last_el.clone();
            yield_constr.constraint_transition(not_init * (token_id_el * P::ONES - multiplier.last().unwrap().clone() * token_id_el));
            yield_constr.constraint_last_row(not_init * (token_id_el * P::ONES - multiplier.last().unwrap().clone() * token_id_el));
        }
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let lv = vars.local_values;
        let nv = vars.next_values;
        let lv_is_input = lv[columns::IS_INPUT];
        let nv_is_input = nv[columns::IS_INPUT];
        let lv_is_output = lv[columns::IS_OUTPUT];
        let nv_is_output = nv[columns::IS_OUTPUT];
        let token_id = &lv[columns::TOKEN_ID];
        let multiplier = &lv[columns::MULTIPLIER];
        let not_init = lv[columns::NOT_INIT];
        let one = builder.one_extension();
        let mulsub = builder.mul_sub_extension(lv_is_input, lv_is_input, lv_is_input);
        yield_constr.constraint_first_row(builder, mulsub);
        yield_constr.constraint_first_row(builder, lv_is_output);
        let mul_sub = builder.mul_sub_extension(nv_is_input, nv_is_input, nv_is_input);
        yield_constr.constraint_transition(builder, mul_sub);
        let mul_sub = builder.mul_sub_extension(nv_is_output, nv_is_output, nv_is_output);
        yield_constr.constraint_transition(builder, mul_sub);
        let mul_sub = builder.mul_sub_extension(nv_is_output, nv_is_output, nv_is_output);
        yield_constr.constraint_last_row(builder, mul_sub);
        yield_constr.constraint_last_row(builder, lv_is_input);
        if let Some(last_el)  = token_id.last(){
            let token_id_el = last_el.clone();
            let constraint  = {
                let filter = builder.mul_extension(token_id_el, one);
                let filter_multiplier = builder.mul_extension(multiplier.last().unwrap().clone(), token_id_el);
                let sub = builder.sub_extension(filter, filter_multiplier);
                builder.mul_extension(not_init, sub)
            };
            yield_constr.constraint_transition(builder, constraint);
            yield_constr.constraint_last_row(builder, constraint);
        }
    }

    fn constraint_degree(&self) -> usize {
        3
    }
}