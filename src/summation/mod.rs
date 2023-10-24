use ethereum_types::U256;
use log::info;
use plonky2::field::types::PrimeField64;
use crate::arithmetic::{BinaryOperator, Operation};

use crate::arithmetic::utils::u256_to_array;
use crate::summation::sum_stark::columns;
use crate::summation::sum_stark::NUM_COLUMNS;

pub mod sum_stark;


#[derive(Debug)]
pub(crate) enum ChainResult {
    SumOperation {
        sum_result: Vec<U256>,
        mul_op: Vec<MulOp>

    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct MulOp{
    pub(crate) token_id: U256,
    pub(crate) value: U256,
    pub(crate) multiplier: U256,
    pub(crate) mul_result: U256,
}


impl ChainResult {
    pub(crate) fn to_rows<F: PrimeField64>(&self) -> Vec<[F; NUM_COLUMNS]> {
        match self {
            ChainResult::SumOperation { sum_result: result, mul_op: ops } =>
                sum_to_rows(result, ops),
        }
    }
}

pub fn sum_to_rows<F: PrimeField64>(
    result: &[U256],
    ops: &[MulOp],

) -> Vec<[F; NUM_COLUMNS]> {
    let mut calculation_id = 1;
    let mut row = [F::ZERO; NUM_COLUMNS];
    row[columns::IS_INPUT] = F::ONE;
    row[columns::IS_OUTPUT] = F::ONE;
    let mut rows: Vec<[F; NUM_COLUMNS]> = result.iter()
        .map(|_| row.clone())
        .collect();
    let last_row = rows.clone().len() - 1;
    let first_row = 0;
    rows[first_row][columns::IS_OUTPUT] = F::ZERO;
    rows[last_row][columns::IS_INPUT] = F::ZERO;
    u256_to_array(&mut rows[0][columns::ACUM_SUM], result[0]);
    for i in 1..result.len() {
        u256_to_array(&mut rows[i][columns::ACUM_SUM], result[i]);
        u256_to_array(&mut rows[i][columns::VALUE], ops[i - 1].value);
        u256_to_array(&mut rows[i][columns::MULTIPLIER], ops[i - 1].multiplier);
        u256_to_array(&mut rows[i][columns::MULT_RESULT], ops[i - 1].mul_result);
        u256_to_array(&mut rows[i][columns::TOKEN_ID], ops[i - 1].token_id);
        rows[i][columns::CALCULATION_ID] = F::from_canonical_u32(calculation_id);
        rows[i][columns::NOT_INIT] = F::ONE;
        calculation_id += 1;
    }

    rows
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChainOperator {
    Add,

}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct MulAdd {
    pub(crate) input0: U256,
    pub(crate) coef: U256,
    pub(crate) token_id: U256,
}

impl ChainOperator {
    pub(crate) fn result(
        &self,
        init: U256,
        mul_add_ops: &[MulAdd],
    ) -> (Vec<U256>, Vec<MulOp>) {
        match self {
            ChainOperator::Add => {
                let mut result: Vec<U256> = vec![];
                let mut mul_ops: Vec<MulOp> = vec![];
                let mut sum = init;
                result.push(sum);
                for i in 0..mul_add_ops.len() {
                    let left_operand = BinaryOperator::Mul.result(mul_add_ops[i].input0, mul_add_ops[i].coef);
                    let mul_op = MulOp{token_id: mul_add_ops[i].token_id,
                        value: mul_add_ops[i].input0,
                        multiplier: mul_add_ops[i].coef,
                        mul_result: left_operand,
                    };
                    let add_result = BinaryOperator::Add.result(
                        sum,
                        left_operand,
                    );
                    result.push(add_result);
                    sum = add_result;
                    mul_ops.push(mul_op);
                }
                (result, mul_ops)
            }
        }
    }

    pub(crate) fn to_binary_ops(&self, input0: &[MulAdd], result: &[U256]) -> Vec<Operation> {
        let mut ops = vec![];
        match self {
            ChainOperator::Add => {
                for i in 0..input0.len() {
                    let left_operand = BinaryOperator::Mul.result(input0[i].input0, input0[i].coef);
                    ops.push(Operation::binary(BinaryOperator::Mul, input0[i].input0, input0[i].coef));
                    ops.push(Operation::binary(BinaryOperator::Add, left_operand, result[i]));
                }
            }
        }
        ops
    }
}