use std::borrow::Borrow;
use std::marker::PhantomData;
use itertools::{Itertools};
use log::info;
use num::One;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use crate::block_header::{LogIndexes, Receipt};
use crate::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use crate::cross_table_lookup::Column;
use crate::data::columns;
use crate::data::columns::*;
use crate::data::data_stark::DataType::Leaf;
use crate::lookup::{eval_lookups, eval_lookups_circuit, eval_lookups_circuit_diff, eval_lookups_diff, permuted_cols};
use crate::permutation::PermutationPair;
use crate::search_substring::search_stark::columns::{HAYSTACK_SIZE};
use crate::search_substring::search_stark::SearchOp;
use crate::stark::Stark;
use crate::summation::sum_stark::columns::TOKEN_ID;
use crate::util::trace_rows_to_poly_values;
use crate::vars::{StarkEvaluationTargets, StarkEvaluationVars};


pub(crate) fn ctl_looked_data<F: Field>() -> Vec<Column<F>> {
    let cols = DATA_COL_MAP;

    Column::singles(
        cols.block_bytes
    )
        .collect()
}

pub(crate) fn ctl_looked_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::sum([cols.is_leaf, cols.is_node, cols.is_receipts_root])
}

pub(crate) fn ctl_pis_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::sum([cols.is_block_hash, cols.external_child_hash_found, cols.total_sum])
}

pub(crate) fn ctl_filter_none<F: Field>() -> Column<F> {
    Column::constant(F::ZERO)
}

pub(crate) fn ctl_looking_haystack_hash<F: Field>() -> Vec<Column<F>> {
    let cols = DATA_COL_MAP;
    Column::singles(
        [cols.prefix_bytes.as_slice(), &cols.block_bytes, &[cols.shift_num], &[cols.id]].concat()
    ).collect()
}

pub(crate) fn ctl_looking_keccak_sponge<F: Field>() -> Vec<Column<F>> {
    let cols = DATA_COL_MAP;

    Column::singles(
        cols.typed_data
    )
        .collect()
}

pub fn ctl_typed_data<F: Field>() -> Vec<Column<F>> {
    let mut outputs = vec![];
    let cols = DATA_COL_MAP;
    let root_cols = cols.typed_data;
    for i in (0..(KECCAK_DIGEST_BYTES / 4)).rev() {
        let cur_col = Column::linear_combination(
            root_cols[i * 4..(i + 1) * 4]
                .iter()
                .enumerate()
                .map(|(j, &c)| (c, F::from_canonical_u64(1 << (24 - 8 * j)))),
        );
        outputs.push(cur_col);
    }
    outputs
}

pub(crate) fn ctl_looking_needle_hash<F: Field>() -> Vec<Column<F>> {
    let cols = DATA_COL_MAP;

    Column::singles(
        [cols.typed_data.as_slice(), &[cols.zero_shift_num], &[cols.id]].concat()
    )
        .collect()
}

pub(crate) fn ctl_looking_token_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::single(cols.sold_token_id_found)
}


pub(crate) fn ctl_looking_keccak_sponge_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::sum([cols.child_hash_found, cols.receipts_root_found])
}

pub(crate) fn ctl_looking_receipts_root_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::single(cols.receipts_root_found)
}

pub(crate) fn ctl_looking_substr_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::sum([cols.child_hash_found, cols.transfer_value_found, cols.method_signature_found, cols.contract_address_found,
        cols.receipts_root_found, cols.external_child_hash_found, cols.sold_token_id_found, cols.total_sum])
}

pub(crate) fn ctl_looking_value<F: Field>() -> Vec<Column<F>> {
    let cols = DATA_COL_MAP;
    let mut outputs = vec![];
    // for i in (0..16).rev() {
    //     let cur_col = Column::linear_combination(
    //         cols.typed_data[i * 2..(i + 1) * 2]
    //             .iter()
    //             .enumerate()
    //             .map(|(j, &c)| (c, F::from_canonical_u64(1 << (8 - 8 * j)))),
    //     );
    //     outputs.push(cur_col);
    // }
    for i in (0..32).rev() {
        outputs.push(Column::single(cols.typed_data[i]));
    }
    outputs.push(Column::single(
        cols.calculation_id));
    outputs
}


pub(crate) fn ctl_looking_arithmetic_filter<F: Field>() -> Column<F> {
    let cols = DATA_COL_MAP;
    Column::single(cols.transfer_value_found)
}


const RANGE_MAX: usize = 1usize << 8;


#[derive(Clone, Debug, Copy)]
pub(crate) struct DataItem {
    pub(crate) offset: usize,
    pub(crate) offset_in_block: usize,
    pub(crate) item: [u8; KECCAK_DIGEST_BYTES],
}

#[derive(Clone, Debug, Copy)]
pub(crate) struct EventLogPart {
    pub(crate) contract: DataItem,
    pub(crate) value: DataItem,
    pub(crate) token_id: DataItem,
    pub(crate) method_signature: DataItem,
    pub(crate) event_rlp_index: usize,
    pub(crate) bought_token_volume_index: usize,
}


#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DataType {
    Leaf = 0,
    Node = 1,
    ReceiptsRoot = 3,
    BlockHash = 4,
    TotalSum = 5,
}

#[derive(Clone, Debug)]
pub(crate) struct DataOp {
    pub(crate) input: Vec<u8>,
    pub(crate) event_logs: Option<Vec<EventLogPart>>,
    pub(crate) child: Option<Vec<DataItem>>,
    pub(crate) external_child: Option<Vec<DataItem>>,
    pub(crate) data_type: DataType,
    pub(crate) receipts_root: Option<DataItem>,
    pub(crate) pi_sum: Option<DataItem>,
}

#[derive(Copy, Clone, Default)]
pub struct DataStark<F, const D: usize> {
    f: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> DataStark<F, D> {
    fn generate_range_checks(&self, cols: &mut Vec<Vec<F>>) {
        debug_assert!(cols.len() == NUM_DATA_COLUMNS);
        let n_rows = cols[0].len();
        debug_assert!(cols.iter().all(|col| col.len() == n_rows));


        for i in 0..RANGE_MAX {
            cols[RANGE_COUNTER][i] = F::from_canonical_usize(i);
        }

        for i in RANGE_MAX..n_rows {
            cols[RANGE_COUNTER][i] = F::from_canonical_usize(RANGE_MAX - 1);
        }
        for (c, rc_c) in BLOCK_BYTES.zip(RC_COLS.step_by(2)) {
            let (col_perm, table_perm) = permuted_cols(&cols[c], &cols[RANGE_COUNTER]);
            cols[rc_c].copy_from_slice(&col_perm);
            cols[rc_c + 1].copy_from_slice(&table_perm);
        }

        // let (col_perm, table_perm) = permuted_cols(&cols[START_OF_EVENT], &cols[END_OF_EVENT]);
        // cols[EVENT_INDEX.start].copy_from_slice(&col_perm);
        // cols[EVENT_INDEX.start + 1].copy_from_slice(&table_perm);
        // info!("col_perm : {:?}",  cols[EVENT_INDEX.start]);
        // info!("table_perm : {:?}",  cols[EVENT_INDEX.start + 1]);
    }

    pub(crate) fn generate_trace(
        &self,
        operations: Vec<DataOp>,
        timing: &mut TimingTree,
    ) -> (Vec<PolynomialValues<F>>, Vec<SearchOp>) {
        // Generate the witness row-wise.
        let (trace_rows, search_ops) = timed!(
            timing,
            "generate trace rows",
            self.generate_trace_rows(operations)
        );

        let trace_polys = timed!(
            timing,
            "convert to PolynomialValues",
            trace_rows.into_iter().map(PolynomialValues::new).collect()
        );

        (trace_polys, search_ops)
    }

    fn generate_trace_rows(
        &self,
        operations: Vec<DataOp>,
    ) -> (Vec<Vec<F>>, Vec<SearchOp>) {
        let mut rows = vec![];
        let mut index = 1;
        let mut calculation_id = 1;
        let mut search_ops = vec![];
        for op in operations {
            rows.extend(self.generate_rows_for_op(op, &mut index, &mut search_ops, &mut calculation_id));
        }

        let padded_len = rows.len().next_power_of_two();
        for _ in rows.len()..std::cmp::max(padded_len, RANGE_MAX) {
            rows.push(self.generate_padding_row());
        }

        let mut converted_rows: Vec<Vec<F>> = rows.iter().map(|&array| array.to_vec()).collect();
        let mut trace_cols = transpose(&mut converted_rows);
        self.generate_range_checks(&mut trace_cols);
        (trace_cols, search_ops)
    }

    fn generate_search_op(&self, row: &DataColumnsView<F>) -> SearchOp {
        let mut search_haystack = [0u8; KECCAK_DIGEST_BYTES + KECCAK_RATE_BYTES];
        let prefix: [u8; 32] = row.prefix_bytes
            .iter()
            .take(32)
            .map(|&x| F::to_canonical_u64(&x) as u8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to [u8; 32]"));
        let block: [u8; 136] = row.block_bytes
            .iter()
            .take(136)
            .map(|&x| F::to_canonical_u64(&x) as u8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to [u8; 136]"));
        let search_data: [u8; 32] = row.typed_data
            .iter()
            .take(32)
            .map(|&x| F::to_canonical_u64(&x) as u8)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap_or_else(|_| panic!("Failed to convert to [u8; 32]"));
        search_haystack[0..KECCAK_DIGEST_BYTES].copy_from_slice(&prefix);
        search_haystack[KECCAK_DIGEST_BYTES..].copy_from_slice(&block);
        let search_offset = F::to_canonical_u64(&row.offset_block) as usize;
        let search_id = F::to_canonical_u64(&row.id) as usize;
        let search_op = SearchOp {
            input: search_haystack,
            sub_string: search_data,
            offset: search_offset,
            id: search_id,
        };
        search_op
    }


    fn generate_rows_for_op(&self, op: DataOp, index: &mut u64, search_ops: &mut Vec<SearchOp>, calculation_id: &mut u64) -> Vec<[F; NUM_DATA_COLUMNS]> {
        let mut rows = vec![];
        let mut input_blocks = op.input.chunks_exact(KECCAK_RATE_BYTES);
        let mut already_absorbed_bytes = 0;
        let mut index_block = 0;
        let mut previous_block: Option<DataColumnsView<F>> = None;
        let mut log_idxs = if op.data_type == DataType::Leaf {
            let rlp_idx = Receipt::split_rlp(&op.input).expect("RLP not splitted correctly");
            info!("INDEXES : {:?}", rlp_idx);
            let (start_list_idx, end_list_idx) = rlp_idx.logs_container_idx;
            let mut offset_header = 0;
            match op.input[start_list_idx] {
                248 => offset_header += 2,
                249 => offset_header += 3,
                _ => offset_header += 0,
            }
            info!("{:?}", end_list_idx);
            Some(LogIndexes { logs_container_idx: (start_list_idx + offset_header, end_list_idx), logs_idx: rlp_idx.logs_idx })
        } else {
            None
        };
        for block in input_blocks.by_ref() {
            let mut block_rows = self.generate_full_input_row(
                &op,
                already_absorbed_bytes,
                block.try_into().unwrap(),
                index,
                calculation_id,
                log_idxs.as_mut(),
            );
            let mut temp_row: DataColumnsView<F> = Default::default();
            if index_block == 0 {
                temp_row.prefix_bytes = [F::ZERO; KECCAK_DIGEST_BYTES];
            } else if let Some(prev_block) = &previous_block {
                temp_row.prefix_bytes.copy_from_slice(&prev_block.block_bytes[KECCAK_RATE_BYTES - 32..]);
            }
            for mut row in block_rows.clone() {
                row.prefix_bytes = temp_row.prefix_bytes;
                temp_row = row.clone();
                if row.id != F::ZERO {
                    let search_op = self.generate_search_op(&row.clone());
                    search_ops.push(search_op);
                }
                rows.push(row.into());
            }
            previous_block = Some(temp_row.clone());
            already_absorbed_bytes += KECCAK_RATE_BYTES;
            index_block += 1;
        }
        let mut final_rows = self.generate_final_row(
            &op,
            already_absorbed_bytes,
            input_blocks.remainder(),
            index,
            calculation_id,
            log_idxs.as_mut(),
        );
        for mut row in final_rows.clone() {
            if let Some(prev_block) = &previous_block {
                row.prefix_bytes.copy_from_slice(&prev_block.block_bytes[KECCAK_RATE_BYTES - 32..]);
            }
            if row.id != F::ZERO {
                let search_op = self.generate_search_op(&row.clone());
                search_ops.push(search_op);
            }
            rows.push(row.into());
        }

        rows
    }

    fn generate_full_input_row(
        &self,
        op: &DataOp,
        already_absorbed_bytes: usize,
        block: [u8; KECCAK_RATE_BYTES],
        index: &mut u64,
        calculation_id: &mut u64,
        log_idxs: Option<&mut LogIndexes>,
    ) -> Vec<DataColumnsView<F>> {
        let mut row = DataColumnsView {
            is_full_input_block: F::ONE,
            ..Default::default()
        };
        row.block_bytes = block.map(F::from_canonical_u8);
        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, index, calculation_id, log_idxs)
    }


    fn generate_final_row(
        &self,
        op: &DataOp,
        already_absorbed_bytes: usize,
        final_inputs: &[u8],
        index: &mut u64,
        calculation_id: &mut u64,
        log_idxs: Option<&mut LogIndexes>,
    ) -> Vec<DataColumnsView<F>> {
        assert_eq!(already_absorbed_bytes + final_inputs.len(), op.input.len());

        let mut row = DataColumnsView::default();

        for (block_byte, input_byte) in row.block_bytes.iter_mut().zip(final_inputs) {
            *block_byte = F::from_canonical_u8(*input_byte);
        }

        // pad10*1 rule
        if final_inputs.len() == KECCAK_RATE_BYTES - 1 {
            // Both 1s are placed in the same byte.
            row.block_bytes[final_inputs.len()] = F::from_canonical_u8(0b10000001);
        } else {
            row.block_bytes[final_inputs.len()] = F::ONE;
            row.block_bytes[KECCAK_RATE_BYTES - 1] = F::from_canonical_u8(0b10000000);
        }


        row.last_block = F::from_bool(true);
        Self::generate_common_fields(&mut row, op, already_absorbed_bytes, index, calculation_id, log_idxs)
    }

    fn generate_data_fields(row: &mut DataColumnsView<F>,
                            item: &DataItem) {
        row.typed_data = item.item.map(F::from_canonical_u8);
        row.offset_object = F::from_canonical_usize(item.offset);
        row.offset_block = F::from_canonical_usize(item.offset_in_block);
        row.shift_num = F::from_canonical_usize(HAYSTACK_SIZE - item.offset_in_block);
    }

    fn generate_log_fields(mut log_idxs: Option<&mut &mut LogIndexes>, row: &mut DataColumnsView<F>,
                            ) {
        match log_idxs {
            None => {}
            Some(mut logs) => {
                row.is_event_log = F::from_bool(true);
                row.start_of_event = F::from_canonical_usize(logs.logs_idx[0].0);
                row.end_of_event = F::from_canonical_usize(logs.logs_idx[0].0);
            }
        }
    }

    /// Generate fields that are common to both full-input-block rows and final-block rows.
    /// Also updates the sponge state with a single absorption.
    fn generate_common_fields(
        row: &mut DataColumnsView<F>,
        op: &DataOp,
        already_absorbed_bytes: usize,
        index_op: &mut u64,
        calculation_id: &mut u64,
        mut log_idxs: Option<&mut LogIndexes>,
    ) -> Vec<DataColumnsView<F>> {
        let mut rows: Vec<DataColumnsView<F>> = vec![];
        row.len = F::from_canonical_usize(op.input.len());
        row.already_absorbed_bytes = F::from_canonical_usize(already_absorbed_bytes);
        row.is_leaf = F::from_bool(op.data_type == Leaf);
        row.is_node = F::from_bool(op.data_type == DataType::Node);
        row.is_receipts_root = F::from_bool(op.data_type == DataType::ReceiptsRoot);
        row.is_block_hash = F::from_bool(op.data_type == DataType::BlockHash);
        let mut row_clone = row.clone();
        match op.event_logs.clone() {
            Some(item) => {
                if already_absorbed_bytes == 0 {
                    match log_idxs.as_mut() {
                        None => {}
                        Some(indexes) => {
                            row_clone = row.clone();
                            row_clone.start_of_event = F::from_canonical_usize(indexes.logs_container_idx.1);
                            row_clone.end_of_event = F::from_canonical_usize(indexes.logs_container_idx.0);
                            row_clone.is_event_log = F::from_bool(true);
                            rows.push(row_clone);
                        }
                    }
                }
                for event in item {
                    if (event.contract.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (event.contract.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        row_clone.contract_address_found = F::from_bool(true);
                        Self::generate_data_fields(&mut row_clone, &event.contract);
                        match log_idxs.as_mut() {
                            None => {}
                            Some(mut logs) => {
                                let start = logs.logs_idx[0].0;
                                let end = logs.logs_idx[0].1;
                                if end + KECCAK_DIGEST_BYTES >= already_absorbed_bytes && end + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES {
                                    row_clone.is_event_log = F::from_bool(true);
                                    row_clone.start_of_event = F::from_canonical_usize(start);
                                    row_clone.end_of_event = F::from_canonical_usize(end + 1);
                                    logs.logs_idx.remove(0);
                                } else {
                                    row_clone.is_event_log = F::from_bool(true);
                                    row_clone.start_of_event = F::from_canonical_usize(start);
                                    row_clone.end_of_event = F::from_canonical_usize(start);
                                }
                            }
                        }
                        rows.push(row_clone.clone());
                    }
                    if (event.method_signature.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (event.method_signature.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        row_clone.method_signature_found = F::from_bool(true);
                        Self::generate_data_fields(&mut row_clone, &event.method_signature);
                        Self::generate_log_fields(log_idxs.as_mut(), &mut row_clone);
                        rows.push(row_clone.clone());
                    }
                    if (event.token_id.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (event.token_id.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        row_clone.sold_token_id_found = F::from_bool(true);
                        Self::generate_data_fields(&mut row_clone, &event.token_id);
                        row_clone.calculation_id = F::from_canonical_u64(*calculation_id);
                        Self::generate_log_fields(log_idxs.as_mut(), &mut row_clone);
                        rows.push(row_clone.clone());
                    }
                    if (event.value.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (event.value.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        Self::generate_data_fields(&mut row_clone, &event.value);
                        row_clone.calculation_id = F::from_canonical_u64(*calculation_id);
                        row_clone.transfer_value_found = F::from_bool(true);
                        match log_idxs.as_mut() {
                            None => {}
                            Some(mut logs) => {
                                row_clone.is_event_log = F::from_bool(true);
                                row_clone.start_of_event = F::from_canonical_usize(event.event_rlp_index);
                                row_clone.end_of_event = F::from_canonical_usize(event.bought_token_volume_index);
                                logs.logs_idx.remove(0);
                            }
                        }
                        *calculation_id += 1;
                        rows.push(row_clone.clone());
                    }
                }
            }
            None => {}
        }
        match op.child.clone() {
            Some(mut data_items) => {
                let mut index = 0;
                for item in &data_items {
                    if (item.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (item.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        Self::generate_data_fields(&mut row_clone, &item);
                        row_clone.child_hash_found = F::from_bool(true);
                        rows.push(row_clone.clone());
                        data_items.clone().remove(index);
                        index += 1;
                    }
                }
            }
            None => {}
        };
        match op.external_child.clone() {
            Some(data_items) => {
                for item in &data_items {
                    if (item.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (item.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                        row_clone = row.clone();
                        row_clone.external_child_hash_found = F::from_bool(true);
                        Self::generate_data_fields(&mut row_clone, &item);
                        rows.push(row_clone.clone());
                    }
                }
            }
            None => {}
        };
        match op.receipts_root {
            Some(item) => {
                if (item.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (item.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                    row_clone = row.clone();
                    row_clone.receipts_root_found = F::from_bool(true);
                    Self::generate_data_fields(&mut row_clone, &item);
                    rows.push(row_clone.clone());
                }
            }
            None => {}
        };
        match op.pi_sum {
            Some(item) => {
                if (item.offset + KECCAK_DIGEST_BYTES >= already_absorbed_bytes) && (item.offset + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES) {
                    row_clone = row.clone();
                    row_clone.total_sum = F::from_bool(true);
                    Self::generate_data_fields(&mut row_clone, &item);
                    rows.push(row_clone.clone());
                }
            }
            None => {}
        }
        if rows.is_empty() {
            let mut row_clone = row.clone();
            match log_idxs.as_mut() {
                None => {}
                Some(mut logs) => {
                    let mut index = 0;
                    let mut not_found = true;
                    for (start_idx, end_idx) in &logs.logs_idx {
                        if end_idx + KECCAK_DIGEST_BYTES >= already_absorbed_bytes && end_idx + KECCAK_DIGEST_BYTES < already_absorbed_bytes + KECCAK_RATE_BYTES {
                            row_clone.start_of_event = F::from_canonical_usize(*start_idx);
                            row_clone.end_of_event = F::from_canonical_usize(end_idx + 1);
                            row_clone.is_event_log = F::from_bool(true);
                            logs.logs_idx.remove(index);
                            not_found = false;
                            break;
                        }
                        index += 1;
                    }
                    if not_found {
                        Self::generate_log_fields(log_idxs.as_mut(), &mut row_clone);
                    }
                }
            }
            if row_clone.last_block == F::from_bool(true) {
                row_clone.is_event_log = F::from_bool(false);
            }
            rows.push(row_clone);
        } else if rows.len() > 1 {
            rows[0].id = F::from_canonical_u64(*index_op);
            rows[0].is_shadow = F::from_bool(false);
            *index_op += 1;
            for i in 1..rows.len() {
                rows[i].is_shadow = F::from_bool(true);
                rows[i].last_block = F::from_bool(false);
                rows[i].is_leaf = F::from_bool(false);
                rows[i].is_node = F::from_bool(false);
                rows[i].is_receipts_root = F::from_bool(false);
                rows[i].is_block_hash = F::from_bool(false);
                rows[i].id = F::from_canonical_u64(*index_op);
                *index_op += 1;
            }
            if rows[0].last_block == F::from_bool(true) {
                rows[0].last_block = F::from_bool(false);
                if let Some(row) = rows.last_mut() {
                    match log_idxs.as_mut() {
                        None => { row.last_block = F::from_bool(true); }
                        Some(indexes) => {
                            let mut temp_row = DataColumnsView::default();
                            temp_row.already_absorbed_bytes = row.already_absorbed_bytes;
                            temp_row.last_block = F::from_bool(true);
                            temp_row.block_bytes = row.block_bytes;
                            temp_row.is_shadow = F::from_bool(true);
                            temp_row.prefix_bytes = row.prefix_bytes;
                            temp_row.start_of_event = F::from_canonical_usize(indexes.logs_container_idx.1 + 1);
                            temp_row.end_of_event = F::from_canonical_usize(indexes.logs_container_idx.0);
                            rows.push(temp_row);
                        }
                    }
                }
            }
        } else {
            if rows[0].last_block == F::from_bool(true) {
                rows[0].is_event_log = F::from_bool(false);
            }
            if rows[0].is_event_log != F::from_bool(true) {
                rows[0].id = F::from_canonical_u64(*index_op);
                *index_op += 1;
            }
        }
        if op.data_type == Leaf {
            info!("ROWS : {:?}", rows);
        }
        rows
    }

    fn generate_padding_row(&self) -> [F; NUM_DATA_COLUMNS] {
        // The default instance has is_full_input_block = is_final_block = 0,
        // indicating that it's a dummy/padding row.
        DataColumnsView::default().into()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> Stark<F, D> for DataStark<F, D> {
    const COLUMNS: usize = NUM_DATA_COLUMNS;

    fn eval_packed_generic<FE, P, const D2: usize>(
        &self,
        vars: StarkEvaluationVars<FE, P, { Self::COLUMNS }>,
        yield_constr: &mut ConstraintConsumer<P>,
    ) where
        FE: FieldExtension<D2, BaseField=F>,
        P: PackedField<Scalar=FE>,
    {
        for col in RC_COLS.step_by(2) {
            eval_lookups(vars, yield_constr, col, col + 1);
        }
        let local_values: &DataColumnsView<P> = vars.local_values.borrow();
        let next_values: &DataColumnsView<P> = vars.next_values.borrow();
        yield_constr.constraint(local_values.is_event_log * (next_values.start_of_event - local_values.end_of_event));


        let rc1 = local_values.range_counter;
        let rc2 = next_values.range_counter;
        yield_constr.constraint_first_row(rc1);
        let incr = rc2 - rc1;
        yield_constr.constraint_transition(incr * incr - incr);
        let range_max = P::Scalar::from_canonical_u64((RANGE_MAX - 1) as u64);
        yield_constr.constraint_last_row(rc1 - range_max);


        let method_signature: [u8; 32] = [139, 62, 150, 242, 184, 137, 250, 119, 28, 83, 201, 129, 180, 13, 175, 0, 95, 99, 246, 55, 241, 134, 159, 112, 112, 82, 209, 90, 61, 217, 113, 64];
        let converted_method_signature = method_signature.map(|byte| P::from(FE::from_canonical_u8(byte)));

        let pool_address: [u8; 20] = [190, 188, 68, 120, 44, 125, 176, 161, 166, 12, 182, 254, 151, 208, 180, 131, 3, 47, 241, 199];
        let converted_pool_address = pool_address.map(|byte| P::from(FE::from_canonical_u8(byte)));
        let method_length = P::from(FE::from_canonical_u8(32));
        let token_id_length = P::from(FE::from_canonical_u8(32));
        let contract_length = P::from(FE::from_canonical_u8(20));

        let offset_contract_method = P::from(FE::from_canonical_u8(3));
        let offset_contract_token_id = P::from(FE::from_canonical_u8(35));

        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        let is_last_block = local_values.last_block;
        yield_constr.constraint(is_full_input_block * (is_full_input_block - P::ONES));

        //Ensure that zero_shift_num is always zero
        yield_constr.constraint(P::ZEROS - local_values.zero_shift_num);

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        yield_constr.constraint(is_last_block * is_full_input_block);
        //
        // // If this is a final block, the next row's original sponge state should be 0 and already_absorbed_bytes = 0.
        yield_constr.constraint_transition(is_last_block * next_values.already_absorbed_bytes);
        // //
        // // // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus 136.
        yield_constr.constraint_transition(
            next_values.already_absorbed_bytes * (P::ONES - next_values.is_shadow)
                * (local_values.already_absorbed_bytes + P::from(FE::from_canonical_u64(136))
                - next_values.already_absorbed_bytes),
        );

        yield_constr.constraint_transition(
            next_values.is_shadow
                * (local_values.already_absorbed_bytes
                - next_values.already_absorbed_bytes),
        );
        //
        // // //A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = P::ONES - is_full_input_block - is_last_block;
        let next_is_final_block: P = next_values.last_block;
        yield_constr.constraint_transition(
            (P::ONES - next_values.is_shadow) * is_dummy * (next_values.is_full_input_block + next_is_final_block),
        );

        // // //Ensure that if we have more than 2 objects of 32 length in one block, is_shadow will be 1
        // // // and next row has the same prefix, block_bytes as previous
        let is_shadow = next_values.is_shadow;
        for (&xi, &yi) in local_values.prefix_bytes.iter().zip_eq(next_values.prefix_bytes.iter()) {
            yield_constr.constraint_transition(
                is_shadow * (xi - yi),
            );
        }
        for (&xi, &yi) in local_values.block_bytes.iter().zip_eq(next_values.block_bytes.iter()) {
            yield_constr.constraint_transition(
                is_shadow * (xi - yi),
            );
        }

        for (&xi, &yi) in converted_method_signature.iter().zip_eq(local_values.typed_data.iter()) {
            yield_constr.constraint_transition(
                local_values.method_signature_found * (xi - yi),
            );
        }

        for (&xi, &yi) in converted_pool_address.iter().zip_eq(local_values.typed_data.iter().take(20)) {
            yield_constr.constraint_transition(local_values.contract_address_found * (xi - yi));
        }

        yield_constr.constraint_transition(local_values.contract_address_found *
            (next_values.offset_object - (local_values.offset_object + contract_length) - offset_contract_method));
        yield_constr.constraint_transition(local_values.method_signature_found *
            (next_values.offset_object - (local_values.offset_object + method_length) - offset_contract_token_id));
        yield_constr.constraint_transition(local_values.sold_token_id_found *
            (next_values.offset_object - (local_values.offset_object + token_id_length)));
    }

    fn eval_ext_circuit(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
        vars: StarkEvaluationTargets<D, { Self::COLUMNS }>,
        yield_constr: &mut RecursiveConstraintConsumer<F, D>,
    ) {
        let one = builder.one_extension();
        for col in RC_COLS.step_by(2) {
            eval_lookups_circuit(builder, vars, yield_constr, col, col + 1);
        }

        let local_values: &DataColumnsView<ExtensionTarget<D>> = vars.local_values.borrow();
        let next_values: &DataColumnsView<ExtensionTarget<D>> = vars.next_values.borrow();

        let constraint = {
            let filter = local_values.is_event_log;
            let sub = builder.sub_extension(next_values.start_of_event, local_values.end_of_event);
            builder.mul_extension(filter, sub)
        };

        yield_constr.constraint(builder, constraint);

        let rc1 = local_values.range_counter;
        let rc2 = next_values.range_counter;
        yield_constr.constraint_first_row(builder, rc1);
        let incr = builder.sub_extension(rc2, rc1);
        let t = builder.mul_sub_extension(incr, incr, incr);
        yield_constr.constraint_transition(builder, t);
        let range_max =
            builder.constant_extension(F::Extension::from_canonical_usize(RANGE_MAX - 1));
        let t = builder.sub_extension(rc1, range_max);
        yield_constr.constraint_last_row(builder, t);


        let method_signature: [u8; 32] = [139, 62, 150, 242, 184, 137, 250, 119, 28, 83, 201, 129, 180, 13, 175, 0, 95, 99, 246, 55, 241, 134, 159, 112, 112, 82, 209, 90, 61, 217, 113, 64];
        let converted_method_signature = method_signature.map(|byte| F::Extension::from_canonical_u8(byte));

        let pool_address: [u8; 20] = [190, 188, 68, 120, 44, 125, 176, 161, 166, 12, 182, 254, 151, 208, 180, 131, 3, 47, 241, 199];
        let converted_pool_address = pool_address.map(|byte| F::Extension::from_canonical_u8(byte));

        let contract_length = builder.constant_extension(F::Extension::from_canonical_u8(20));
        let method_length = builder.constant_extension(F::Extension::from_canonical_u8(32));
        let token_id_length = builder.constant_extension(F::Extension::from_canonical_u8(32));

        let offset_contract_method = builder.constant_extension(F::Extension::from_canonical_u8(3));
        let offset_contract_token_id = builder.constant_extension(F::Extension::from_canonical_u8(35));
        // Each flag (full-input block, final block or implied dummy flag) must be boolean.
        let is_full_input_block = local_values.is_full_input_block;
        let is_last_block = local_values.last_block;
        let constraint = builder.mul_sub_extension(
            is_full_input_block,
            is_full_input_block,
            is_full_input_block,
        );
        yield_constr.constraint(builder, constraint);

        //Ensure that zero_shift_num is always zero
        let zero = builder.zero_extension();
        let constraint = builder.sub_extension(zero, local_values.zero_shift_num);
        yield_constr.constraint(builder, constraint);

        // Ensure that full-input block and final block flags are not set to 1 at the same time.
        let constraint = builder.mul_extension(is_last_block, is_full_input_block);
        yield_constr.constraint(builder, constraint);

        let constraint = builder.mul_extension(is_last_block, next_values.already_absorbed_bytes);
        yield_constr.constraint_transition(builder, constraint);

        // If this is the first row, the original sponge state should be 0 and already_absorbed_bytes = 0.
        let already_absorbed_bytes = local_values.already_absorbed_bytes;

        // If this is a full-input block, the next row's already_absorbed_bytes should be ours plus 136.
        let shadow_is_zero = builder.sub_extension(one, next_values.is_shadow);
        let absorbed_bytes =
            builder.add_const_extension(already_absorbed_bytes, F::from_canonical_u64(136));
        let absorbed_diff =
            builder.sub_extension(absorbed_bytes, next_values.already_absorbed_bytes);
        let filter = builder.mul_extension(next_values.already_absorbed_bytes, shadow_is_zero);
        let constraint = builder.mul_extension(filter, absorbed_diff);
        yield_constr.constraint_transition(builder, constraint);
        //
        let absorbed_diff = builder.sub_extension(already_absorbed_bytes, next_values.already_absorbed_bytes);
        let constraint = builder.mul_extension(next_values.is_shadow, absorbed_diff);
        yield_constr.constraint_transition(builder, constraint);

        // // A dummy row is always followed by another dummy row, so the prover can't put dummy rows "in between" to avoid the above checks.
        let is_dummy = {
            let tmp = builder.sub_extension(one, is_last_block);
            builder.sub_extension(tmp, is_full_input_block)
        };
        let constraint = {
            let tmp = builder.add_extension(next_values.last_block, next_values.is_full_input_block);
            let tmp2 = builder.mul_extension(is_dummy, tmp);
            let tmp3 = builder.sub_extension(one, next_values.is_shadow);
            builder.mul_extension(tmp2, tmp3)
        };
        yield_constr.constraint_transition(builder, constraint);

        // //Ensure that if we have more than 2 objects of 32 length in one block, is_shadow will be 1
        // // and next row has the same prefix, block_bytes as previous
        let is_shadow = next_values.is_shadow;
        for (&xi, &yi) in local_values.prefix_bytes.iter().zip_eq(next_values.prefix_bytes.iter()) {
            let constraint = {
                let tmp = builder.sub_extension(xi, yi);
                builder.mul_extension(is_shadow, tmp)
            };
            yield_constr.constraint_transition(
                builder, constraint,
            );
        }
        for (&xi, &yi) in local_values.block_bytes.iter().zip_eq(next_values.block_bytes.iter()) {
            let constraint = {
                let tmp = builder.sub_extension(xi, yi);
                builder.mul_extension(is_shadow, tmp)
            };
            yield_constr.constraint_transition(
                builder, constraint,
            );
        }

        for (&xi, &yi) in converted_method_signature.iter().zip_eq(local_values.typed_data.iter()) {
            let constraint = {
                let constant_byte = builder.constant_extension(xi);
                let sub = builder.sub_extension(constant_byte, yi);
                builder.mul_extension(local_values.method_signature_found, sub)
            };
            yield_constr.constraint_transition(
                builder, constraint,
            );
        }

        for (&xi, &yi) in converted_pool_address.iter().zip_eq(local_values.typed_data.iter().take(20)) {
            let constraint = {
                let constant_byte = builder.constant_extension(xi);
                let sub = builder.sub_extension(constant_byte, yi);
                builder.mul_extension(local_values.contract_address_found, sub)
            };
            yield_constr.constraint_transition(
                builder, constraint,
            );
        }
        let constraint = {
            let addition = builder.add_extension(local_values.offset_object, contract_length);
            let offset_diff = builder.sub_extension(next_values.offset_object, addition);
            let overall_diff = builder.sub_extension(offset_diff, offset_contract_method);
            builder.mul_extension(local_values.contract_address_found, overall_diff)
        };
        yield_constr.constraint_transition(builder, constraint);

        let constraint = {
            let addition = builder.add_extension(local_values.offset_object, method_length);
            let offset_diff = builder.sub_extension(next_values.offset_object, addition);
            let overall_diff = builder.sub_extension(offset_diff, offset_contract_token_id);
            builder.mul_extension(local_values.method_signature_found, overall_diff)
        };
        yield_constr.constraint_transition(builder, constraint);

        let constraint = {
            let addition = builder.add_extension(local_values.offset_object, token_id_length);
            let offset_diff = builder.sub_extension(next_values.offset_object, addition);
            builder.mul_extension(local_values.sold_token_id_found, offset_diff)
        };
        yield_constr.constraint_transition(builder, constraint);
    }

    fn constraint_degree(&self) -> usize {
        3
    }

    fn permutation_pairs(&self) -> Vec<PermutationPair> {
        const START: usize = START_BYTES_COLS;
        const END: usize = START + KECCAK_RATE_BYTES;
        let mut pairs = Vec::with_capacity(2 * KECCAK_RATE_BYTES);
        for (c, c_perm) in (START..END).zip_eq(RC_COLS.step_by(2)) {
            pairs.push(PermutationPair::singletons(c, c_perm));
            pairs.push(PermutationPair::singletons(
                c_perm + 1,
                RANGE_COUNTER,
            ));
        }
        // pairs.push(PermutationPair::singletons(START_OF_EVENT, EVENT_INDEX.start));
        // pairs.push(PermutationPair::singletons(
        //     EVENT_INDEX.start + 1,
        //     END_OF_EVENT,
        // ));
        pairs
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use anyhow::Result;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use crate::keccak_sponge::keccak_sponge_stark::{KeccakSpongeStark};
    use crate::stark_testing::{test_stark_circuit_constraints, test_stark_low_degree};

    #[test]
    fn test_stark_degree() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakSpongeStark<F, D>;
        let stark = S::default();
        test_stark_low_degree(stark)
    }

    #[test]
    fn test_stark_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type S = KeccakSpongeStark<F, D>;

        let stark = S::default();
        test_stark_circuit_constraints::<F, C, S, D>(stark)
    }
}