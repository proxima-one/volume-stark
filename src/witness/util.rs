// use core::slice::SlicePattern;

use ethereum_types::U256;
use log::info;
use plonky2::field::types::Field;
use crate::all_stark::Table::Data;

use crate::arithmetic::{Operation, BinaryOperator};
// use crate::cpu::columns::CpuColumnsView;
// use crate::cpu::kernel::keccak_util::keccakf_u8s;
// use crate::cpu::membus::{NUM_CHANNELS, NUM_GP_CHANNELS};
// use crate::cpu::stack_bounds::MAX_USER_STACK_SIZE;
use crate::data::columns::KECCAK_DIGEST_BYTES;
use crate::data::data_stark::{DataOp, DataType, DataItem, EventLogPart};
use crate::generation::GenerationState;
// use crate::generation::state::GenerationState;
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_WIDTH_BYTES};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::keccak_sponge::keccak_util::keccakf_u8s;
use crate::logic;
use crate::patricia_merkle_trie::{EventParts, PatriciaMerklePathElement};
// use crate::public::PublicOp;
use crate::search_substring::search_stark::SearchOp;
// use crate::memory::segments::Segment;
use crate::summation::{ChainOperator, ChainResult, MulAdd};
use crate::witness::errors::ProgramError;

// use super::traces::PublicOp;
// use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryOp, MemoryOpKind};

fn to_byte_checked(n: U256) -> u8 {
    let res = n.byte(0);
    assert_eq!(n, res.into());
    res
}

fn to_bits_le<F: Field>(n: u8) -> [F; 8] {
    let mut res = [F::ZERO; 8];
    for (i, bit) in res.iter_mut().enumerate() {
        *bit = F::from_bool(n & (1 << i) != 0);
    }
    res
}
/*
/// Peek at the stack item `i`th from the top. If `i=0` this gives the tip.
pub(crate) fn stack_peek<F: Field>(state: &GenerationState<F>, i: usize) -> Option<U256> {
    if i >= state.registers.stack_len {
        return None;
    }
    Some(state.memory.get(MemoryAddress::new(
        state.registers.context,
        Segment::Stack,
        state.registers.stack_len - 1 - i,
    )))
}

/// Peek at kernel at specified segment and address
pub(crate) fn current_context_peek<F: Field>(
    state: &GenerationState<F>,
    segment: Segment,
    virt: usize,
) -> U256 {
    let context = state.registers.context;
    state.memory.get(MemoryAddress::new(context, segment, virt))
}

pub(crate) fn mem_read_with_log<F: Field>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &GenerationState<F>,
) -> (U256, MemoryOp) {
    let val = state.memory.get(address);
    let op = MemoryOp::new(
        channel,
        state.traces.clock(),
        address,
        MemoryOpKind::Read,
        val,
    );
    (val, op)
}

pub(crate) fn mem_write_log<F: Field>(
    channel: MemoryChannel,
    address: MemoryAddress,
    state: &mut GenerationState<F>,
    val: U256,
) -> MemoryOp {
    MemoryOp::new(
        channel,
        state.traces.clock(),
        address,
        MemoryOpKind::Write,
        val,
    )
}

pub(crate) fn mem_read_code_with_log_and_fill<F: Field>(
    address: MemoryAddress,
    state: &GenerationState<F>,
    row: &mut CpuColumnsView<F>,
) -> (u8, MemoryOp) {
    let (val, op) = mem_read_with_log(MemoryChannel::Code, address, state);

    let val_u8 = to_byte_checked(val);
    row.opcode_bits = to_bits_le(val_u8);

    (val_u8, op)
}

pub(crate) fn mem_read_gp_with_log_and_fill<F: Field>(
    n: usize,
    address: MemoryAddress,
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
) -> (U256, MemoryOp) {
    let (val, op) = mem_read_with_log(MemoryChannel::GeneralPurpose(n), address, state);
    let val_limbs: [u64; 4] = val.0;

    let channel = &mut row.mem_channels[n];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ONE;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    for (i, limb) in val_limbs.into_iter().enumerate() {
        channel.value[2 * i] = F::from_canonical_u32(limb as u32);
        channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
    }

    (val, op)
}

pub(crate) fn mem_write_gp_log_and_fill<F: Field>(
    n: usize,
    address: MemoryAddress,
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    val: U256,
) -> MemoryOp {
    let op = mem_write_log(MemoryChannel::GeneralPurpose(n), address, state, val);
    let val_limbs: [u64; 4] = val.0;

    let channel = &mut row.mem_channels[n];
    assert_eq!(channel.used, F::ZERO);
    channel.used = F::ONE;
    channel.is_read = F::ZERO;
    channel.addr_context = F::from_canonical_usize(address.context);
    channel.addr_segment = F::from_canonical_usize(address.segment);
    channel.addr_virtual = F::from_canonical_usize(address.virt);
    for (i, limb) in val_limbs.into_iter().enumerate() {
        channel.value[2 * i] = F::from_canonical_u32(limb as u32);
        channel.value[2 * i + 1] = F::from_canonical_u32((limb >> 32) as u32);
    }

    op
}

pub(crate) fn stack_pop_with_log_and_fill<const N: usize, F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
) -> Result<[(U256, MemoryOp); N], ProgramError> {
    if state.registers.stack_len < N {
        return Err(ProgramError::StackUnderflow);
    }

    let result = core::array::from_fn(|i| {
        let address = MemoryAddress::new(
            state.registers.context,
            Segment::Stack,
            state.registers.stack_len - 1 - i,
        );
        mem_read_gp_with_log_and_fill(i, address, state, row)
    });

    state.registers.stack_len -= N;

    Ok(result)
}

pub(crate) fn stack_push_log_and_fill<F: Field>(
    state: &mut GenerationState<F>,
    row: &mut CpuColumnsView<F>,
    val: U256,
) -> Result<MemoryOp, ProgramError> {
    if !state.registers.is_kernel && state.registers.stack_len >= MAX_USER_STACK_SIZE {
        return Err(ProgramError::StackOverflow);
    }

    let address = MemoryAddress::new(
        state.registers.context,
        Segment::Stack,
        state.registers.stack_len,
    );
    let res = mem_write_gp_log_and_fill(NUM_GP_CHANNELS - 1, address, state, row, val);

    state.registers.stack_len += 1;

    Ok(res)
}
*/
fn xor_into_sponge<F: Field>(
    state: &mut GenerationState<F>,
    sponge_state: &mut [u8; KECCAK_WIDTH_BYTES],
    block: &[u8; KECCAK_RATE_BYTES],
) {
    for i in (0..KECCAK_RATE_BYTES).step_by(32) {
        let range = i..KECCAK_RATE_BYTES.min(i + 32);
        let lhs = U256::from_little_endian(&sponge_state[range.clone()]);
        let rhs = U256::from_little_endian(&block[range]);
        state
            .traces
            .push_logic(logic::Operation::new(logic::Op::Xor, lhs, rhs));
    }
    for i in 0..KECCAK_RATE_BYTES {
        sponge_state[i] ^= block[i];
    }
}

pub(crate) fn keccak_sponge_log<F: Field>(
    state: &mut GenerationState<F>,
    // base_address: MemoryAddress,
    input: Vec<u8>,
) {
    // let clock = state.traces.clock();

    // let mut address = base_address;
    let mut input_blocks = input.chunks_exact(KECCAK_RATE_BYTES);
    let mut sponge_state = [0u8; KECCAK_WIDTH_BYTES];
    for block in input_blocks.by_ref() {
        // for &byte in block {
        //     state.traces.push_memory(MemoryOp::new(
        //         MemoryChannel::Code,
        //         clock,
        //         address,
        //         MemoryOpKind::Read,
        //         byte.into(),
        //     ));
        //     address.increment();
        // }
        xor_into_sponge(state, &mut sponge_state, block.try_into().unwrap());
        state.traces.push_keccak_bytes(sponge_state);
        keccakf_u8s(&mut sponge_state);
    }

    // for &byte in input_blocks.remainder() {
    //     state.traces.push_memory(MemoryOp::new(
    //         MemoryChannel::Code,
    //         clock,
    //         address,
    //         MemoryOpKind::Read,
    //         byte.into(),
    //     ));
    //     address.increment();
    // }
    let mut final_block = [0u8; KECCAK_RATE_BYTES];
    final_block[..input_blocks.remainder().len()].copy_from_slice(input_blocks.remainder());
    // pad10*1 rule
    if input_blocks.remainder().len() == KECCAK_RATE_BYTES - 1 {
        // Both 1s are placed in the same byte.
        final_block[input_blocks.remainder().len()] = 0b10000001;
    } else {
        final_block[input_blocks.remainder().len()] = 1;
        final_block[KECCAK_RATE_BYTES - 1] = 0b10000000;
    }
    xor_into_sponge(state, &mut sponge_state, &final_block);
    state.traces.push_keccak_bytes(sponge_state);

    state.traces.push_keccak_sponge(KeccakSpongeOp {
        // base_address: 0,//base_address,
        timestamp: 0,//timestamp: clock * NUM_CHANNELS,
        input,
    });
}

pub(crate) fn keccak_short_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
) {
    keccak_sponge_log(state, input);
}


pub(crate) fn data_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
) {
    state.traces.push_data(DataOp {
        input: input,
        child: None,
        external_child: None,
        data_type: DataType::Leaf,
        receipts_root: None,
        pi_sum: None,
        event_logs: None,
    });
}

pub(crate) fn data_leaf_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
    event_logs: &[EventParts],
    pmt_element: PatriciaMerklePathElement
) {
    let mut event_parts = vec![];
    for event in event_logs{
        let sold_token_id_offset = event.sold_token_id_index + pmt_element.clone().prefix.len();
        let value_offset = event.sold_token_volume_index + pmt_element.clone().prefix.len();
        let method_offset = event.event_selector_index + pmt_element.clone().prefix.len();
        let contract_offset = event.pool_address_index + pmt_element.clone().prefix.len();
        let contract_data: [u8; KECCAK_DIGEST_BYTES] = input[contract_offset..contract_offset + KECCAK_DIGEST_BYTES].try_into().unwrap();
        let value_data: [u8; KECCAK_DIGEST_BYTES] = input[value_offset..value_offset + KECCAK_DIGEST_BYTES].try_into().unwrap();
        let method_data: [u8; KECCAK_DIGEST_BYTES] = input[method_offset..method_offset + KECCAK_DIGEST_BYTES].try_into().unwrap();
        let sold_token_id: [u8; KECCAK_DIGEST_BYTES] = input[sold_token_id_offset..sold_token_id_offset + KECCAK_DIGEST_BYTES].try_into().unwrap();
        event_parts.push(EventLogPart{
            contract: DataItem {
                        offset: contract_offset,
                        item: contract_data,
                        offset_in_block: (contract_offset + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES,
                    },
            value:DataItem {
                        offset: value_offset,
                        item: value_data,
                        offset_in_block: (value_offset + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES,
                    },
            token_id: DataItem{
                        offset: sold_token_id_offset,
                        item: sold_token_id,
                        offset_in_block: (sold_token_id_offset + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES
                    },
            method_signature: DataItem {
                        offset: method_offset,
                        item: method_data,
                        offset_in_block: (method_offset + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES,
                    },
        })
    }
    event_parts.sort_by(|a, b| a.contract.offset.cmp(&b.contract.offset));
    state.traces.push_data(DataOp {
        input: input.clone(),
        event_logs: Some(event_parts),
        child: None,
        external_child: None,
        data_type: DataType::Leaf,
        receipts_root: None,
        pi_sum: None,
    });
}

pub(crate) fn data_node_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
    mut hash_offset: Vec<usize>,
) {
    let mut node_childs: Vec<DataItem> = vec![];
    hash_offset.sort();
    for offset in hash_offset {
        let child_hash: [u8; KECCAK_DIGEST_BYTES] = input[offset.clone()..offset.clone() + KECCAK_DIGEST_BYTES].try_into().unwrap();
        let item = DataItem {
            offset: offset.clone(),
            item: child_hash.clone(),
            offset_in_block: (offset.clone() + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES,
        };
        node_childs.push(item);
    }
    state.traces.push_data(DataOp {
        input: input.clone(),
        child: Some(node_childs),
        external_child: None,
        data_type: DataType::Node,
        receipts_root: None,
        pi_sum: None,
        event_logs: None,
    });
}

pub(crate) fn receipt_root_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
    offset: usize,
    root_in_tree: bool,
    parent_block_hash: Vec<u8>,
    is_external: bool,
) {
    let receipts_root: [u8; KECCAK_DIGEST_BYTES] = input[offset.clone()..offset.clone() + KECCAK_DIGEST_BYTES].try_into().unwrap();
    state.traces.push_data(DataOp {
        input: input.clone(),
        event_logs: None,
        child: if !is_external {
            Some(vec![
                DataItem {
                    offset: 4,
                    item: parent_block_hash[..KECCAK_DIGEST_BYTES].try_into().unwrap(),
                    offset_in_block: 4 + KECCAK_DIGEST_BYTES,
                }
            ])
        } else { None },
        external_child: if is_external {
            Some(vec![
                DataItem {
                    offset: 4,
                    item: parent_block_hash[..KECCAK_DIGEST_BYTES].try_into().unwrap(),
                    offset_in_block: 4 + KECCAK_DIGEST_BYTES,
                }
            ])
        } else { None },
        data_type: DataType::ReceiptsRoot,
        receipts_root: if root_in_tree {
            Some(DataItem {
                offset: offset.clone(),
                item: receipts_root.clone(),
                offset_in_block: (offset.clone() + KECCAK_DIGEST_BYTES) % KECCAK_RATE_BYTES,
            })
        } else { None },
        pi_sum: None,
    });
}


pub(crate) fn block_hash_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
) {
    let block_hash: [u8; KECCAK_DIGEST_BYTES] = input[..KECCAK_DIGEST_BYTES].try_into().unwrap();
    state.traces.push_data(DataOp {
        input: input.clone(),
        event_logs: None,
        child: Some(vec![DataItem {
            offset: 0,
            item: block_hash,
            offset_in_block: KECCAK_DIGEST_BYTES,
        }]),
        external_child: None,
        data_type: DataType::BlockHash,
        receipts_root: None,
        pi_sum: None,
    });
}


pub(crate) fn pi_sum_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
) {
    let pi_sum: [u8; KECCAK_DIGEST_BYTES] = input[..KECCAK_DIGEST_BYTES].try_into().unwrap();
    state.traces.push_data(DataOp {
        input: input.clone(),
        event_logs: None,
        child: None,
        external_child: None,
        data_type: DataType::TotalSum ,
        receipts_root: None,
        pi_sum: Some(DataItem {
            offset: 0,
            item: pi_sum,
            offset_in_block: KECCAK_DIGEST_BYTES,
        }),
    });
}


pub(crate) fn arithmetic_value_log<F: Field>(
    state: &mut GenerationState<F>,
    input: Vec<u8>,
) {
    let data: [u8; 32] = input.try_into().unwrap();
    state.traces.push_arithmetic(
        Operation::binary(BinaryOperator::Add, U256::from(data), U256::from(0))
    );
}

pub(crate) fn sum_log<F: Field>(
    state: &mut GenerationState<F>,
    input0: Vec<(Vec<u8>, Vec<u8>)>,
) -> Vec<u8> {
    let mut input0_256 = vec![];
    for i in 0..input0.len() {
        let (sold_volume, sold_token_id) = input0[i].clone();
        let converted_volume: [u8; 32] = sold_volume.try_into().unwrap();
        let converted_token_id: [u8; 32] = sold_token_id.try_into().unwrap();
        let token_id = U256::from(converted_token_id);
        let op = MulAdd {
            input0: U256::from(converted_volume),
            coef: if token_id == U256::zero() { U256::from(10u64.pow(12)) } else { U256::one() },
            token_id,
        };

        input0_256.push(op);
    }

    let (sum_result, mul_ops) = ChainOperator::Add.result(U256::zero(), &*input0_256);
    let arithm_operations = ChainOperator::Add.to_binary_ops(&*input0_256, &*sum_result);
    let chain_result: ChainResult = ChainResult::SumOperation { sum_result: sum_result.clone(), mul_op: mul_ops };
    for ops in arithm_operations {
        state.traces.push_arithmetic(ops);
    }
    state.traces.push_sum(chain_result);
    let mut bytes = [0; 32];
    sum_result.last().unwrap().to_big_endian(&mut bytes);
    bytes.to_vec()
}

// pub(crate) fn public_log<F:Field>(
//     state: &mut GenerationState<F>,
//     super_root: Vec<u8>,
//     sum: Vec<u8>
// ) {
//     state.traces.push_public(
//         PublicOp {
//             sum,
//             super_root
//         }
//     )
// }
