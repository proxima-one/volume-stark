use ethereum_types::U256;
use plonky2::field::types::Field;

use crate::arithmetic::{Operation, BinaryOperator};
use crate::block_header::Receipt;
use crate::data::columns::KECCAK_DIGEST_BYTES;
use crate::data::data_stark::{DataOp, DataType, DataItem, EventLogPart};
use crate::generation::GenerationState;
use crate::keccak_sponge::columns::{KECCAK_RATE_BYTES, KECCAK_WIDTH_BYTES};
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
use crate::keccak_sponge::keccak_util::keccakf_u8s;
use crate::logic;
use crate::patricia_merkle_trie::{EventParts, PatriciaMerklePathElement};
use crate::summation::{ChainOperator, ChainResult, MulAdd};

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
    input: Vec<u8>,
) {
    let mut input_blocks = input.chunks_exact(KECCAK_RATE_BYTES);
    let mut sponge_state = [0u8; KECCAK_WIDTH_BYTES];
    for block in input_blocks.by_ref() {
        xor_into_sponge(state, &mut sponge_state, block.try_into().unwrap());
        state.traces.push_keccak_bytes(sponge_state);
        keccakf_u8s(&mut sponge_state);
    }

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
        timestamp: 0,
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
        let header_prefix = pmt_element.clone().prefix.len();
        let sold_token_id_offset = event.sold_token_id_index + header_prefix;
        let value_offset = event.sold_token_volume_index + header_prefix;
        let method_offset = event.event_selector_index + header_prefix;
        let contract_offset = event.pool_address_index + header_prefix;
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
            event_rlp_index: event.event_rlp_index + header_prefix,
            bought_token_volume_index:  event.bought_token_volume_index + KECCAK_DIGEST_BYTES + header_prefix,
        });
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

