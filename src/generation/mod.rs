use std::collections::HashMap;
use eth_trie_utils::partial_trie::{HashedPartialTrie, PartialTrie};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use itertools::Itertools;
use keccak_hash::{keccak};
use log::info;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::{Error, Visitor};

extern crate alloc;


use crate::all_stark::{AllStark, NUM_TABLES};
use crate::block_header::Header;
use crate::config::StarkConfig;

use crate::patricia_merkle_trie::{NodeType, PatriciaMerklePath, PatriciaTree, TreeNode};
use crate::proof::{
    PublicValues,
};


use crate::witness::traces::Traces;
use crate::witness::util::{data_leaf_log, keccak_short_log, data_node_log, sum_log, receipt_root_log, block_hash_log, pi_sum_log};


/// Inputs needed for trace generation.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {
    pub signed_txns: Vec<Vec<u8>>,
    pub tries: TrieInputs,
    /// Expected trie roots after the transactions are executed.
    // pub trie_roots_after: TrieRoots,

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    // pub block_metadata: BlockMetadata,

    /// A list of known addresses in the input state trie (which itself doesn't hold addresses,
    /// only state keys). This is only useful for debugging, so that we can return addresses in the
    /// post-state rather than state keys. (See `GenerationOutputs`, and in particular
    /// `AddressOrStateKey`.) If the caller is not interested in the post-state, this can be left
    /// empty.
    pub addresses: Vec<Address>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TrieInputs {
    /// A partial version of the state trie prior to these transactions. It should include all nodes
    /// that will be accessed by these transactions.
    pub state_trie: HashedPartialTrie,

    /// A partial version of the transaction trie prior to these transactions. It should include all
    /// nodes that will be accessed by these transactions.
    pub transactions_trie: HashedPartialTrie,

    /// A partial version of the receipt trie prior to these transactions. It should include all nodes
    /// that will be accessed by these transactions.
    pub receipts_trie: HashedPartialTrie,

    /// A partial version of each storage trie prior to these transactions. It should include all
    /// storage tries, and nodes therein, that will be accessed by these transactions.
    pub storage_tries: Vec<(H256, HashedPartialTrie)>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct PatriciaInputs {
    pub pmt: Vec<PatriciaTree>,
    pub starting_blockhash: H256,
    pub blockheaders: Vec<Header>,
}

#[derive(Debug)]
pub(crate) struct GenerationState<F: Field> {
    pub(crate) traces: Traces<F>,
}


/*
fn apply_metadata_and_tries_memops<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
    inputs: &GenerationInputs,
) {
    let metadata = &inputs.block_metadata;
    let tries = &inputs.tries;
    let trie_roots_after = &inputs.trie_roots_after;
    let fields = [
        (
            GlobalMetadata::BlockBeneficiary,
            U256::from_big_endian(&metadata.block_beneficiary.0),
        ),
        (GlobalMetadata::BlockTimestamp, metadata.block_timestamp),
        (GlobalMetadata::BlockNumber, metadata.block_number),
        (GlobalMetadata::BlockDifficulty, metadata.block_difficulty),
        (GlobalMetadata::BlockGasLimit, metadata.block_gaslimit),
        (GlobalMetadata::BlockChainId, metadata.block_chain_id),
        (GlobalMetadata::BlockBaseFee, metadata.block_base_fee),
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            h2u(tries.state_trie.hash()),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestBefore,
            h2u(tries.transactions_trie.hash()),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestBefore,
            h2u(tries.receipts_trie.hash()),
        ),
        (
            GlobalMetadata::StateTrieRootDigestAfter,
            h2u(trie_roots_after.state_root),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestAfter,
            h2u(trie_roots_after.transactions_root),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestAfter,
            h2u(trie_roots_after.receipts_root),
        ),
    ];

    let channel = MemoryChannel::GeneralPurpose(0);
    let ops = fields.map(|(field, val)| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::GlobalMetadata, field as usize),
            state,
            val,
        )
    });

    state.memory.apply_ops(&ops);
    state.traces.memory_ops.extend(ops);
}
*/
fn recursive_log<F: RichField + Extendable<D>, const D: usize>(node: &TreeNode, values: &mut Vec<(Vec<u8>, Vec<u8>)>,
                                                               state: &mut GenerationState<F>, roots: &mut Vec<H256>) {
    for child in &node.children {
        recursive_log(child, values, state, roots);
    }
    proper_log_node(node, values, state, roots);
}

fn proper_log_node<F: RichField + Extendable<D>, const D: usize>(node: &TreeNode, values: &mut Vec<(Vec<u8>, Vec<u8>)>, state: &mut GenerationState<F>, roots: &mut Vec<H256>) {
    if node.node_type == NodeType::LEAF {
        let event_logs = node.event_parts.clone().unwrap();
        for event_logs in &event_logs {
            let sold_token_id = event_logs.clone().sold_token_id;
            values.push((event_logs.sold_token_volume.clone(), sold_token_id));
        }
        keccak_short_log(state, node.full_data.clone());
        data_leaf_log(state, node.full_data.clone(), &event_logs, node.value.clone().unwrap());
    } else if node.node_type == NodeType::NODE {
        keccak_short_log(state, node.full_data.clone());
        data_node_log(state, node.full_data.clone(), node.hash_offset.clone());
    } else if node.node_type == NodeType::ROOT {
        keccak_short_log(state, node.full_data.clone());
        data_node_log(state, node.full_data.clone(), node.hash_offset.clone());
        roots.push(node.hash.clone());
    }
}

pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    patricia_inputs: PatriciaInputs,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> anyhow::Result<(
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
)> {
    //let mut state = GenerationState::<F>::new(inputs.clone(), &KERNEL.code);
    let mut state = GenerationState { traces: Traces::default() };

    // apply_metadata_and_tries_memops(&mut state, &inputs);

    // generate_bootstrap_kernel::<F>(&mut state);

    // timed!(timing, "simulate CPU", simulate_cpu(&mut state)?);

    // assert!(
    //     state.mpt_prover_inputs.is_empty(),
    //     "All MPT data should have been consumed"
    // );

    let mut roots = vec![];
    let mut values = vec![];
    for patricia_tree in &patricia_inputs.pmt {
        recursive_log(&patricia_tree.root.clone().unwrap(), &mut values, &mut state, &mut roots);
    }

    let mut is_first = true;
    for header in patricia_inputs.blockheaders.iter() {
        let (header_rlp, receipts_root_offset) = header.rlp_encode();
        let mut is_receipts_root_in_tree = false;
        for root in roots.clone() {
            if &header_rlp[receipts_root_offset..receipts_root_offset + 32] == root.as_bytes() {
                is_receipts_root_in_tree = true;
                break;
            }
        }
        receipt_root_log(&mut state, header_rlp.clone(), receipts_root_offset.clone(), is_receipts_root_in_tree, header.parent_hash.clone().as_bytes().to_vec(), is_first);
        keccak_short_log(&mut state, header_rlp.clone());
        is_first = false;
    }
    let block_hash = patricia_inputs.blockheaders.last().unwrap().hash.clone().as_bytes().to_vec();
    block_hash_log(&mut state, block_hash);
    let total_res = sum_log(&mut state, values.clone());

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.checkpoint()
    );

    // let outputs = get_outputs(&mut state);

    // let read_metadata = |field| state.memory.read_global_metadata(field);
    // let trie_roots_before = TrieRoots {
    //     state_root: H256::from_uint(&read_metadata(StateTrieRootDigestBefore)),
    //     transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestBefore)),
    //     receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestBefore)),
    // };
    // let trie_roots_after = TrieRoots {
    //     state_root: H256::from_uint(&read_metadata(StateTrieRootDigestAfter)),
    //     transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestAfter)),
    //     receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestAfter)),
    // };

    // let public_values = PublicValues {
    //     trie_roots_before,
    //     trie_roots_after,
    //     block_metadata: inputs.block_metadata,
    // };
    let mut last_block_hash = H256::default();

    if let Some(header) = patricia_inputs.blockheaders.last() {
        last_block_hash = header.hash();
    }
    pi_sum_log(&mut state, total_res.clone());

    let public_values = PublicValues {
        starting_blockhash: patricia_inputs.starting_blockhash,
        ending_blockhash: last_block_hash,
        total_sum: U256::from_big_endian(total_res.as_slice()),
    };

    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(all_stark, config, timing)
    );
    Ok((tables, public_values))
}



#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::marker::PhantomData;
    use ethereum_types::{Bloom, H160, H256, H64, U256};
    use keccak;
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
    use plonky2::util::timing::TimingTree;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    //use patricia_merkle_trie::patricia_merkle_trie::{PatriciaMerklePath, read_paths_from_file};
    use crate::all_stark::AllStark;
    use crate::config::StarkConfig;
    use crate::fixed_recursive_verifier::AllRecursiveCircuits;
    use crate::generation::{GenerationInputs, TrieInputs};
    use crate::patricia_merkle_trie::{convert_to_tree, read_paths_from_file};
    use crate::stark::Stark;
    use anyhow::Result;
    use crate::block_header::read_headers_from_file;

    extern crate rlp;

    use crate::prover::prove;
    use crate::verifier::verify_proof;


    type F = GoldilocksField;

    const D: usize = 2;

    type C = PoseidonGoldilocksConfig;


    fn init_logger() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }


    #[test]
    fn test_regular_proof() -> Result<()> {
        init_logger();
        let all_paths: Vec<PatriciaMerklePath> = read_paths_from_file("test_data/paths/paths_12901400-12901596.json")?;
        let block_headers: Vec<Header> = read_headers_from_file("test_data/headers/block_headers_12901400-12901596.json")?;
        let tries = convert_to_tree(&all_paths)?;
        let patricia_inputs: PatriciaInputs = PatriciaInputs {
            pmt: tries,
            starting_blockhash: block_headers[0].parent_hash.clone(),
            blockheaders: block_headers,
        };
        let inputs: GenerationInputs = Default::default();
        let config = StarkConfig::standard_fast_config();
        let all_stark = AllStark::<F, D>::default();
        let mut timing = TimingTree::new("generate proof", log::Level::Error);
        let proof = prove::<F, C, D>(&all_stark, &config, inputs.clone(), patricia_inputs.clone(), &mut timing)?;
        timing.print();
        info!("Degree bits: {:?}", proof.degree_bits(&config));
        verify_proof(&all_stark, proof.clone(), &config)?;
        Ok(())
    }


    #[test]
    fn test_recursive_proof() -> Result<()> {
        init_logger();
        let all_paths_1: Vec<PatriciaMerklePath> = read_paths_from_file("test_data/paths/paths_12901300-12901399.json")?;
        let all_paths_2: Vec<PatriciaMerklePath> = read_paths_from_file("test_data/paths/paths_12901400-12901596.json")?;
        let block_headers_1: Vec<Header> = read_headers_from_file("test_data/headers/block_headers_12901300-12901399.json")?;
        let block_headers_2: Vec<Header> = read_headers_from_file("test_data/headers/block_headers_12901400-12901596.json")?;
        let tries_1 = convert_to_tree(&all_paths_1)?;
        let tries_2 = convert_to_tree(&all_paths_2)?;
        let patricia_inputs_1: PatriciaInputs = PatriciaInputs {
            pmt: tries_1,
            starting_blockhash: block_headers_1[0].parent_hash.clone(),
            blockheaders: block_headers_1,
        };
        let mut patricia_inputs_2: PatriciaInputs = PatriciaInputs {
            pmt: tries_2,
            starting_blockhash: block_headers_2[0].parent_hash.clone(),
            blockheaders: block_headers_2,
        };
        let inputs: GenerationInputs = Default::default();
        let config = StarkConfig::standard_fast_config();
        let all_stark = AllStark::<F, D>::default();
        let degree_bit_ranges_high = [12usize, 16, 12, 14, 15, 12, 16, 5];
        let degree_bit_ranges_low = [8usize, 9, 5, 7, 5, 7, 10, 3];
        let degree_bit_ranges = degree_bit_ranges_low.iter().zip(degree_bit_ranges_high.iter()).map(|(x, y)| *x..*y).collect::<Vec<_>>().try_into().unwrap();
        println!("{:?}", degree_bit_ranges);
        let recursive_circuit: AllRecursiveCircuits<GoldilocksField, C, D> = AllRecursiveCircuits::new(
            &all_stark,
            &degree_bit_ranges,
            &config,
        );
        let mut timing = TimingTree::new("generate recursive first proof", log::Level::Info);
        let root_proof_1 = recursive_circuit.prove_root(
            &all_stark,
            &config,
            inputs.clone(),
            patricia_inputs_1,
            &mut timing,
        ).unwrap();
        timing.print();
        let mut timing = TimingTree::new("generate recursive  second proof", log::Level::Info);
        let public_inputs_1 = root_proof_1.1;
        patricia_inputs_2.starting_blockhash = public_inputs_1.ending_blockhash;
        let root_proof_2 = recursive_circuit.prove_root(
            &all_stark,
            &config,
            inputs.clone(),
            patricia_inputs_2,
            &mut timing,
        ).unwrap();
        timing.print();
        let mut timing = TimingTree::new("prove aggregation", log::Level::Info);
        let public_inputs_2 = root_proof_2.1;
        let total_sum = public_inputs_1.total_sum + public_inputs_2.total_sum;
        let agg_proof = recursive_circuit.prove_aggregation(false, &root_proof_1.0, false, &root_proof_2.0, PublicValues {
            total_sum,
            starting_blockhash: public_inputs_1.starting_blockhash,
            ending_blockhash: public_inputs_2.ending_blockhash,
        }).unwrap();
        timing.print();
        let actual_proof = agg_proof.0;

        println!("Size: {:?}", actual_proof.to_bytes().len());
//        recursive_circuit.verify_root(actual_proof.clone())?;
        let mut timing = TimingTree::new("verify aggregation", log::Level::Error);
        recursive_circuit.verify_aggregation(&actual_proof)?;
        timing.print();
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer {
            _phantom: PhantomData::<C>,
        };
        let circuit_bytes = recursive_circuit.root.circuit.to_bytes(&gate_serializer, &generator_serializer).map_err(|_| anyhow::Error::msg("CircuitData serialization failed."))?;
        let proof_bytes = actual_proof.to_bytes();

        let mut circuit_file = File::create("root_circuit.bin")?;
        circuit_file.write_all(&circuit_bytes)?;

        let mut proof_file = File::create("root_proof.bin")?;
        proof_file.write_all(&proof_bytes)?;

        Ok(())
    }
}