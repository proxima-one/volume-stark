use std::mem::size_of;

use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
// use crate::cpu::columns::CpuColumnsView;
use crate::data::columns::DATA_COL_MAP;
use crate::data::data_stark::DataOp;
use crate::keccak_sponge::columns::KECCAK_WIDTH_BYTES;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeOp;
// use crate::public::PublicOp;
// use crate::public::PublicOp;
use crate::util::trace_rows_to_poly_values;
// use crate::witness::memory::MemoryOp;
use crate::{arithmetic, keccak, logic};
use crate::search_substring::search_stark::columns::HAYSTACK_SIZE;
use crate::search_substring::search_stark::SearchOp;
use crate::summation::{ChainResult};

#[derive(Clone, Copy, Debug)]
pub struct TraceCheckpoint {
    pub(self) arithmetic_len: usize,
    // pub(self) cpu_len: usize,
    pub(self) keccak_len: usize,
    pub(self) keccak_sponge_len: usize,
    pub(self) logic_len: usize,
    // pub(self) memory_len: usize,
    pub(self) data_len: usize,
    pub(self) sum_len: usize,
    pub(self) search_len: usize,
}

#[derive(Debug)]
pub(crate) struct Traces<T: Copy> {
    pub(crate) arithmetic_ops: Vec<arithmetic::Operation>,
    // pub(crate) cpu: Vec<CpuColumnsView<T>>,
    pub(crate) logic_ops: Vec<logic::Operation>,
    // pub(crate) memory_ops: Vec<MemoryOp>,
    pub(crate) keccak_inputs: Vec<[u64; keccak::keccak_stark::NUM_INPUTS]>,
    pub(crate) keccak_sponge_ops: Vec<KeccakSpongeOp>,
    pub(crate) data_ops: Vec<DataOp>,
    pub(crate) sum_ops: Vec<ChainResult>,
    pub(crate) search_ops: Vec<SearchOp>,
}

impl<T: Copy> Traces<T> {
    pub fn new() -> Self {
        Traces {
            arithmetic_ops: vec![],
            // cpu: vec![],
            logic_ops: vec![],
            // memory_ops: vec![],
            keccak_inputs: vec![],
            keccak_sponge_ops: vec![],
            data_ops: vec![],
            sum_ops: vec![],
            search_ops: vec![],
        }
    }

    pub fn checkpoint(&self) -> TraceCheckpoint {
        TraceCheckpoint {
            arithmetic_len: self.arithmetic_ops.len(),
            // cpu_len: self.cpu.len(),
            keccak_len: self.keccak_inputs.len(),
            keccak_sponge_len: self.keccak_sponge_ops.len(),
            logic_len: self.logic_ops.len(),
            // memory_len: self.memory_ops.len(),
            data_len: self.data_ops.len(),
            sum_len: self.sum_ops.len(),
            search_len: self.search_ops.len(),
        }
    }

    pub fn rollback(&mut self, checkpoint: TraceCheckpoint) {
        self.arithmetic_ops.truncate(checkpoint.arithmetic_len);
        // self.cpu.truncate(checkpoint.cpu_len);
        self.keccak_inputs.truncate(checkpoint.keccak_len);
        self.keccak_sponge_ops
            .truncate(checkpoint.keccak_sponge_len);
        self.logic_ops.truncate(checkpoint.logic_len);
        // self.memory_ops.truncate(checkpoint.memory_len);
        self.data_ops.truncate(checkpoint.data_len);
        self.sum_ops.truncate(checkpoint.data_len);
        self.search_ops.truncate(checkpoint.search_len);
    }

    // pub fn mem_ops_since(&self, checkpoint: TraceCheckpoint) -> &[MemoryOp] {
    //     &self.memory_ops[checkpoint.memory_len..]
    // }

    // pub fn push_cpu(&mut self, val: CpuColumnsView<T>) {
    //     self.cpu.push(val);
    // }

    pub fn push_logic(&mut self, op: logic::Operation) {
        self.logic_ops.push(op);
    }

    pub fn push_arithmetic(&mut self, op: arithmetic::Operation) {
        self.arithmetic_ops.push(op);
    }

    pub fn push_sum(&mut self, op_result: ChainResult) {
        self.sum_ops.push(op_result);
    }

    // pub fn push_search(&mut self, op: SearchOp) {
    //     self.search_ops.push(op);
    // }


    // pub fn push_public(&mut self, op: PublicOp) {
    //     self.public_ops.push(op);
    // }

    // pub fn push_memory(&mut self, op: MemoryOp) {
    //     self.memory_ops.push(op);
    // }

    pub fn push_keccak(&mut self, input: [u64; keccak::keccak_stark::NUM_INPUTS]) {
        self.keccak_inputs.push(input);
    }

    pub fn push_keccak_bytes(&mut self, input: [u8; KECCAK_WIDTH_BYTES]) {
        let chunks = input
            .chunks(size_of::<u64>())
            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
            .collect_vec()
            .try_into()
            .unwrap();
        self.push_keccak(chunks);
    }

    pub fn push_keccak_sponge(&mut self, op: KeccakSpongeOp) {
        self.keccak_sponge_ops.push(op);
    }

    pub fn push_data(&mut self, op: DataOp) {
        self.data_ops.push(op);
    }


    // pub fn clock(&self) -> usize {
    //     self.cpu.len()
    // }

    pub fn into_tables<const D: usize>(
        self,
        all_stark: &AllStark<T, D>,
        config: &StarkConfig,
        timing: &mut TimingTree,
    ) -> [Vec<PolynomialValues<T>>; NUM_TABLES]
    where
        T: RichField + Extendable<D>,
    {
        let cap_elements = config.fri_config.num_cap_elements();
        let Traces {
            arithmetic_ops,
            // cpu:_,
            logic_ops,
            // memory_ops:_,
            keccak_inputs,
            keccak_sponge_ops,
            data_ops,
            sum_ops,
            search_ops,
            // public_ops,
        } = self;

        let arithmetic_trace = timed!(
            timing,
            "generate arithmetic trace",
            all_stark.arithmetic_stark.generate_trace(arithmetic_ops)
        );
        println!("Arithmetic trace: {}", arithmetic_trace[0].len());
        let keccak_trace = timed!(
            timing,
            "generate Keccak trace",
            all_stark
                .keccak_stark
                .generate_trace(keccak_inputs, cap_elements, timing)
        );
        println!("Permutation trace: {}", keccak_trace[0].len());
        let keccak_sponge_trace = timed!(
            timing,
            "generate Keccak sponge trace",
            all_stark
                .keccak_sponge_stark
                .generate_trace(keccak_sponge_ops, cap_elements, timing)
        );
        println!("Sponge trace: {}", keccak_sponge_trace[0].len());
        let logic_trace = timed!(
            timing,
            "generate logic trace",
            all_stark
                .logic_stark
                .generate_trace(logic_ops, cap_elements, timing)
        );
        println!("Logic trace: {}", logic_trace[0].len());
        let (data_trace, search_ops) = timed!(
            timing,
            "generate data trace",
            all_stark
                .data_stark
                .generate_trace(data_ops,  timing)
        );
        println!("Data trace: {}", data_trace[0].len());

        let sum_trace = timed!(
            timing,
            "generate sum trace",
            all_stark.sum_stark.generate_trace(sum_ops)
        );
        println!("Sum trace: {}", sum_trace[0].len());
        let search_trace = timed!(
            timing,
            "generate sum trace",
            all_stark
                .search_stark
                .generate_trace(search_ops, timing)
        );
        println!("Search trace: {}", search_trace[0].len());
        // let public_trace = timed!(
        //     timing,
        //     "generate sum trace",
        //     all_stark
        //         .public_stark
        //         .generate_trace(public_ops, cap_elements, timing)
        // );
        // println!("Public trace: {}", public_trace[0].len());

        // let cols = DATA_COL_MAP;
        // println!("{:?}", data_trace[cols.is_root_data].values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());
        // for v in &data_trace[41..177] {
        //     println!("{:?}", v.values.iter().take(4).map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());
        // }
        // println!("{:?}", concat_trace[0].values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());
        // println!("{:?}", concat_trace[1].values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());

        // println!("{:?}", data_trace[cols.is_full_input_block].values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());

        // for v in &data_trace[6 + 32..6 + 32 + 136] {
        //     println!("{:?}", v.values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());
        // }
        // println!("----");
        // for v in &keccak_sponge_trace[192..192+136] {
        //     println!("{:?}", v.values.iter().map(|x| T::to_canonical_u64(x)).collect::<Vec<_>>());
        // }
        [
            arithmetic_trace,
            keccak_trace,
            keccak_sponge_trace,
            logic_trace,
            data_trace,
            sum_trace,
            search_trace,
            // public_trace
        ]
    }
}

impl<T: Copy> Default for Traces<T> {
    fn default() -> Self {
        Self::new()
    }
}
