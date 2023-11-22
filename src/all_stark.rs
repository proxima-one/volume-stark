
use log::info;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;

use crate::arithmetic::arithmetic_stark;
use crate::arithmetic::arithmetic_stark::ArithmeticStark;
use crate::config::StarkConfig;
use crate::cross_table_lookup::{CrossTableLookup, TableWithColumns};
use crate::data::data_stark::{DataStark, self};
use crate::keccak::keccak_stark;
use crate::keccak::keccak_stark::KeccakStark;
use crate::keccak_sponge::keccak_sponge_stark;
use crate::keccak_sponge::keccak_sponge_stark::KeccakSpongeStark;
use crate::{bloom_stark, logic};
use crate::bloom_stark::BloomStark;
use crate::logic::LogicStark;
use crate::search_substring::search_stark;
use crate::search_substring::search_stark::SearchStark;
use crate::stark::Stark;
use crate::summation::sum_stark;
use crate::summation::sum_stark::SumStark;

#[derive(Clone)]
pub struct AllStark<F: RichField + Extendable<D>, const D: usize> {
    pub arithmetic_stark: ArithmeticStark<F, D>,
    pub keccak_stark: KeccakStark<F, D>,
    pub keccak_sponge_stark: KeccakSpongeStark<F, D>,
    pub logic_stark: LogicStark<F, D>,
    pub data_stark: DataStark<F, D>,
    pub sum_stark: SumStark<F, D>,
    pub search_stark: SearchStark<F, D>,
    pub bloom_stark: BloomStark<F, D>,
    pub cross_table_lookups: Vec<CrossTableLookup<F>>,
}


impl<F: RichField + Extendable<D>, const D: usize> Default for AllStark<F, D> {
    fn default() -> Self {
        Self {
            arithmetic_stark: ArithmeticStark::default(),
            keccak_stark: KeccakStark::default(),
            keccak_sponge_stark: KeccakSpongeStark::default(),
            logic_stark: LogicStark::default(),
            data_stark: DataStark::default(),
            sum_stark: SumStark::default(),
            search_stark: SearchStark::default(),
            bloom_stark: BloomStark::default(),
            cross_table_lookups: all_cross_table_lookups(),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> AllStark<F, D> {
    pub(crate) fn nums_permutation_zs(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        [
            self.arithmetic_stark.num_permutation_batches(config),
            self.keccak_stark.num_permutation_batches(config),
            self.keccak_sponge_stark.num_permutation_batches(config),
            self.logic_stark.num_permutation_batches(config),
            self.data_stark.num_permutation_batches(config),
            self.sum_stark.num_permutation_batches(config),
            self.search_stark.num_permutation_batches(config),
            self.bloom_stark.num_permutation_batches(config)
        ]
    }

    pub(crate) fn permutation_batch_sizes(&self) -> [usize; NUM_TABLES] {
        [
            self.arithmetic_stark.permutation_batch_size(),
            self.keccak_stark.permutation_batch_size(),
            self.keccak_sponge_stark.permutation_batch_size(),
            self.logic_stark.permutation_batch_size(),
            self.data_stark.permutation_batch_size(),
            self.sum_stark.permutation_batch_size(),
            self.search_stark.permutation_batch_size(),
            self.bloom_stark.permutation_batch_size(),
        ]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Table {
    Arithmetic = 0,
    Keccak = 1,
    KeccakSponge = 2,
    Logic = 3,
    Data = 4,
    Sum = 5,
    Search = 6,
    Bloom = 7,
}

pub(crate) const NUM_TABLES: usize = Table::Bloom as usize + 1;

impl Table {
    pub(crate) fn all() -> [Self; NUM_TABLES] {
        [
            Self::Arithmetic,
            Self::Keccak,
            Self::KeccakSponge,
            Self::Logic,
            Self::Data,
            Self::Sum,
            Self::Search,
            Self::Bloom

        ]
    }
}

pub(crate) fn all_cross_table_lookups<F: Field>() -> Vec<CrossTableLookup<F>> {
    vec![
        ctl_keccak(),
        ctl_logic(),
        ctl_data(),
        ctl_keccak_sponge(),
        ctl_acum_equals_result(),
        ctl_previous_sum_equal_op1(),
        ctl_substr_in_haystack(),
        ctl_haystack_equal_data(),
        ctl_last_blockhash_included(),
        ctl_mult_value(),
        ctl_volume_value(),
        ctl_token_id(),
        ctl_bloom()
    ]
}

fn ctl_keccak<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looking = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looking_keccak(),
        Some(keccak_sponge_stark::ctl_looking_keccak_filter()),
    );
    let keccak_looked = TableWithColumns::new(
        Table::Keccak,
        keccak_stark::ctl_data(),
        Some(keccak_stark::ctl_filter()),
    );
    CrossTableLookup::new(vec![keccak_sponge_looking], keccak_looked)
}

fn ctl_logic<F: Field>() -> CrossTableLookup<F> {
    let mut all_lookers = vec![];
    for i in 0..keccak_sponge_stark::num_logic_ctls() {
        let keccak_sponge_looking = TableWithColumns::new(
            Table::KeccakSponge,
            keccak_sponge_stark::ctl_looking_logic(i),
            Some(keccak_sponge_stark::ctl_looking_logic_filter()),
        );
        all_lookers.push(keccak_sponge_looking);
    }
    let logic_looked =
        TableWithColumns::new(Table::Logic, logic::ctl_data(), Some(logic::ctl_filter()));
    CrossTableLookup::new(all_lookers, logic_looked)
}

fn ctl_data<F: Field>() -> CrossTableLookup<F> {
    let keccak_sponge_looked = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looking_data(),
        Some(keccak_sponge_stark::ctl_looking_keccak_filter()),
    );
    let data_looking = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looked_data(),
        Some(data_stark::ctl_looked_filter()),
    );
    CrossTableLookup::new(vec![data_looking], keccak_sponge_looked)
}

fn ctl_keccak_sponge<F: Field>() -> CrossTableLookup<F> {
    let data_looking = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looking_keccak_sponge(),
        Some(data_stark::ctl_looking_keccak_sponge_filter()),
    );

    let keccak_sponge_looked = TableWithColumns::new(
        Table::KeccakSponge,
        keccak_sponge_stark::ctl_looked_data(),
        Some(keccak_sponge_stark::ctl_looked_filter()),
    );

    CrossTableLookup::new(vec![data_looking], keccak_sponge_looked)
}

fn ctl_previous_sum_equal_op1<F: Field>() -> CrossTableLookup<F> {
    let sum_looking = TableWithColumns::new(
        Table::Sum,
        sum_stark::ctl_looked_acum_sum(),
        Some(sum_stark::ctl_looking_filter_input())
    );

    let arithmetic_looked = TableWithColumns::new(
        Table::Arithmetic,
        arithmetic_stark::ctl_looked_op1(),
        Some(arithmetic_stark::ctl_looked_filter()),
    );

    CrossTableLookup::new(vec![sum_looking], arithmetic_looked)
}

fn ctl_acum_equals_result<F: Field>() -> CrossTableLookup<F> {
    let sum_looking = TableWithColumns::new(
        Table::Sum,
        sum_stark::ctl_looked_acum_sum(),
        Some(sum_stark::ctl_looking_filter_output())
    );

    let arithmetic_looked = TableWithColumns::new(
        Table::Arithmetic,
        arithmetic_stark::ctl_looked_res(),
        Some(arithmetic_stark::ctl_looked_filter()),
    );

    CrossTableLookup::new(vec![sum_looking], arithmetic_looked)
}


fn ctl_substr_in_haystack<F: Field>() -> CrossTableLookup<F> {
    let substring_looking = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looking_needle_hash(),
        Some(data_stark::ctl_looking_substr_filter()),
    );

    let substring_looked = TableWithColumns::new(
        Table::Search,
        search_stark::ctl_looked_needle(),
        Some(search_stark::ctl_looked_filter_out())
    );

    CrossTableLookup::new(vec![substring_looking], substring_looked)
}

fn ctl_haystack_equal_data<F: Field>() -> CrossTableLookup<F> {
    let substring_looking = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looking_haystack_hash(),
        Some(data_stark::ctl_looking_substr_filter())
    );

    let string_looked = TableWithColumns::new(
        Table::Search,
        search_stark::ctl_looked_haystack(),
        Some(search_stark::ctl_looking_filter_in()),
    );

    CrossTableLookup::new(vec![substring_looking], string_looked)
}


fn ctl_last_blockhash_included<F: Field>() -> CrossTableLookup<F> {
    let string_looking = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_typed_data(),
        Some(data_stark::ctl_filter_none()),
    );
    let string_looked = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_typed_data(),
        Some(data_stark::ctl_pis_filter()),
    );

    CrossTableLookup::new(vec![string_looking], string_looked)
}

fn ctl_mult_value<F: Field>() -> CrossTableLookup<F> {
    let string_looking = TableWithColumns::new(
        Table::Sum,
        sum_stark::ctl_looking_mult(),
        Some(sum_stark::ctl_filter_not_init()),
    );
    let string_looked = TableWithColumns::new(
        Table::Arithmetic,
        arithmetic_stark::ctl_looked_mult(),
        Some(arithmetic_stark::ctl_looked_filter_mult()),
    );

    CrossTableLookup::new(vec![string_looking], string_looked)
}

fn ctl_volume_value<F: Field>() -> CrossTableLookup<F> {
    let string_looking = TableWithColumns::new(
        Table::Sum,
        sum_stark::ctl_looking_value(),
        Some(sum_stark::ctl_filter_not_init()),
    );
    let string_looked = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looking_value(),
        Some(data_stark::ctl_looking_arithmetic_filter()),
    );

    CrossTableLookup::new(vec![string_looked], string_looking)
}

fn ctl_token_id<F: Field>() -> CrossTableLookup<F> {
    let string_looking = TableWithColumns::new(
        Table::Sum,
        sum_stark::ctl_looking_token_id(),
        Some(sum_stark::ctl_filter_not_init()),
    );
    let string_looked = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looking_value(),
        Some(data_stark::ctl_looking_token_filter()),
    );

    CrossTableLookup::new(vec![string_looked], string_looking)
}

fn ctl_bloom<F: Field>() -> CrossTableLookup<F> {
    let bloom_looking = TableWithColumns::new(
        Table::Bloom,
        bloom_stark::ctl_looking_topic(),
        Some(bloom_stark::ctl_not_dummy_filter()),
    );

    let address_looked = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looked_address_id(),
        Some(data_stark::ctl_address_filter()),
    );

    let topic_looked = TableWithColumns::new(
        Table::Data,
        data_stark::ctl_looked_topic_id(),
        Some(data_stark::ctl_method_filter()),
    );

    CrossTableLookup::new(vec![topic_looked, address_looked], bloom_looking)
}


