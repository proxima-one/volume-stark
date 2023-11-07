use std::borrow::{Borrow, BorrowMut};
use std::mem::{size_of, transmute};
use std::ops::Range;
use crate::util::{indices_arr, transmute_no_compile_time_size_checks};

pub(crate) const KECCAK_RATE_BYTES: usize = 136;
pub(crate) const KECCAK_DIGEST_BYTES: usize = 32;

#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub(crate) struct DataColumnsView<T: Copy> {
    /// 1 if this row represents a full input block, i.e. one in which each byte is an input byte,
    /// not a padding byte; 0 otherwise.
    pub is_full_input_block: T,

    /// The length of the original input, in bytes.
    pub len: T,

    /// The number of input bytes that have already been absorbed prior to this block.
    pub already_absorbed_bytes: T,

    pub last_block: T,

    pub is_leaf: T,

    pub is_node: T,

    pub is_shadow: T,

    pub is_block_hash: T,

    pub is_receipts_root: T,

    pub prefix_bytes: [T; KECCAK_DIGEST_BYTES],

    /// The block being absorbed, which may contain input bytes and/or padding bytes.
    pub block_bytes: [T; KECCAK_RATE_BYTES],

    pub contract_address_found: T,

    pub method_signature_found: T,

    pub transfer_value_found: T,

    pub child_hash_found: T,

    pub external_child_hash_found: T,

    pub receipts_root_found: T,

    pub sold_token_id_found: T,

    pub total_sum: T,

    pub offset_block: T,

    pub shift_num: T,

    pub zero_shift_num: T,

    pub id: T,

    pub calculation_id: T,

    pub offset_object: T,

    pub typed_data: [T; KECCAK_DIGEST_BYTES],

    pub range_counter: T,

    pub rc_cols : [T; 2 * KECCAK_RATE_BYTES],

    pub offset_diff: T,

    pub range_counter_offset_diff: T,

    pub rc_cols_offset_diff: [T; 2]
}



// `u8` is guaranteed to have a `size_of` of 1.
pub const NUM_DATA_COLUMNS: usize = size_of::<DataColumnsView<u8>>();
pub const START_BYTES_COLS: usize = 41;
pub const TRANSFER_VALUE_FOUND: usize = 179;
pub const CONTRACT_ADDRESS_FOUND: usize = 177;
pub const METHOD_SIGNATURE_FOUND: usize = 178;
pub const SOLD_TOKEN_ID_FOUND: usize = 183;

pub const RANGE_COUNTER: usize = 223;
pub const START_OFFSET_DIFF: usize = 496;
pub const RANGE_COUNTER_OFFSET_DIFF: usize = 497;

pub const BLOCK_BYTES: Range<usize> = START_BYTES_COLS..START_BYTES_COLS + KECCAK_RATE_BYTES;
pub const RC_COLS: Range<usize> = RANGE_COUNTER + 1..RANGE_COUNTER + 1 + 2 * KECCAK_RATE_BYTES;
pub const RC_COLS_OFFSET_DIFF: Range<usize> = RANGE_COUNTER_OFFSET_DIFF + 1 .. RANGE_COUNTER + 1 + 2;


impl<T: Copy> From<[T; NUM_DATA_COLUMNS]> for DataColumnsView<T> {
    fn from(value: [T; NUM_DATA_COLUMNS]) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> From<DataColumnsView<T>> for [T; NUM_DATA_COLUMNS] {
    fn from(value: DataColumnsView<T>) -> Self {
        unsafe { transmute_no_compile_time_size_checks(value) }
    }
}

impl<T: Copy> Borrow<DataColumnsView<T>> for [T; NUM_DATA_COLUMNS] {
    fn borrow(&self) -> &DataColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<DataColumnsView<T>> for [T; NUM_DATA_COLUMNS] {
    fn borrow_mut(&mut self) -> &mut DataColumnsView<T> {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> Borrow<[T; NUM_DATA_COLUMNS]> for DataColumnsView<T> {
    fn borrow(&self) -> &[T; NUM_DATA_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy> BorrowMut<[T; NUM_DATA_COLUMNS]> for DataColumnsView<T> {
    fn borrow_mut(&mut self) -> &mut [T; NUM_DATA_COLUMNS] {
        unsafe { transmute(self) }
    }
}

impl<T: Copy + Default> Default for DataColumnsView<T> {
    fn default() -> Self {
        [T::default(); NUM_DATA_COLUMNS].into()
    }
}

const fn make_col_map() -> DataColumnsView<usize> {
    let indices_arr = indices_arr::<NUM_DATA_COLUMNS>();
    unsafe {
        transmute::<[usize; NUM_DATA_COLUMNS], DataColumnsView<usize>>(indices_arr)
    }
}

pub(crate) const DATA_COL_MAP: DataColumnsView<usize> = make_col_map();



