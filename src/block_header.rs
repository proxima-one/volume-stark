use ::rlp::{RlpStream};
use ethereum_types::{Bloom, H160, H256, H64, U256};
use serde::{Deserialize, Deserializer, Serialize};
use serde::de::{Error, Unexpected, Visitor};
use keccak_hash::{keccak};
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use anyhow::Result;
use http_body_util::BodyExt;
use itertools::Itertools;
use log::{error, info};
use serde_json::Value;

type Bytes = Vec<u8>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub parent_hash: H256,
    pub uncles_hash: H256,
    pub author: H160,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub hash: H256,
    pub number: ethereum_types::U64,
    pub gas_limit: U256,
    pub gas_used: U256,
    pub timestamp: U256,
    #[serde(deserialize_with = "deserialize_hex_bytes")]
    pub extra_data: Bytes,
    pub mix_hash: H256,
    pub nonce: H64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<H256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_beacon_root: Option<H256>,
}


impl Header {
    pub fn rlp_encode(&self) -> (Vec<u8>, usize) {
        let len = 15 + self.base_fee_per_gas.is_some() as usize
            + self.withdrawals_root.is_some() as usize
            + self.blob_gas_used.is_some() as usize
            + self.excess_blob_gas.is_some() as usize
            + self.parent_beacon_root.is_some() as usize;
        let mut stream = RlpStream::new_list(len);
        stream.append(&self.parent_hash);
        stream.append(&self.uncles_hash);
        stream.append(&self.author);
        stream.append(&self.state_root);
        stream.append(&self.transactions_root);
        let before_rlp_len = stream.len();
        stream.append(&self.receipts_root);
        let after_rlp_len = stream.len();
        stream.append(&self.logs_bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data);
        stream.append(&self.mix_hash);
        stream.append(&self.nonce);
        let offset_rlp_len = after_rlp_len - before_rlp_len - 32 + 1;
        let offset_receipt_root = before_rlp_len + offset_rlp_len;
        if let Some(base_fee_per_gas) = &self.base_fee_per_gas {
            stream.append(base_fee_per_gas);
        }

        if let Some(withdrawals_root) = &self.withdrawals_root {
            stream.append(withdrawals_root);
        }

        if let Some(blobGasUsed) = &self.blob_gas_used {
            stream.append(blobGasUsed);
        }

        if let Some(excessBlobGas) = &self.excess_blob_gas {
            stream.append(excessBlobGas);
        }

        if let Some(ParentBeaconRoot) = &self.parent_beacon_root {
            stream.append(ParentBeaconRoot);
        }
        let rlp = stream.out().to_vec();
        (rlp, offset_receipt_root)
    }

    pub fn hash(&self) -> H256 {
        keccak(self.rlp_encode().0)
    }
}


fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
{
    {
        deserializer.deserialize_identifier(BytesVisitor)
    }
}

struct BytesVisitor;

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a 0x-prefixed hex-encoded vector of bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: Error,
    {
        if let Some(value) = value.strip_prefix("0x") {
            let bytes = hex::decode(value).map_err(|e| Error::custom(format!("Invalid hex: {}", e)))?;
            Ok(bytes)
        } else {
            Err(Error::invalid_value(Unexpected::Str(value), &"0x prefix"))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: Error,
    {
        self.visit_str(value.as_ref())
    }
}


fn deserialize_number<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
{
    let number = u128::deserialize(deserializer)?;
    Ok(U256::from(number))
}

pub fn read_headers_from_file(file_name: &str) -> Result<Vec<Header>, anyhow::Error> {
    let file = File::open(file_name)?;
    let reader = BufReader::new(file);
    let headers: Vec<Header> = match serde_json::from_reader(reader) {
        Ok(paths) => paths,
        Err(e) => {
            error!("JSON deserialization error: {:?}", e);
            std::process::exit(1);
        }
    };
    Ok(headers)
}

pub fn read_headers_from_request(objects_arr: &Vec<Value>) -> Result<Vec<Header>, anyhow::Error> {
    let headers: Vec<Header> = objects_arr.iter().map(|json_value| serde_json::from_value(json_value.clone()).unwrap()).collect_vec();
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use anyhow::Result;
    use log::info;


    fn init_logger() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }

    #[test]
    fn test_headers() -> Result<()> {
        init_logger();
        let all_headers: Vec<Header> = read_headers_from_file("test_data/headers/block_headers_17388000-17389000.json")?;
        info!("Headers: {:?}, hash: {:?}", all_headers[0].hash, all_headers[0].hash());
        Ok(())
    }
}
