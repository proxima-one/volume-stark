use std::{
    fs::File,
    io::{BufReader, BufWriter},
};
use std::collections::{HashMap, HashSet};
use anyhow::Result;
use bytes::Buf;
use bytes::buf::Reader;
use keccak_hash::{H256, keccak};
use log::{error, info};
use plonky2::{
    hash::hash_types::RichField,
    plonk::{
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};

use plonky2::plonk::config::Hasher;
use rand::{self, Rng};
use serde_json::Value;

pub fn str_to_u8_array(str: &str) -> Result<Vec<u8>> {
    let str: Vec<char> = str.chars().collect();
    let mut number: Vec<char> = vec![];
    let mut vec: Vec<u8> = vec![];
    for i in str.iter() {
        if i.is_numeric() {
            number.push(*i);
        } else if !number.is_empty() {
            vec.push(String::from_iter(number.clone()).parse::<u8>()?);
            number.clear();
        }
    }
    if !number.is_empty() {
        vec.push(String::from_iter(number.clone()).parse::<u8>()?);
        number.clear();
    }
    Ok(vec)
}


#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct PatriciaMerklePathStr {
    pub merkle_path: Vec<PatriciaMerklePathElementStr>,
    pub rlp_recipt: String,
    pub hash_root: String,
    pub event_parts: EventPartsStr,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct EventPartsStr {
    pub event_rlp: String,
    pub pool_address: String,
    pub event_selector: String,
    pub topic_value1: String,
    pub data: String,
    pub sold_token_id: String,
    pub sold_token_volume: String,
    pub bought_token_id: String,
    pub bought_token_volume: String,
    pub event_rlp_length: usize,
    pub pool_address_length: usize,
    pub event_selector_length: usize,
    pub topic_value1_length: usize,
    pub data_length: usize,
    pub sold_token_id_length: usize,
    pub sold_token_volume_length: usize,
    pub bought_token_id_length: usize,
    pub bought_token_volume_length: usize,
    pub event_rlp_index: usize,
    pub pool_address_index: usize,
    pub event_selector_index: usize,
    pub topic_value1_index: usize,
    pub data_index: usize,
    pub sold_token_id_index: usize,
    pub sold_token_volume_index: usize,
    pub bought_token_id_index: usize,
    pub bought_token_volume_index: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct PatriciaMerklePathElementStr {
    pub prefix: String,
    pub postfix: String,
    pub prefix_length: usize,
    pub postfix_length: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, Hash, PartialEq)]
#[serde(bound = "")]
pub struct PatriciaMerklePathElement {
    pub prefix: Vec<u8>,
    pub postfix: Vec<u8>,
    pub prefix_length: usize,
    pub postfix_length: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(bound = "")]
pub struct EventParts {
    pub pool_address: Vec<u8>,
    pub event_selector: Vec<u8>,
    pub sold_token_volume: Vec<u8>,
    pub pool_address_index: usize,
    pub event_rlp_index: usize,
    pub event_selector_index: usize,
    pub sold_token_volume_index: usize,
    pub sold_token_id: Vec<u8>,
    pub sold_token_id_index: usize,
    pub bought_token_volume_index: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "")]
pub struct PatriciaMerklePath {
    pub merkle_path: Vec<PatriciaMerklePathElement>,
    pub rlp_recipt: Vec<u8>,
    pub hash_root: Vec<u8>,
    pub event_parts: EventParts,
}

impl PatriciaMerklePath {
    pub fn new_from_file(file_name: &str) -> Result<Self> {
        Ok(Self::read_path_from_file(file_name)?)
    }
    pub fn generate_random_path(trie_heigth: usize, range: usize) -> Self {
        let mut merkle_path: Vec<PatriciaMerklePathElement> = vec![];
        let mut rng = rand::thread_rng();
        for _ in 0..trie_heigth {
            let prefix_length = rng.gen_range(0..range);
            let postfix_length = rng.gen_range(0..range);
            merkle_path.push(PatriciaMerklePathElement {
                prefix: (0..prefix_length)
                    .map(|_| rand::random())
                    .collect::<Vec<u8>>(),
                postfix: (0..postfix_length)
                    .map(|_| rand::random())
                    .collect::<Vec<u8>>(),
                prefix_length,
                postfix_length,
            });
        }
        let rlp_recipt = (0..rng.gen_range(0..range))
            .map(|_| rand::random())
            .collect::<Vec<u8>>();
        let hash_root = find_root(&merkle_path, &rlp_recipt);
        let dummy = rlp_recipt[..32].to_vec();
        Self {
            merkle_path,
            rlp_recipt,
            hash_root,
            event_parts: EventParts {
                pool_address: dummy.clone(),
                event_selector: dummy.clone(),
                sold_token_volume: dummy.clone(),
                pool_address_index: 0,
                event_rlp_index: 0,
                event_selector_index: 0,
                sold_token_volume_index: 0,
                sold_token_id: vec![],
                sold_token_id_index: 0,
                bought_token_volume_index: 0,
            },
        }
    }
    pub fn verify_hash_path(&self) -> Vec<u8> {
        let mut hash = self.rlp_recipt.to_vec();
        for i in 0..self.merkle_path.len() {
            hash = keccak(
                [
                    self.merkle_path[i].prefix.clone(),
                    hash,
                    self.merkle_path[i].postfix.clone(),
                ]
                    .concat(),
            )
                .0
                .to_vec();
        }
        assert_eq!(hash, self.hash_root);
        hash
    }
    pub fn write_path_to_file(&self, file_name: &str) -> Result<(), std::io::Error> {
        let file = File::create(file_name)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &self)?;
        Ok(())
    }
    fn read_path_from_file(file_name: &str) -> Result<Self> {
        let file = File::open(file_name)?;
        let reader = BufReader::new(file);
        let path_str: PatriciaMerklePathStr = serde_json::from_reader(reader)?;
        let mut merkle_path: Vec<PatriciaMerklePathElement> = vec![];
        for i in path_str.merkle_path.iter() {
            merkle_path.push(PatriciaMerklePathElement {
                prefix: str_to_u8_array(&i.prefix)?,
                postfix: str_to_u8_array(&i.postfix)?,
                prefix_length: i.prefix_length,
                postfix_length: i.postfix_length,
            });
        }
        let path = PatriciaMerklePath {
            merkle_path,
            rlp_recipt: str_to_u8_array(&path_str.rlp_recipt)?,
            hash_root: str_to_u8_array(&path_str.hash_root)?,
            event_parts: EventParts {
                pool_address: str_to_u8_array(&path_str.event_parts.pool_address)?,
                event_selector: str_to_u8_array(&path_str.event_parts.event_selector)?,
                sold_token_volume: str_to_u8_array(&path_str.event_parts.sold_token_volume)?,
                pool_address_index: path_str.event_parts.pool_address_index,
                event_rlp_index: path_str.event_parts.event_rlp_index,
                event_selector_index: path_str.event_parts.event_selector_index,
                sold_token_volume_index: path_str.event_parts.sold_token_volume_index,
                sold_token_id: str_to_u8_array(&path_str.event_parts.pool_address)?,
                sold_token_id_index: path_str.event_parts.sold_token_id_index,
                bought_token_volume_index: path_str.event_parts.bought_token_volume_index,
            },
        };
        Ok(path)
    }
}

pub fn read_paths_from_file(file_name: &str) -> Result<Vec<PatriciaMerklePath>, anyhow::Error> {
    let file = File::open(file_name)?;
    let reader = BufReader::new(file);
    let paths_str: Vec<PatriciaMerklePathStr> = match serde_json::from_reader(reader) {
        Ok(paths) => paths,
        Err(e) => {
            error!("JSON deserialization error: {:?}", e);
            std::process::exit(1);
        }
    };
    let mut paths: Vec<PatriciaMerklePath> = vec![];
    let mut merkle_path: Vec<PatriciaMerklePathElement> = vec![];
    for i in paths_str.iter() {
        for j in i.merkle_path.iter() {
            merkle_path.push(PatriciaMerklePathElement {
                prefix: str_to_u8_array(&j.prefix)?,
                postfix: str_to_u8_array(&j.postfix)?,
                prefix_length: j.prefix_length,
                postfix_length: j.postfix_length,
            });
        }
        paths.push(PatriciaMerklePath {
            merkle_path: merkle_path.clone(),
            rlp_recipt: str_to_u8_array(&i.rlp_recipt)?,
            hash_root: str_to_u8_array(&i.hash_root)?,
            event_parts: EventParts {
                pool_address: str_to_u8_array(&i.event_parts.pool_address)?,
                event_selector: str_to_u8_array(&i.event_parts.event_selector)?,
                sold_token_volume: str_to_u8_array(&i.event_parts.sold_token_volume)?,
                pool_address_index: i.event_parts.pool_address_index,
                event_rlp_index: i.event_parts.event_rlp_index,
                event_selector_index: i.event_parts.event_selector_index,
                sold_token_volume_index: i.event_parts.sold_token_volume_index,
                sold_token_id: str_to_u8_array(&i.event_parts.sold_token_id)?,
                sold_token_id_index: i.event_parts.sold_token_id_index,
                bought_token_volume_index: i.event_parts.bought_token_volume_index,
            },
        });
        merkle_path.clear();
    }
    Ok(paths)
}

pub fn read_paths_from_json_request(objects_arr: &Vec<Value>) -> Result<Vec<PatriciaMerklePath>, anyhow::Error> {
    let mut merkle_path: Vec<PatriciaMerklePathElement> = vec![];
    let mut paths: Vec<PatriciaMerklePath> = vec![];
    for object in objects_arr {
        let paths_str: PatriciaMerklePathStr = serde_json::from_value(object.clone()).unwrap();
        for j in paths_str.merkle_path.iter() {
            merkle_path.push(PatriciaMerklePathElement {
                prefix: str_to_u8_array(&j.prefix)?,
                postfix: str_to_u8_array(&j.postfix)?,
                prefix_length: j.prefix_length,
                postfix_length: j.postfix_length,
            });
        }
        paths.push(PatriciaMerklePath {
            merkle_path: merkle_path.clone(),
            rlp_recipt: str_to_u8_array(&paths_str.rlp_recipt)?,
            hash_root: str_to_u8_array(&paths_str.hash_root)?,
            event_parts: EventParts {
                pool_address: str_to_u8_array(&paths_str.event_parts.pool_address)?,
                event_selector: str_to_u8_array(&paths_str.event_parts.event_selector)?,
                sold_token_volume: str_to_u8_array(&paths_str.event_parts.sold_token_volume)?,
                pool_address_index: paths_str.event_parts.pool_address_index,
                event_rlp_index: paths_str.event_parts.event_rlp_index,
                event_selector_index: paths_str.event_parts.event_selector_index,
                sold_token_volume_index: paths_str.event_parts.sold_token_volume_index,
                sold_token_id: str_to_u8_array(&paths_str.event_parts.sold_token_id)?,
                sold_token_id_index: paths_str.event_parts.sold_token_id_index,
                bought_token_volume_index: paths_str.event_parts.bought_token_volume_index,
            },
        });
        merkle_path.clear();
    }
    Ok(paths)
}


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
#[serde(bound = "")]
pub struct PatriciaTree {
    pub root: Option<Box<TreeNode>>,
    pub hash_root: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(bound = "")]
pub enum NodeType {
    LEAF,
    NODE,
    ROOT,
    NULL,
}

impl Default for NodeType {
    fn default() -> Self {
        NodeType::NULL
    }
}


#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
#[serde(bound = "")]
pub struct TreeNode {
    pub value: Option<PatriciaMerklePathElement>,
    pub children: Vec<TreeNode>,
    pub rlp_receipt: Option<Vec<u8>>,
    pub event_parts: Option<Vec<EventParts>>,
    pub index_level: usize,
    pub num_paths: Vec<usize>,
    pub node_type: NodeType,
    pub full_data: Vec<u8>,
    pub hash_offset: Vec<usize>,
    pub hash: H256,

}

impl TreeNode {
    fn insert(&mut self, value: Option<PatriciaMerklePathElement>, level: usize, rlp_receipt: Option<Vec<u8>>, event_parts: Option<EventParts>,
              path_index: usize, node_type: NodeType, full_data: Vec<u8>, hash_offset: usize, hash: H256) {
        if level == self.index_level + 1 {
            if let Some(existing_child) = self.children.iter_mut().find(|child| {
                child.index_level == level && child.full_data.clone() == full_data.clone() && child.hash == hash
            }) {
                if !existing_child.hash_offset.contains(&hash_offset.clone()) {
                    existing_child.hash_offset.push(hash_offset.clone());
                    existing_child.num_paths.push(path_index.clone());
                }

                if let Some(existing_events) = existing_child.event_parts.as_mut() {
                        existing_events.push(event_parts.clone().unwrap());
                }
            } else {
                let new_node = TreeNode {
                    value,
                    children: Vec::new(),
                    rlp_receipt,
                    event_parts: if event_parts.is_some(){
                       Some(vec![event_parts.unwrap()])
                    }else {
                        None
                    },
                    index_level: level,
                    num_paths: vec![path_index],
                    node_type,
                    full_data,
                    hash_offset: vec![hash_offset],
                    hash,
                };
                self.children.push(new_node);
            }
        } else {
            if let Some(existing_child) = self.children.iter_mut().find(|child| child.index_level == self.index_level + 1) {
                existing_child.insert(value, level, rlp_receipt, event_parts, path_index, node_type, full_data, hash_offset, hash);
                return;
            } else {
                let new_node = TreeNode {
                    value,
                    children: Vec::new(),
                    rlp_receipt,
                    event_parts: if event_parts.is_some(){
                        Some(vec![event_parts.unwrap()])
                    }else {
                        None
                    },
                    index_level: level,
                    num_paths: vec![path_index],
                    node_type,
                    full_data,
                    hash_offset: vec![hash_offset],
                    hash,
                };
                self.children.push(new_node);
            }
        }
    }

    fn print_at_level(&self, indent: String, target_level: usize) {
        if self.index_level == target_level {
            info!("Hash: {:?}", self.hash);
        }
        for child in &self.children {
            child.print_at_level(indent.clone(), target_level);
        }
    }
}

impl PatriciaTree {
    pub fn insert(&mut self, value: Option<PatriciaMerklePathElement>, level: usize, rlp_receipt: Option<Vec<u8>>,
                  event_parts: Option<EventParts>, path_index: usize, node_type: NodeType, full_data: Vec<u8>, hash_offset: usize, hash: H256) {
        if let Some(root) = &mut self.root {
            if level == 0 && root.hash == hash && root.full_data == full_data {
                if root.hash_offset.contains(&hash_offset) {
                    return;
                } else {
                    root.hash_offset.push(hash_offset);
                }
            } else {
                root.insert(value, level, rlp_receipt, event_parts, path_index, node_type, full_data, hash_offset, hash);
            }
        } else {
            let new_node = TreeNode {
                value,
                children: Vec::new(),
                rlp_receipt,
                event_parts: if event_parts.is_some(){
                    Some(vec![event_parts.unwrap()])
                }else {
                    None
                },
                index_level: level,
                num_paths: vec![path_index],
                node_type,
                full_data,
                hash_offset: vec![hash_offset],
                hash,
            };
            self.root = Some(Box::new(new_node));
        }
    }


    pub fn print_at_each_level(&self) {
        if let Some(root) = &self.root {
            let max_level = self.get_max_level();
            for level in 0..=max_level {
                info!("Level {}", level);
                root.print_at_level(String::new(), level);
            }
        } else {
            info!("Tree is empty.");
        }
    }

    pub fn get_root(&self) -> Option<&TreeNode> {
        self.root.as_ref().map(|boxed_root| &**boxed_root)
    }

    fn get_max_level(&self) -> usize {
        fn find_max_level(node: &TreeNode, current_max: usize) -> usize {
            let new_max = std::cmp::max(current_max, node.index_level);
            node.children
                .iter()
                .fold(new_max, |max, child| find_max_level(child, max))
        }

        if let Some(root) = &self.root {
            find_max_level(root, root.index_level)
        } else {
            0
        }
    }
}

pub fn convert_to_tree(paths: &[PatriciaMerklePath]) -> Result<Vec<PatriciaTree>> {
    let mut seen_hashes = HashSet::new();
    let mut hash_to_paths: HashMap<Vec<u8>, Vec<PatriciaMerklePath>> = HashMap::new();

    for path in paths.iter() {
        let hash_root = &path.hash_root;
        if seen_hashes.contains(hash_root) {
            if let Some(paths) = hash_to_paths.get_mut(hash_root) {
                paths.push(path.clone());
            }
        } else {
            seen_hashes.insert(hash_root.clone());
            hash_to_paths.insert(hash_root.clone(), vec![path.clone()]);
        }
    }

    let mut result = Vec::new();
    for (_, paths) in &hash_to_paths {
        if paths.len() > 1 {
            let mut tree = PatriciaTree {
                root: None,
                hash_root: paths[0].hash_root.clone(),
            };
            let mut path_index = 0;
            for path in paths.iter() {
                let mut num_hash: usize = paths[path_index].clone().merkle_path.len();
                let merkle_path = paths[path_index].clone().merkle_path;
                let path_copy = paths[path_index].clone();
                for (index, path_el) in path.merkle_path.iter().skip(1).rev().enumerate() {
                    let mut hash = H256::default();
                    let mut data = vec![];
                    for i in 0..num_hash {
                        data = [
                            merkle_path[i].prefix.clone(),
                            if i == 0 {
                                path_copy.rlp_recipt.clone()
                            } else {
                                hash.clone().as_bytes().to_vec()
                            },
                            merkle_path[i].postfix.clone(),
                        ]
                            .concat();
                        hash = keccak(data.clone());
                    }
                    let node_type = if index == 0 {
                        NodeType::ROOT
                    } else {
                        NodeType::NODE
                    };
                    num_hash -= 1;
                    tree.insert(None, index, None, None, path_index, node_type, data, path_el.prefix.len(), hash);
                }
                let data =
                    [
                        path_copy.merkle_path[0].prefix.clone(),
                        path_copy.rlp_recipt.clone(),
                        path_copy.merkle_path[0].postfix.clone(),
                    ].concat();
                let hash = keccak(data.clone());
                tree.insert(Some(path_copy.merkle_path[0].clone()), path_copy.merkle_path.len() - 1, Some(path_copy.rlp_recipt),
                            Some(path_copy.event_parts), path_index, NodeType::LEAF, data, path_copy.merkle_path[0].clone().prefix.len(), hash);
                path_index += 1;
            }
            result.push(tree);
        } else {
            let mut tree = PatriciaTree {
                root: None,
                hash_root: paths[0].hash_root.clone(),
            };
            let mut num_hash: usize = paths[0].clone().merkle_path.len();
            let merkle_path = paths[0].clone().merkle_path;
            let path_copy = paths[0].clone();
            for (index, path) in paths[0].clone().merkle_path.iter().skip(1).rev().enumerate() {
                let mut hash = H256::default();
                let mut data = vec![];
                for i in 0..num_hash {
                    data = [
                        merkle_path[i].prefix.clone(),
                        if i == 0 {
                            path_copy.rlp_recipt.clone()
                        } else {
                            hash.clone().as_bytes().to_vec()
                        },
                        merkle_path[i].postfix.clone(),
                    ]
                        .concat();
                    hash = keccak(data.clone());
                }

                let node_type = if index == 0 {
                    NodeType::ROOT
                } else {
                    NodeType::NODE
                };
                num_hash -= 1;
                tree.insert(None, index, None, None, 0, node_type, data, path.prefix_length, hash);
            }
            let data =
                [
                    path_copy.merkle_path[0].prefix.clone(),
                    path_copy.rlp_recipt.clone(),
                    path_copy.merkle_path[0].postfix.clone(),
                ].concat();
            let hash = keccak(data.clone());
            tree.insert(Some(path_copy.merkle_path[0].clone()), path_copy.merkle_path.len() - 1, Some(path_copy.rlp_recipt),
                        Some(path_copy.event_parts), 0, NodeType::LEAF, data, path_copy.merkle_path[0].clone().prefix.len(), hash);
            result.push(tree);
        }
    }


    Ok(result)
}


pub fn find_root(merkle_path: &[PatriciaMerklePathElement], rlp_recipt: &[u8]) -> Vec<u8> {
    let mut hash = rlp_recipt.to_vec();
    for i in 0..merkle_path.len() {
        hash = keccak(
            [
                merkle_path[i].prefix.clone(),
                hash,
                merkle_path[i].postfix.clone(),
            ]
                .concat(),
        )
            .0
            .to_vec();
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
    use anyhow::Result;


    fn init_logger() {
        let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"));
    }

    #[test]
    fn test_tree() -> Result<()> {
        init_logger();
        let all_paths: Vec<PatriciaMerklePath> = read_paths_from_file("test_data/paths/block_headers_12901300-12901399.json")?;
        let result = convert_to_tree(&all_paths)?;
        for tree in result {
            tree.print_at_each_level()
        }
        Ok(())
    }
}
