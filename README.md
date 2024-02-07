# volume-stark

## How to run volume_stark for Testnet v0.3
```
cargo run --release --bin generate_recursive_circuit config/config.json circuits/testnet_v03.circuit
cargo run --release --bin prove_recursive circuits/testnet_v03.circuit test_data/paths/paths_1.json test_data/headers/blockheaders_1.json firstproof.bin
cargo run --release --bin prove_recursive circuits/testnet_v03.circuit test_data/paths/paths_2.json test_data/headers/blockheaders_2.json secondproof.bin
cargo run --release --bin prove_agg_recursive circuits/testnet_v03.circuit proof_list.txt final_proof.bin     
```

For aggregation, you need to create txt file with proof path names, for example:
```
firstproof.bin
secondproof.bin
```
