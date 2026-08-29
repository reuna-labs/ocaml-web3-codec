## v0.1.0~alpha1 (unreleased)

First alpha release of the shared web3 codec family: bounded radix, Base58,
Bech32/Bech32m, Borsh, deterministic CBOR, protobuf runtime, and the full
multiformats/ABI/RLP/SCALE package. The protocol-specific packages can depend
on the lean codec slices without pulling in the full dependency closure.
