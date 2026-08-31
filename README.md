# ocaml-web3-codec

Shared pure-OCaml codecs for the Reuna Web3 libraries: canonical CBOR,
protobuf, Base58, BaseN, Bech32, Borsh, RLP and multiformats. The lean codec
packages keep protocol clients from depending on the umbrella library.

> **Security:** public, unaudited `v0.1.0-alpha1`. Parsers process untrusted
> network and signed data; do not treat alpha status as production assurance.
> See [SECURITY.md](SECURITY.md) for private reporting and the review boundary.

## Install

```sh
opam repository add reuna https://github.com/reuna-labs/opam-repository.git
opam update
opam install web3-codec.0.1.0~alpha1
```

Consumers can install only the required lean packages, for example
`web3-codec-cbor`, `web3-codec-protobuf` or `web3-codec-base58`. All overlay
entries use immutable release archives with SHA-256 and SHA-512 checksums; no
development pins are required.

## Build and test

```sh
opam install . --deps-only --with-test
opam exec -- dune build @install
opam exec -- dune runtest
```

The protobuf runtime includes bounds checks for hostile lengths, and `fuzz/`
contains the parser fuzz target. Ordinary tests are hermetic.

## Licence

ISC; see [LICENSE](LICENSE).
