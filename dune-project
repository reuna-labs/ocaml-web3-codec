(lang dune 3.0)
(name web3-codec)
(generate_opam_files true)
(source (github reuna-labs/ocaml-web3-codec))
(license ISC)
(authors "Gil Bahat <bahat.gil@gmail.com>")
(maintainers "Gil Bahat <bahat.gil@gmail.com>")

(package
 (name web3-codec)
 (synopsis "Serialization formats shared across blockchain protocols")
 (description
  "Byte-level codecs used by more than one chain: Ethereum ABI, RLP, SCALE,\nBorsh, base58, bech32, SS58 and the CRC variants those formats rely on.")
 (depends
  (ocaml (>= 4.14))
  (zarith (>= 1.12))
  (digestif (>= 1.1.4))
  (evm-abi (>= 0.1.0))
  (alcotest :with-test)))
