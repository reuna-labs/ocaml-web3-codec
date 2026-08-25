(lang dune 3.0)
(name web3-codec)
(version 0.1.0~alpha1)
(generate_opam_files true)
(source (github reuna-labs/ocaml-web3-codec))
(license ISC)
(authors "Gil Bahat <bahat.gil@gmail.com>")
(maintainers "Gil Bahat <bahat.gil@gmail.com>")

(package
 (name web3-codec-basen)
 (synopsis "Bounded radix conversion for web3 encodings")
 (description
  "Canonical bounded conversion for base10, base36 and base58 alphabets.")
 (depends
  (ocaml (>= 4.14))
  (zarith (>= 1.12))
  (alcotest :with-test)))

(package
 (name web3-codec-base58)
 (synopsis "Base58 and Base58Check for web3 protocols")
 (description
  "Canonical Bitcoin-alphabet Base58 and Base58Check without the full web3-codec dependency closure.")
 (depends
  (ocaml (>= 4.14))
  (web3-codec-basen (= :version))
  (digestif (>= 1.2.0))
  (alcotest :with-test)))

(package
 (name web3-codec-bech32)
 (synopsis "Bech32 and Bech32m for web3 address encodings")
 (description
  "BIP-173 Bech32 and BIP-350 Bech32m, without the full web3-codec dependency\nclosure. Depends on nothing: the checksum is integer arithmetic and the\ncharset is a string, so this links into a MirageOS/Solo5 unikernel and needs\nno bignum.\n\nThe 90-character cap is BIP-173's and remains the default, but it is a\nparameter rather than a constant -- the Cosmos SDK spells addresses in Bech32\nand does not enforce it.")
 (depends
  (ocaml (>= 4.14))
  (alcotest :with-test)))

(package
 (name web3-codec-borsh)
 (synopsis "Canonical Borsh encoding and decoding")
 (description
  "Strict canonical Borsh primitives for Solana, NEAR and other protocols.")
 (depends
  (ocaml (>= 4.14))
  (zarith (>= 1.12))
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))

(package
 (name web3-codec-cbor)
 (synopsis "Deterministic CBOR for hash-bearing protocols")
 (description
  "RFC 8949 CBOR with a permissive decoder and a strict encoder, offering both\nthe RFC 8949 section 4.2.1 and the RFC 7049 section 3.9 map orderings, and\nreporting the source byte span of every decoded value so that a structure\nidentified by the hash of its encoding can be re-hashed from the bytes it\narrived in rather than from a re-encode.\n\nNo bignum dependency: arbitrary-precision integers are carried as magnitudes\nand never operated on, so this links into a unikernel without GMP.")
 (depends
  (ocaml (>= 4.14))
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))

(package
 (name web3-codec-protobuf)
 (synopsis "Protobuf runtime for the OCaml chain libraries")
 (description
  "The ocaml-protoc-plugin 6.2.0 runtime, vendored with its ppx pre-expanded,\nplus tools/gen-protobuf.sh -- the shared protoc invocation that generates\nbindings for a consuming repository.\n\nThe package proper cannot be depended on: building its code generator needs\nppx_expect, ppx_inline_test, omd and conf-protoc, and that cone makes\n`opam monorepo lock` fail outright, so a unikernel could not vendor its\ndependencies at all. The runtime alone is base64 + ptime and neither depends\non unix, so this links into a MirageOS/Solo5 guest.\n\nGenerated bindings are NOT here: they belong to whichever repository owns the\nschema, and are committed there so that building it needs no protoc. Only the\nruntime and the generator invocation are shared. See lib/protobuf/README.md.")
 (depends
  (ocaml (>= 4.14))
  (base64 (>= 3.1.0))
  ptime))

(package
 (name web3-codec)
 (synopsis "Serialization formats shared across blockchain protocols")
 (description
  "Byte-level codecs used by more than one chain: Ethereum ABI, RLP, SCALE,\nBorsh, base58, bech32, SS58 and the CRC variants those formats rely on,\nplus the multiformats family -- unsigned varint, multibase (with base16,\nbase32 and base64), multicodec, multihash, CID, multiaddr, multikey and\nmultistream-select framing.")
 (depends
  (ocaml (>= 4.14))
  (zarith (>= 1.12))
  (web3-codec-basen (= :version))
  (web3-codec-base58 (= :version))
  (web3-codec-bech32 (= :version))
  (web3-codec-borsh (= :version))
  ; 1.4.0 is the Reuna fork (private: github.com/reuna-labs/digestif). It is
  ; what supplies SHAKE-128/256, KECCAK-224/384/512 and SHA-512/224+256, which
  ; Multihash.compute needs to cover the multicodec codes this library already
  ; names. Released digestif tops out at 1.3.1, so a plain `opam install` will
  ; not solve this: pin it first, e.g.
  ;   opam pin add -k path -yn digestif.1.4.0 ../../ports/ocaml/digestif
  (digestif (>= 1.4.0))
  (evm-abi (>= 0.1.0))
  (alcotest :with-test)
  (qcheck-core :with-test)
  (qcheck-alcotest :with-test)))
