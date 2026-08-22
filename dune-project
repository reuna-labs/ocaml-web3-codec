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
 (name web3-codec)
 (synopsis "Serialization formats shared across blockchain protocols")
 (description
  "Byte-level codecs used by more than one chain: Ethereum ABI, RLP, SCALE,\nBorsh, base58, bech32, SS58 and the CRC variants those formats rely on,\nplus the multiformats family -- unsigned varint, multibase (with base16,\nbase32 and base64), multicodec, multihash, CID, multiaddr, multikey and\nmultistream-select framing.")
 (depends
  (ocaml (>= 4.14))
  (zarith (>= 1.12))
  (web3-codec-basen (= :version))
  (web3-codec-base58 (= :version))
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
