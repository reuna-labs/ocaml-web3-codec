(* The multicodec registry: a varint code identifying what some bytes are.
   https://github.com/multiformats/multicodec

   A code is just an integer, so [t = int] and every code is
   representable -- including ones absent from the table below. That is
   deliberate: an unknown code must still round-trip, or a CID naming a
   codec this library has never heard of would become unparseable rather
   than merely unnamed.

   The table is a curated subset of the upstream registry covering the
   hashes, IPLD codecs, multiaddr protocols and key types this library
   actually reaches, plus the key and hash types the sibling
   mirage-crypto-blockchain package can compute.

   Provenance: every entry was checked against multiformats/multicodec
   table.csv (master, 651 entries) on 2026-08-21 -- codes and names both.
   [test/multiformats.ml] additionally checks the table for internal
   consistency, since a duplicate would be silently shadowed by the lookup
   tables below. To refresh against upstream:

     curl -sSL https://raw.githubusercontent.com/multiformats/multicodec/\
master/table.csv

   Note that a few names differ between registries for the same code:
   0x309 is "memorytransport" here, which multiaddr spells "memory" in its
   own protocol table. Each table uses its own domain's name. *)

type tag =
  | Multihash
  | Ipld
  | Multiaddr
  | Key
  | Serialization
  | Misc

type t = int

let table : (int * string * tag) list =
  [ (* --- misc / CID versions --- *)
    (0x00, "identity", Multihash);
    (0x01, "cidv1", Misc);
    (0x02, "cidv2", Misc);
    (0x03, "cidv3", Misc);
    (* --- multiaddr protocols --- *)
    (0x04, "ip4", Multiaddr);
    (0x06, "tcp", Multiaddr);
    (0x21, "dccp", Multiaddr);
    (0x29, "ip6", Multiaddr);
    (0x2a, "ip6zone", Multiaddr);
    (0x35, "dns", Multiaddr);
    (0x36, "dns4", Multiaddr);
    (0x37, "dns6", Multiaddr);
    (0x38, "dnsaddr", Multiaddr);
    (0x84, "sctp", Multiaddr);
    (0x0111, "udp", Multiaddr);
    (0x0113, "p2p-webrtc-star", Multiaddr);
    (0x0114, "p2p-webrtc-direct", Multiaddr);
    (0x0122, "p2p-circuit", Multiaddr);
    (0x012d, "udt", Multiaddr);
    (0x012e, "utp", Multiaddr);
    (0x0190, "unix", Multiaddr);
    (0x01a5, "p2p", Multiaddr);
    (0x01bb, "https", Multiaddr);
    (0x01bc, "onion", Multiaddr);
    (0x01bd, "onion3", Multiaddr);
    (0x01be, "garlic64", Multiaddr);
    (0x01bf, "garlic32", Multiaddr);
    (0x01c0, "tls", Multiaddr);
    (0x01c1, "sni", Multiaddr);
    (0x01c6, "noise", Multiaddr);
    (0x01cc, "quic", Multiaddr);
    (0x01cd, "quic-v1", Multiaddr);
    (0x01d1, "webtransport", Multiaddr);
    (0x01d2, "certhash", Multiaddr);
    (0x01dd, "ws", Multiaddr);
    (0x01de, "wss", Multiaddr);
    (0x01df, "p2p-websocket-star", Multiaddr);
    (0x01e0, "http", Multiaddr);
    (0x0309, "memorytransport", Multiaddr);
    (* --- hash functions --- *)
    (0x11, "sha1", Multihash);
    (0x12, "sha2-256", Multihash);
    (0x13, "sha2-512", Multihash);
    (0x14, "sha3-512", Multihash);
    (0x15, "sha3-384", Multihash);
    (0x16, "sha3-256", Multihash);
    (0x17, "sha3-224", Multihash);
    (0x18, "shake-128", Multihash);
    (0x19, "shake-256", Multihash);
    (0x1a, "keccak-224", Multihash);
    (0x1b, "keccak-256", Multihash);
    (0x1c, "keccak-384", Multihash);
    (0x1d, "keccak-512", Multihash);
    (0x1e, "blake3", Multihash);
    (0x20, "sha2-384", Multihash);
    (0x56, "dbl-sha2-256", Multihash);
    (0xd5, "md5", Multihash);
    (0x1013, "sha2-224", Multihash);
    (0x1014, "sha2-512-224", Multihash);
    (0x1015, "sha2-512-256", Multihash);
    (* RIPEMD and Poseidon: not computable from digestif, but the sibling
       mirage-crypto-blockchain package implements ripemd-160 (Bitcoin's
       hash160) and Poseidon, so name them here regardless -- naming a code
       costs nothing and parsing never depended on computing. *)
    (0x1052, "ripemd-128", Multihash);
    (0x1053, "ripemd-160", Multihash);
    (0x1054, "ripemd-256", Multihash);
    (0x1055, "ripemd-320", Multihash);
    (0xb401, "poseidon-bls12_381-a2-fc1", Multihash);
    (* --- IPLD / content types --- *)
    (0x50, "protobuf", Serialization);
    (0x51, "cbor", Serialization);
    (0x55, "raw", Ipld);
    (0x60, "rlp", Serialization);
    (0x63, "bencode", Serialization);
    (0x70, "dag-pb", Ipld);
    (0x71, "dag-cbor", Ipld);
    (0x72, "libp2p-key", Ipld);
    (0x78, "git-raw", Ipld);
    (0x7b, "torrent-info", Ipld);
    (0x7c, "torrent-file", Ipld);
    (0x90, "eth-block", Ipld);
    (0x91, "eth-block-list", Ipld);
    (0x92, "eth-tx-trie", Ipld);
    (0x93, "eth-tx", Ipld);
    (0x94, "eth-tx-receipt-trie", Ipld);
    (0x95, "eth-tx-receipt", Ipld);
    (0x96, "eth-state-trie", Ipld);
    (0x97, "eth-account-snapshot", Ipld);
    (0x98, "eth-storage-trie", Ipld);
    (0xb0, "bitcoin-block", Ipld);
    (0xb1, "bitcoin-tx", Ipld);
    (0xb2, "bitcoin-witness-commitment", Ipld);
    (0xc0, "zcash-block", Ipld);
    (0xc1, "zcash-tx", Ipld);
    (0x0129, "dag-json", Ipld);
    (0x0200, "json", Serialization);
    (0x0300, "ipns-record", Ipld);
    (* --- keys --- *)
    (0xe7, "secp256k1-pub", Key);
    (0xea, "bls12_381-g1-pub", Key);
    (0xeb, "bls12_381-g2-pub", Key);
    (0xec, "x25519-pub", Key);
    (0xed, "ed25519-pub", Key);
    (0xee, "bls12_381-g1g2-pub", Key);
    (0xef, "sr25519-pub", Key);
    (0x1200, "p256-pub", Key);
    (0x1201, "p384-pub", Key);
    (0x1202, "p521-pub", Key);
    (0x1203, "ed448-pub", Key);
    (0x1204, "x448-pub", Key);
    (0x1205, "rsa-pub", Key);
    (0x1300, "ed25519-priv", Key);
    (0x1301, "secp256k1-priv", Key);
    (0x1302, "x25519-priv", Key);
    (0x1303, "sr25519-priv", Key);
    (0x1305, "rsa-priv", Key);
    (0x1306, "p256-priv", Key);
    (0x1307, "p384-priv", Key);
    (0x1308, "p521-priv", Key);
    (0x1309, "bls12_381-g1-priv", Key);
    (0x130a, "bls12_381-g2-priv", Key);
    (0x1340, "bip340-pub", Key);
    (0x1341, "bip340-priv", Key);
    (0xeb51, "jwk_jcs-pub", Key);
  ]
  (* BLAKE2b-8..512 and BLAKE2s-8..256 are contiguous ranges, so they are
     generated rather than listed: blake2b-N is 0xb200 + N/8. *)
  @ List.init 64 (fun i -> (0xb200 + i + 1, Printf.sprintf "blake2b-%d" ((i + 1) * 8), Multihash))
  @ List.init 32 (fun i -> (0xb240 + i + 1, Printf.sprintf "blake2s-%d" ((i + 1) * 8), Multihash))

let by_code = Hashtbl.create 512
let by_name = Hashtbl.create 512

let () =
  List.iter
    (fun (code, name, tag) ->
      Hashtbl.replace by_code code (name, tag);
      Hashtbl.replace by_name name code)
    table

let of_code c = c
let to_code t = t
let name t = match Hashtbl.find_opt by_code t with Some (n, _) -> Some n | None -> None
let tag t = match Hashtbl.find_opt by_code t with Some (_, g) -> Some g | None -> None
let of_name n = Hashtbl.find_opt by_name n
let is_known t = Hashtbl.mem by_code t

(* An unknown code prints as its hex value, so it stays round-trippable
   through text and stays obviously unnamed. *)
let to_string t =
  match name t with Some n -> n | None -> Printf.sprintf "0x%02x" t

let write t = Varint.write t
let read s pos = Varint.read s pos
