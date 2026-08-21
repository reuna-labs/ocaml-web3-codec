(* Multikey: a public or private key that says which algorithm it belongs
   to -- <varint key codec><key bytes>.

   Its text form is a multibase string, and in base58btc that is exactly
   the W3C Multikey / did:key encoding: ed25519 keys come out as "z6Mk...",
   secp256k1 as "zQ3s...", and so on. Those prefixes are not special-cased
   here; they fall out of the codec varint.

   This is a structural codec only. The library has no elliptic-curve code,
   so it checks the length a key type declares and nothing more -- it
   cannot tell you a point is on its curve, or that a private key is in
   range. Do not read a successful decode as key validation. *)

type t = { codec : Multicodec.t; key : string }

let codec t = t.codec
let key_bytes t = t.key

(* Byte lengths for the key types with a fixed one. A wrong entry here
   rejects valid keys, so each is either derivable from the curve size or
   was checked against mirage-crypto-blockchain's encodings. Types whose
   length is neither -- RSA's DER, JWK's JSON, Ed448's 456+1 convention --
   are absent rather than guessed at, and are simply unconstrained. *)
let expected_length code =
  match code with
  | 0xe7 -> Some 33 (* secp256k1-pub, compressed *)
  | 0xea -> Some 48 (* bls12_381-g1-pub, compressed *)
  | 0xeb -> Some 96 (* bls12_381-g2-pub, compressed *)
  | 0xec -> Some 32 (* x25519-pub *)
  | 0xed -> Some 32 (* ed25519-pub *)
  | 0xee -> Some 144 (* bls12_381-g1g2-pub, a compressed G1 then G2 *)
  | 0xef -> Some 32 (* sr25519-pub, a Ristretto point *)
  | 0x1200 -> Some 33 (* p256-pub, compressed *)
  | 0x1201 -> Some 49 (* p384-pub, compressed *)
  | 0x1202 -> Some 67 (* p521-pub, compressed *)
  | 0x1204 -> Some 56 (* x448-pub *)
  | 0x1300 -> Some 32 (* ed25519-priv *)
  | 0x1301 -> Some 32 (* secp256k1-priv *)
  | 0x1302 -> Some 32 (* x25519-priv *)
  | 0x1303 -> Some 32 (* sr25519-priv, a MiniSecretKey seed *)
  | 0x1306 -> Some 32 (* p256-priv *)
  | 0x1307 -> Some 48 (* p384-priv *)
  | 0x1308 -> Some 66 (* p521-priv, 521 bits rounded up *)
  | 0x1309 -> Some 32 (* bls12_381-g1-priv, a scalar mod r *)
  | 0x130a -> Some 32 (* bls12_381-g2-priv *)
  | 0x1340 -> Some 32 (* bip340-pub, x-only *)
  | 0x1341 -> Some 32 (* bip340-priv *)
  | _ -> None

let check code key =
  match expected_length code with
  | Some n when String.length key <> n ->
    Error
      (Printf.sprintf "multikey: %s is %d bytes, got %d" (Multicodec.to_string code) n
         (String.length key))
  | _ -> Ok ()

let make ~codec ~key =
  match check (Multicodec.to_code codec) key with
  | Error m -> Error m
  | Ok () -> Ok { codec; key }

let to_octets t = Varint.write (Multicodec.to_code t.codec) ^ t.key

let of_octets s =
  match Varint.read_result s 0 with
  | Error m -> Error m
  | Ok (code, pos) ->
    let key = String.sub s pos (String.length s - pos) in
    (match check code key with
     | Error m -> Error m
     | Ok () -> Ok { codec = Multicodec.of_code code; key })

(* base58btc is what W3C Multikey and did:key use. *)
let to_string ?(base = Multibase.Base58btc) t = Multibase.encode base (to_octets t)

let of_string s =
  match Multibase.decode s with
  | Error m -> Error m
  | Ok (_, bytes) -> of_octets bytes

let did_key_prefix = "did:key:"

let to_did_key t = did_key_prefix ^ to_string ~base:Multibase.Base58btc t

let of_did_key s =
  let n = String.length did_key_prefix in
  if String.length s <= n || String.sub s 0 n <> did_key_prefix then
    Error "multikey: not a did:key URI"
  else
    let rest = String.sub s n (String.length s - n) in
    (* did:key is base58btc only; another multibase would be a different
       representation, not this one *)
    if String.length rest = 0 || rest.[0] <> Multibase.prefix Multibase.Base58btc then
      Error "multikey: did:key must be base58btc (a 'z' prefix)"
    else of_string rest
