(* CID -- the IPLD content identifier that ties the other three together.
   https://github.com/multiformats/cid

   CIDv1 is <varint 1><varint content codec><multihash>, rendered in text
   through multibase.

   CIDv0 is not a degenerate CIDv1: it is bare, 34 bytes of sha2-256
   multihash with no version varint and no multibase prefix, always dag-pb,
   and always written in base58btc. Treating it as its own shape is what
   keeps the two from being confused. *)

type version = V0 | V1

type t = { version : version; codec : Multicodec.t; hash : Multihash.t }

let dag_pb = 0x70
let sha2_256 = 0x12

let version t = t.version
let codec t = t.codec
let hash t = t.hash

let is_v0_hash h =
  Multicodec.to_code (Multihash.code h) = sha2_256
  && String.length (Multihash.digest_bytes h) = 32

let v0 h =
  if is_v0_hash h then Ok { version = V0; codec = dag_pb; hash = h }
  else Error "cid: a v0 CID must carry a 32-byte sha2-256 multihash"

let v1 ~codec hash = { version = V1; codec; hash }

let to_v1 t = { t with version = V1 }

let to_v0 t =
  if Multicodec.to_code t.codec <> dag_pb then
    Error "cid: only a dag-pb CID can be written as v0"
  else if not (is_v0_hash t.hash) then
    Error "cid: a v0 CID must carry a 32-byte sha2-256 multihash"
  else Ok { t with version = V0 }

let to_octets t =
  match t.version with
  | V0 -> Multihash.to_octets t.hash
  | V1 ->
    Varint.write 1 ^ Varint.write (Multicodec.to_code t.codec) ^ Multihash.to_octets t.hash

(* A v0 CID is exactly 34 bytes opening with 0x12 0x20 -- sha2-256, length
   32. No other CID can collide with that: a v1 opens with the version
   varint 0x01. *)
let looks_v0 s =
  String.length s = 34 && s.[0] = '\x12' && s.[1] = '\x20'

let of_octets s =
  if looks_v0 s then
    match Multihash.of_octets s with
    | Error _ as e -> e
    | Ok h -> v0 h
  else
    match Varint.read_result s 0 with
    | Error m -> Error m
    | Ok (0, _) ->
        (* an explicit version varint of 0 is not a thing: v0 has no
           version field at all, so this is ambiguous by construction *)
        Error "cid: version 0 is implicit and must not be written as a varint"
    | Ok (1, pos) -> (
      match Varint.read_result s pos with
      | Error m -> Error m
      | Ok (codec, pos) -> (
        match Multihash.read s pos with
        | Error m -> Error m
        | Ok (h, pos) ->
          if pos <> String.length s then Error "cid: trailing bytes"
          else Ok { version = V1; codec = Multicodec.of_code codec; hash = h }))
    | Ok (v, _) -> Error (Printf.sprintf "cid: unsupported version %d" v)

(* v0 has no multibase prefix; its text form is bare base58btc. *)
let to_string ?(base = Multibase.Base32) t =
  match t.version with
  | V0 -> Basen.encode ~max_length:Multibase.max_radix_length ~name:"cid" Basen.btc (to_octets t)
  | V1 -> Multibase.encode base (to_octets t)

let of_string s =
  if String.length s = 0 then Error "cid: empty string"
  else
    match Multibase.of_prefix s.[0] with
    | Some _ -> (
      match Multibase.decode s with
      | Error m -> Error m
      | Ok (_, bytes) -> of_octets bytes)
    | None -> (
      (* no multibase prefix, so this can only be a bare base58btc v0 *)
      match Basen.decode ~max_length:Multibase.max_radix_length ~name:"cid" Basen.btc s with
      | Error m -> Error m
      | Ok bytes ->
        if looks_v0 bytes then of_octets bytes
        else Error "cid: not a multibase prefix and not a v0 CID")

let equal a b = String.equal (to_octets a) (to_octets b)
