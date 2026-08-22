(* Multihash: a digest that says which function produced it.
   <varint code><varint length><digest bytes>
   https://github.com/multiformats/multihash

   Parsing and computing are deliberately separate concerns. The container
   is algorithm-agnostic, so [of_octets] accepts any code -- you can route
   a BLAKE3 multihash through this library without being able to compute
   one. [digest] is the narrow operation, and returns [Error] for an
   algorithm digestif does not provide rather than quietly substituting a
   different hash. *)

type t = { code : Multicodec.t; digest : string }

let code t = t.code
let digest_bytes t = t.digest

let make ~code ~digest =
  if String.length digest > 0x7fffffff then invalid_arg "Multihash.make: digest too long";
  { code; digest }

let to_octets t =
  Varint.write (Multicodec.to_code t.code)
  ^ Varint.write (String.length t.digest)
  ^ t.digest

(* [read s pos] parses one multihash and returns the position after it, so
   CID and multiaddr can embed one without re-slicing. *)
let read s pos =
  match Varint.read_result s pos with
  | Error m -> Error m
  | Ok (code, pos) -> (
    match Varint.read_result s pos with
    | Error m -> Error m
    | Ok (len, pos) ->
      (* the declared length must be backed by real bytes; otherwise a
         short buffer could masquerade as a long digest *)
      if len > String.length s - pos then
        Error
          (Printf.sprintf "multihash: declared length %d exceeds the %d bytes remaining" len
             (String.length s - pos))
      else Ok ({ code = Multicodec.of_code code; digest = String.sub s pos len }, pos + len))

let of_octets s =
  match read s 0 with
  | Error _ as e -> e
  | Ok (t, pos) ->
    if pos = String.length s then Ok t
    else Error "multihash: trailing bytes"

(* ---- digest computation ---- *)

let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))

module B2b_160 = Digestif.Make_BLAKE2B (struct let digest_size = 20 end)
module B2b_256 = Digestif.Make_BLAKE2B (struct let digest_size = 32 end)
module B2b_384 = Digestif.Make_BLAKE2B (struct let digest_size = 48 end)
module B2s_128 = Digestif.Make_BLAKE2S (struct let digest_size = 16 end)
module B2s_160 = Digestif.Make_BLAKE2S (struct let digest_size = 20 end)
module B2s_224 = Digestif.Make_BLAKE2S (struct let digest_size = 28 end)

(* SHAKE is an XOF: FIPS 202 gives it no default output length, so digestif
   exposes no plain [SHAKE128 : S] and the length has to be chosen here. 32 and
   64 bytes are the collision-resistance-matching sizes for the 128- and 256-bit
   security levels, and they are what go-multihash emits for these two codes, so
   a digest produced here round-trips with the rest of the ecosystem. *)
module Shake_128 = Digestif.Make_SHAKE128 (struct let digest_size = 32 end)
module Shake_256 = Digestif.Make_SHAKE256 (struct let digest_size = 64 end)

(* Codes this library can actually compute. Everything else parses fine
   but cannot be produced here. *)
let compute code s =
  match code with
  | 0x00 -> Some s (* identity: the "digest" is the input *)
  | 0x11 -> Some Digestif.SHA1.(to_raw_string (digest_string s))
  | 0x12 -> Some (sha256 s)
  | 0x13 -> Some Digestif.SHA512.(to_raw_string (digest_string s))
  | 0x14 -> Some Digestif.SHA3_512.(to_raw_string (digest_string s))
  | 0x15 -> Some Digestif.SHA3_384.(to_raw_string (digest_string s))
  | 0x16 -> Some Digestif.SHA3_256.(to_raw_string (digest_string s))
  | 0x17 -> Some Digestif.SHA3_224.(to_raw_string (digest_string s))
  | 0x18 -> Some Shake_128.(to_raw_string (digest_string s))
  | 0x19 -> Some Shake_256.(to_raw_string (digest_string s))
  | 0x1a -> Some Digestif.KECCAK_224.(to_raw_string (digest_string s))
  | 0x1b -> Some Digestif.KECCAK_256.(to_raw_string (digest_string s))
  | 0x1c -> Some Digestif.KECCAK_384.(to_raw_string (digest_string s))
  | 0x1d -> Some Digestif.KECCAK_512.(to_raw_string (digest_string s))
  | 0x20 -> Some Digestif.SHA384.(to_raw_string (digest_string s))
  | 0x56 -> Some (sha256 (sha256 s))
  | 0xd5 -> Some Digestif.MD5.(to_raw_string (digest_string s))
  | 0x1013 -> Some Digestif.SHA224.(to_raw_string (digest_string s))
  | 0x1014 -> Some Digestif.SHA512_224.(to_raw_string (digest_string s))
  | 0x1015 -> Some Digestif.SHA512_256.(to_raw_string (digest_string s))
  | 0xb214 -> Some B2b_160.(to_raw_string (digest_string s))
  | 0xb220 -> Some B2b_256.(to_raw_string (digest_string s))
  | 0xb230 -> Some B2b_384.(to_raw_string (digest_string s))
  | 0xb240 -> Some Digestif.BLAKE2B.(to_raw_string (digest_string s))
  | 0xb250 -> Some B2s_128.(to_raw_string (digest_string s))
  | 0xb254 -> Some B2s_160.(to_raw_string (digest_string s))
  | 0xb25c -> Some B2s_224.(to_raw_string (digest_string s))
  | 0xb260 -> Some Digestif.BLAKE2S.(to_raw_string (digest_string s))
  | _ -> None

let supported code = compute code "" <> None

let digest code s =
  match compute (Multicodec.to_code code) s with
  | Some d -> Ok { code; digest = d }
  | None ->
    Error
      (Printf.sprintf "multihash: cannot compute %s here (parsing it is still supported)"
         (Multicodec.to_string code))

(* [verify t s] recomputes and compares. [Error] if the algorithm is not
   one this library can compute -- an unverifiable digest must not report
   as valid. *)
let verify t s =
  match compute (Multicodec.to_code t.code) s with
  | None ->
    Error
      (Printf.sprintf "multihash: cannot verify %s here" (Multicodec.to_string t.code))
  | Some d ->
    (* a truncated multihash is legitimate, so compare the declared prefix *)
    let n = String.length t.digest in
    Ok (n <= String.length d && String.equal t.digest (String.sub d 0 n))

let to_string t =
  Printf.sprintf "%s-%d-%s" (Multicodec.to_string t.code) (String.length t.digest)
    (Base16.encode t.digest)
