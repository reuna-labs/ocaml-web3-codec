(* CBOR (RFC 8949).

   Two rules shape the whole file. The encoder emits exactly one spelling per
   profile, so that anything it produces can be compared byte for byte. The
   decoder accepts every well-formed spelling, because a chain will send them,
   but refuses the ones that are genuinely ambiguous -- duplicate map keys, and
   bignums with leading zeros -- rather than picking a winner.

   No bignum library. Arbitrary-precision integers are carried as big-endian
   magnitudes and never arithmetic'd on, which is what lets an Ed25519-only
   consumer link this into a unikernel without GMP. *)

type fwidth = Half | Single | Double

type t =
  | Uint of int64
  | Nint of int64
  | Big of { negative : bool; magnitude : string }
  | Bytes of string
  | Text of string
  | Array of t list
  | Map of (t * t) list
  | Tag of int * t
  | Bool of bool
  | Null
  | Undefined
  | Simple of int
  | Float of fwidth * float

exception Error of string

let err fmt = Printf.ksprintf (fun s -> raise (Error s)) fmt

type limits = {
  max_input_bytes : int;
  max_nesting : int;
  max_items : int;
  max_string_bytes : int;
}

let default_limits =
  {
    max_input_bytes = 16 * 1024 * 1024;
    max_nesting = 128;
    max_items = 1_000_000;
    max_string_bytes = 8 * 1024 * 1024;
  }

type profile = Canonical | Rfc7049
type span = { off : int; len : int }

(* ---- unsigned helpers ---------------------------------------------------- *)

(* Int64 compare treats the sign bit as a sign; for a CBOR head argument it is
   just bit 63. *)
let ucompare a b = Int64.unsigned_compare a b
let ult a b = ucompare a b < 0
let uint v = Uint v

let uint_of_int n =
  if n < 0 then invalid_arg "Web3_codec_cbor.uint_of_int: negative";
  Uint (Int64.of_int n)

let uint_to_string v = Printf.sprintf "%Lu" v

(* ---- encoding ------------------------------------------------------------ *)

(* A CBOR head is the major type in the top three bits plus a five-bit
   argument, with the shortest of the five widths that fits. Emitting anything
   longer is legal CBOR and non-deterministic, so it never happens here. *)
let put_head buf major arg =
  let m = major lsl 5 in
  if ult arg 24L then Buffer.add_char buf (Char.chr (m lor Int64.to_int arg))
  else if ult arg 0x100L then (
    Buffer.add_char buf (Char.chr (m lor 24));
    Buffer.add_char buf (Char.chr (Int64.to_int arg land 0xff)))
  else if ult arg 0x10000L then (
    Buffer.add_char buf (Char.chr (m lor 25));
    Buffer.add_uint16_be buf (Int64.to_int arg land 0xffff))
  else if ult arg 0x100000000L then (
    Buffer.add_char buf (Char.chr (m lor 26));
    Buffer.add_int32_be buf (Int64.to_int32 arg))
  else (
    Buffer.add_char buf (Char.chr (m lor 27));
    Buffer.add_int64_be buf arg)

let check_magnitude m =
  if String.length m > 0 && m.[0] = '\000' then
    invalid_arg
      "Web3_codec_cbor.encode: bignum magnitude has a leading zero byte, which \
       would give one integer two spellings"

let float_bits w f =
  match w with
  | Double -> Int64.bits_of_float f
  | Single -> Int64.of_int32 (Int32.bits_of_float f) |> Int64.logand 0xffffffffL
  | Half ->
      (* Encode via the single-precision bit pattern: every half value is
         exactly representable as a float, so this is lossless in the direction
         that matters -- a value we decoded from a half and are writing back. *)
      let b = Int32.bits_of_float f in
      let b = Int32.to_int b land 0xffffffff in
      let sign = (b lsr 16) land 0x8000 in
      let exp = (b lsr 23) land 0xff in
      let mant = b land 0x7fffff in
      if exp = 0xff then
        Int64.of_int (sign lor 0x7c00 lor if mant <> 0 then 0x200 else 0)
      else
        let e = exp - 127 + 15 in
        if e >= 0x1f then Int64.of_int (sign lor 0x7c00)
        else if e <= 0 then Int64.of_int sign
        else Int64.of_int (sign lor (e lsl 10) lor (mant lsr 13))

let rec put buf profile v =
  match v with
  | Uint n -> put_head buf 0 n
  | Nint n -> put_head buf 1 n
  | Big { negative; magnitude } ->
      check_magnitude magnitude;
      put_head buf 6 (if negative then 3L else 2L);
      put_head buf 2 (Int64.of_int (String.length magnitude));
      Buffer.add_string buf magnitude
  | Bytes s ->
      put_head buf 2 (Int64.of_int (String.length s));
      Buffer.add_string buf s
  | Text s ->
      put_head buf 3 (Int64.of_int (String.length s));
      Buffer.add_string buf s
  | Array xs ->
      put_head buf 4 (Int64.of_int (List.length xs));
      List.iter (put buf profile) xs
  | Map kvs ->
      put_head buf 5 (Int64.of_int (List.length kvs));
      List.iter
        (fun (k, v) ->
          Buffer.add_string buf k;
          put buf profile v)
        (sorted_pairs profile kvs)
  | Tag (n, x) ->
      if n < 0 then invalid_arg "Web3_codec_cbor.encode: negative tag";
      if n = 2 || n = 3 then
        invalid_arg
          "Web3_codec_cbor.encode: tags 2 and 3 are bignums; use Big so that \
           one integer keeps one spelling";
      put_head buf 6 (Int64.of_int n);
      put buf profile x
  | Bool false -> Buffer.add_char buf '\244'
  | Bool true -> Buffer.add_char buf '\245'
  | Null -> Buffer.add_char buf '\246'
  | Undefined -> Buffer.add_char buf '\247'
  | Simple n ->
      if n < 0 || n > 255 || (n >= 20 && n <= 31) then
        invalid_arg
          (Printf.sprintf
             "Web3_codec_cbor.encode: simple value %d is reserved or not \
              well-formed"
             n);
      put_head buf 7 (Int64.of_int n)
  | Float (w, f) ->
      let ai, bits = match w with Half -> (25, 2) | Single -> (26, 4) | Double -> (27, 8) in
      Buffer.add_char buf (Char.chr ((7 lsl 5) lor ai));
      let v = float_bits w f in
      for i = bits - 1 downto 0 do
        Buffer.add_char buf (Char.chr (Int64.to_int (Int64.shift_right_logical v (8 * i)) land 0xff))
      done

(* Keys are compared by their encoded bytes, which is what both orderings are
   defined over. Encoding each key once and keeping the string also means the
   sort does not re-encode on every comparison. *)
and sorted_pairs profile kvs =
  let encoded =
    List.map
      (fun (k, v) ->
        let b = Buffer.create 16 in
        put b profile k;
        (Buffer.contents b, v))
      kvs
  in
  let cmp (a, _) (b, _) =
    match profile with
    | Canonical -> String.compare a b
    | Rfc7049 ->
        let la = String.length a and lb = String.length b in
        if la <> lb then compare la lb else String.compare a b
  in
  List.stable_sort cmp encoded

let encode ?(profile = Canonical) v =
  let buf = Buffer.create 64 in
  put buf profile v;
  Buffer.contents buf

let encode_exn = encode

let compare_canonical a b =
  String.compare (encode ~profile:Canonical a) (encode ~profile:Canonical b)

(* ---- decoding ------------------------------------------------------------ *)

type st = { s : string; lim : limits; mutable items : int }

let need st pos n =
  if n < 0 || pos + n > String.length st.s then
    err "cbor: truncated: want %d bytes at %d of %d" n pos (String.length st.s)

let u8 st pos = need st pos 1; Char.code st.s.[pos]

let take st pos n =
  (* The length is a claim by the sender until it is checked against what is
     actually there. Check first, allocate second. *)
  if n > st.lim.max_string_bytes then
    err "cbor: string of %d bytes exceeds the %d-byte limit" n st.lim.max_string_bytes;
  need st pos n;
  String.sub st.s pos n

let count st n =
  st.items <- st.items + n;
  if st.items > st.lim.max_items then
    err "cbor: more than %d items" st.lim.max_items

(* Returns the argument and the position after the head. [None] for the
   indefinite-length marker (additional info 31), which is well-formed for
   majors 2-5 and 7 only. *)
let head st pos =
  let b = u8 st pos in
  let major = b lsr 5 and ai = b land 0x1f in
  if ai < 24 then (major, Some (Int64.of_int ai), pos + 1)
  else if ai = 24 then (major, Some (Int64.of_int (u8 st (pos + 1))), pos + 2)
  else if ai = 25 then (
    need st (pos + 1) 2;
    (major, Some (Int64.of_int (String.get_uint16_be st.s (pos + 1))), pos + 3))
  else if ai = 26 then (
    need st (pos + 1) 4;
    let v = Int64.logand (Int64.of_int32 (String.get_int32_be st.s (pos + 1))) 0xffffffffL in
    (major, Some v, pos + 5))
  else if ai = 27 then (
    need st (pos + 1) 8;
    (major, Some (String.get_int64_be st.s (pos + 1)), pos + 9))
  else if ai = 31 then (major, None, pos + 1)
  else err "cbor: additional information %d is not well-formed" ai

let arg_to_int _st what = function
  | None -> err "cbor: %s needs a definite length here" what
  | Some n ->
      if ult n (Int64.of_int max_int) then Int64.to_int n
      else err "cbor: %s length %s does not fit in this runtime" what (uint_to_string n)

let half_to_float bits =
  let sign = if bits land 0x8000 <> 0 then -1.0 else 1.0 in
  let exp = (bits lsr 10) land 0x1f and mant = bits land 0x3ff in
  if exp = 0 then sign *. ldexp (float_of_int mant) (-24)
  else if exp = 0x1f then if mant = 0 then sign *. infinity else Float.nan
  else sign *. ldexp (float_of_int (mant + 1024)) (exp - 25)

(* Duplicate detection is on encoded keys, so that two spellings of the same
   integer still collide. *)
module Keyset = Set.Make (String)

let rec value st depth pos =
  if depth > st.lim.max_nesting then
    err "cbor: nested deeper than %d" st.lim.max_nesting;
  let major, arg, p = head st pos in
  match major with
  | 0 -> (Uint (arg_or () arg), p)
  | 1 -> (Nint (arg_or () arg), p)
  | 2 -> string_like st arg p (fun s -> Bytes s) 2
  | 3 -> string_like st arg p (fun s -> Text s) 3
  | 4 -> (
      match arg with
      | Some _ ->
          let n = arg_to_int () "array" arg in
          count st n;
          let rec go i acc p = if i = 0 then (List.rev acc, p)
            else let v, p = value st (depth + 1) p in go (i - 1) (v :: acc) p
          in
          let xs, p = go n [] p in
          (Array xs, p)
      | None ->
          let rec go acc p =
            if u8 st p = 0xff then (List.rev acc, p + 1)
            else (count st 1; let v, p = value st (depth + 1) p in go (v :: acc) p)
          in
          let xs, p = go [] p in
          (Array xs, p))
  | 5 ->
      let seen = ref Keyset.empty in
      let pair p =
        let k, p = value st (depth + 1) p in
        let enc = encode k in
        if Keyset.mem enc !seen then
          err
            "cbor: duplicate map key -- a decoder that accepts one lets a \
             sender show different values to different readers";
        seen := Keyset.add enc !seen;
        let v, p = value st (depth + 1) p in
        ((k, v), p)
      in
      (match arg with
      | Some _ ->
          let n = arg_to_int () "map" arg in
          count st n;
          let rec go i acc p = if i = 0 then (List.rev acc, p)
            else let kv, p = pair p in go (i - 1) (kv :: acc) p
          in
          let kvs, p = go n [] p in
          (Map kvs, p)
      | None ->
          let rec go acc p =
            if u8 st p = 0xff then (List.rev acc, p + 1)
            else (count st 1; let kv, p = pair p in go (kv :: acc) p)
          in
          let kvs, p = go [] p in
          (Map kvs, p))
  | 6 -> (
      let n = arg_or () arg in
      let inner, p = value st (depth + 1) p in
      match (n, inner) with
      | (2L | 3L), Bytes m ->
          if String.length m > 0 && m.[0] = '\000' then
            err "cbor: bignum magnitude has a leading zero byte";
          (Big { negative = n = 3L; magnitude = m }, p)
      | (2L | 3L), _ -> err "cbor: bignum tag must wrap a byte string"
      | _ ->
          if not (ult n (Int64.of_int max_int)) then
            err "cbor: tag %s does not fit in this runtime" (uint_to_string n);
          (Tag (Int64.to_int n, inner), p))
  | 7 -> (
      let b = Char.code st.s.[pos] land 0x1f in
      match b with
      | 20 -> (Bool false, p)
      | 21 -> (Bool true, p)
      | 22 -> (Null, p)
      | 23 -> (Undefined, p)
      | 25 -> (Float (Half, half_to_float (Int64.to_int (arg_or () arg))), p)
      | 26 ->
          ( Float (Single, Int32.float_of_bits (Int64.to_int32 (arg_or () arg))),
            p )
      | 27 -> (Float (Double, Int64.float_of_bits (arg_or () arg)), p)
      | 31 -> err "cbor: unexpected break"
      | _ ->
          let n = Int64.to_int (arg_or () arg) in
          if n >= 24 && n <= 31 then
            err "cbor: simple value %d is not well-formed" n;
          (Simple n, p))
  | _ -> err "cbor: impossible major type %d" major

and arg_or _st = function
  | Some n -> n
  | None -> err "cbor: indefinite length is not valid here"

(* An indefinite-length string is a sequence of definite-length chunks of the
   same major type, concatenated. The chunking is a transport detail and is not
   preserved in the value; callers who need the original bytes keep the span. *)
and string_like st arg p mk major =
  match arg with
  | Some _ ->
      let n = arg_to_int () "string" arg in
      (mk (take st p n), p + n)
  | None ->
      let buf = Buffer.create 64 in
      let rec go p =
        if u8 st p = 0xff then p + 1
        else
          let m, a, q = head st p in
          if m <> major then err "cbor: chunk of the wrong major type";
          let n = arg_to_int () "chunk" a in
          if Buffer.length buf + n > st.lim.max_string_bytes then
            err "cbor: chunked string exceeds the %d-byte limit"
              st.lim.max_string_bytes;
          Buffer.add_string buf (take st q n);
          go (q + n)
      in
      let p = go p in
      (mk (Buffer.contents buf), p)

let mk_state ?(limits = default_limits) s =
  if String.length s > limits.max_input_bytes then
    err "cbor: input of %d bytes exceeds the %d-byte limit" (String.length s)
      limits.max_input_bytes;
  { s; lim = limits; items = 0 }

let read ?limits s pos =
  let st = mk_state ?limits s in
  value st 0 pos

let read_span ?limits s pos =
  let st = mk_state ?limits s in
  let v, p = value st 0 pos in
  (v, { off = pos; len = p - pos }, p)

let of_octets ?limits s =
  match read ?limits s 0 with
  | v, p when p = String.length s -> Ok v
  | _, p -> Error (Printf.sprintf "cbor: %d trailing bytes" (String.length s - p))
  | exception Error m -> Error m

let is_canonical ?(profile = Canonical) s =
  match of_octets s with
  | Ok v -> ( try String.equal (encode ~profile v) s with Invalid_argument _ -> false)
  | Error _ -> false

let int_value = function
  | Uint n -> if ult n (Int64.of_int max_int) then Some (Int64.to_int n) else None
  | Nint n ->
      if ult n (Int64.of_int max_int) then Some (-1 - Int64.to_int n) else None
  | Big { negative; magnitude } ->
      if String.length magnitude > 7 then None
      else
        let v = String.fold_left (fun a c -> (a lsl 8) lor Char.code c) 0 magnitude in
        Some (if negative then -1 - v else v)
  | _ -> None
