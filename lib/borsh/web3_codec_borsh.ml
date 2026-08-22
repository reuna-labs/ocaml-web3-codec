(* Borsh (Binary Object Representation Serializer for Hashing), the
   deterministic little-endian codec used by Solana and NEAR.
   https://borsh.io/

   Layout: fixed-width integers little-endian; bool as one byte; Option
   as a 1-byte tag (0/1) then the value; Vec<T>/String as a u32 length
   prefix then the elements/UTF-8 bytes; fixed arrays as the bare
   elements; enums as a u8 discriminant then the variant payload.

   Borsh exists to be deterministic -- it is the input to hashes and
   signatures -- so the encoders range-check and raise [Invalid_argument]
   rather than truncating, and the decoders reject any spelling that the
   encoders would not produce. *)

(* ---- encoders ---- *)

let le nbytes z =
  String.init nbytes (fun i ->
      Char.chr (Z.to_int (Z.logand (Z.shift_right z (8 * i)) (Z.of_int 0xff))))

(* two's-complement little-endian for signed values *)
let le_signed nbytes z =
  let mask = Z.sub (Z.shift_left Z.one (8 * nbytes)) Z.one in
  le nbytes (Z.logand z mask)

let check_u name nbits z =
  if Z.sign z < 0 then invalid_arg (Printf.sprintf "Borsh.%s: negative value" name);
  if Z.numbits z > nbits then
    invalid_arg (Printf.sprintf "Borsh.%s: value does not fit u%d" name nbits)

let check_s name nbits z =
  let half = Z.shift_left Z.one (nbits - 1) in
  if Z.geq z half || Z.lt z (Z.neg half) then
    invalid_arg (Printf.sprintf "Borsh.%s: value does not fit i%d" name nbits)

let encode_u8 n = check_u "encode_u8" 8 (Z.of_int n); String.make 1 (Char.chr n)
let encode_u16 n = check_u "encode_u16" 16 (Z.of_int n); le 2 (Z.of_int n)
let encode_u32 n = check_u "encode_u32" 32 (Z.of_int n); le 4 (Z.of_int n)
let encode_u64 z = check_u "encode_u64" 64 z; le 8 z
let encode_u128 z = check_u "encode_u128" 128 z; le 16 z
let encode_i8 n = check_s "encode_i8" 8 (Z.of_int n); le_signed 1 (Z.of_int n)
let encode_i16 n = check_s "encode_i16" 16 (Z.of_int n); le_signed 2 (Z.of_int n)
let encode_i32 n = check_s "encode_i32" 32 (Z.of_int n); le_signed 4 (Z.of_int n)
let encode_i64 z = check_s "encode_i64" 64 z; le_signed 8 z
let encode_i128 z = check_s "encode_i128" 128 z; le_signed 16 z

let encode_bool b = if b then "\001" else "\000"

let encode_option enc = function
  | None -> "\000"
  | Some x -> "\001" ^ enc x

(* Vec<u8> / String: u32 length prefix then the raw bytes. *)
let encode_bytes s = encode_u32 (String.length s) ^ s

(* Borsh strings are UTF-8 by definition; encoding arbitrary bytes as one
   would produce something no conforming decoder accepts. Use
   [encode_bytes] for opaque byte strings. *)
let is_valid_utf8 s =
  let n = String.length s in
  let rec go i =
    i >= n
    ||
    let d = String.get_utf_8_uchar s i in
    Uchar.utf_decode_is_valid d && go (i + Uchar.utf_decode_length d)
  in
  go 0

let encode_string s =
  if not (is_valid_utf8 s) then invalid_arg "Borsh.encode_string: not valid UTF-8";
  encode_bytes s

let encode_vec enc xs =
  encode_u32 (List.length xs) ^ String.concat "" (List.map enc xs)

(* [T; N] fixed array: bare concatenation, no length prefix. *)
let encode_fixed_array enc xs = String.concat "" (List.map enc xs)

(* enum: u8 discriminant then the variant payload. *)
let encode_enum ~variant payload = encode_u8 variant ^ payload

(* ---- decoders (reader style: [read_* s pos] -> (value, next_pos)) ---- *)

exception Error of string

let z_of_le s off n =
  let acc = ref Z.zero in
  for i = n - 1 downto 0 do
    acc := Z.logor (Z.shift_left !acc 8) (Z.of_int (Char.code s.[off + i]))
  done;
  !acc

let need s pos n = if pos + n > String.length s then raise (Error "borsh: truncated input")

let signed nbits z =
  let half = Z.shift_left Z.one (nbits - 1) in
  if Z.geq z half then Z.sub z (Z.shift_left Z.one nbits) else z

let read_u8 s pos =
  need s pos 1;
  (Char.code s.[pos], pos + 1)

let read_u16 s pos = need s pos 2; (Z.to_int (z_of_le s pos 2), pos + 2)
let read_u32 s pos = need s pos 4; (Z.to_int (z_of_le s pos 4), pos + 4)
let read_u64 s pos = need s pos 8; (z_of_le s pos 8, pos + 8)
let read_u128 s pos = need s pos 16; (z_of_le s pos 16, pos + 16)

let read_i8 s pos = need s pos 1; (Z.to_int (signed 8 (z_of_le s pos 1)), pos + 1)
let read_i16 s pos = need s pos 2; (Z.to_int (signed 16 (z_of_le s pos 2)), pos + 2)
let read_i32 s pos = need s pos 4; (Z.to_int (signed 32 (z_of_le s pos 4)), pos + 4)
let read_i64 s pos = need s pos 8; (signed 64 (z_of_le s pos 8), pos + 8)
let read_i128 s pos = need s pos 16; (signed 128 (z_of_le s pos 16), pos + 16)

let read_bool s pos =
  let b, pos = read_u8 s pos in
  match b with 0 -> (false, pos) | 1 -> (true, pos) | _ -> raise (Error "borsh: invalid bool")

let read_bytes s pos =
  let len, pos = read_u32 s pos in
  need s pos len;
  (String.sub s pos len, pos + len)

let read_string s pos =
  let v, pos = read_bytes s pos in
  if not (is_valid_utf8 v) then raise (Error "borsh: string is not valid UTF-8");
  (v, pos)

let read_option read_v s pos =
  let tag, pos = read_u8 s pos in
  match tag with
  | 0 -> (None, pos)
  | 1 ->
    let v, pos = read_v s pos in
    (Some v, pos)
  | _ -> raise (Error "borsh: invalid option tag")

let read_vec read_v s pos =
  let len, pos = read_u32 s pos in
  (* every reader here consumes at least one byte, so a count larger than
     the bytes remaining cannot be satisfied -- reject it up front instead
     of looping [len] times to discover that *)
  if len > String.length s - pos then raise (Error "borsh: vec longer than input");
  let rec go i pos acc =
    if i = 0 then (List.rev acc, pos)
    else
      let v, pos = read_v s pos in
      go (i - 1) pos (v :: acc)
  in
  go len pos []

(* run a reader over a whole buffer, requiring it to be fully consumed *)
let of_octets read s =
  match read s 0 with
  | v, pos -> if pos = String.length s then Ok v else Error "borsh: trailing bytes"
  | exception Error m -> Error m
