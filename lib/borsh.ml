(* Borsh (Binary Object Representation Serializer for Hashing), the
   deterministic little-endian codec used by Solana and NEAR.
   https://borsh.io/

   Layout: fixed-width integers little-endian; bool as one byte; Option
   as a 1-byte tag (0/1) then the value; Vec<T>/String as a u32 length
   prefix then the elements/UTF-8 bytes; fixed arrays as the bare
   elements; enums as a u8 discriminant then the variant payload. *)

(* ---- encoders ---- *)

let le nbytes z =
  String.init nbytes (fun i ->
      Char.chr (Z.to_int (Z.logand (Z.shift_right z (8 * i)) (Z.of_int 0xff))))

(* two's-complement little-endian for signed values *)
let le_signed nbytes z =
  let mask = Z.sub (Z.shift_left Z.one (8 * nbytes)) Z.one in
  le nbytes (Z.logand z mask)

let encode_u8 n = String.make 1 (Char.chr (n land 0xff))
let encode_u16 n = le 2 (Z.of_int n)
let encode_u32 n = le 4 (Z.of_int n)
let encode_u64 z = le 8 z
let encode_u128 z = le 16 z
let encode_i8 n = le_signed 1 (Z.of_int n)
let encode_i16 n = le_signed 2 (Z.of_int n)
let encode_i32 n = le_signed 4 (Z.of_int n)
let encode_i64 z = le_signed 8 z
let encode_i128 z = le_signed 16 z

let encode_bool b = if b then "\001" else "\000"

let encode_option enc = function
  | None -> "\000"
  | Some x -> "\001" ^ enc x

(* Vec<u8> / String: u32 length prefix then the raw bytes. *)
let encode_bytes s = encode_u32 (String.length s) ^ s
let encode_string = encode_bytes

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

let read_u8 s pos =
  need s pos 1;
  (Char.code s.[pos], pos + 1)

let read_u16 s pos = need s pos 2; (Z.to_int (z_of_le s pos 2), pos + 2)
let read_u32 s pos = need s pos 4; (Z.to_int (z_of_le s pos 4), pos + 4)
let read_u64 s pos = need s pos 8; (z_of_le s pos 8, pos + 8)
let read_u128 s pos = need s pos 16; (z_of_le s pos 16, pos + 16)

let read_bool s pos =
  let b, pos = read_u8 s pos in
  match b with 0 -> (false, pos) | 1 -> (true, pos) | _ -> raise (Error "borsh: invalid bool")

let read_bytes s pos =
  let len, pos = read_u32 s pos in
  need s pos len;
  (String.sub s pos len, pos + len)

let read_string = read_bytes

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
