(* SCALE (Simple Concatenated Aggregate Little-Endian), the codec used by
   Substrate / Polkadot.
   https://docs.substrate.io/reference/scale-codec/

   Compact integers have exactly one valid spelling per value, and decoding
   enforces that: accepting a longer-than-necessary encoding would let two
   distinct extrinsics carry the same arguments and hash differently.

   The fixed-width encoders range-check their argument and raise
   [Invalid_argument] rather than truncating it, so an out-of-range balance
   fails loudly instead of being silently reduced mod 2^n. *)

(* ---- fixed-width little-endian unsigned integers ---- *)

let le_fixed nbytes z =
  String.init nbytes (fun i ->
      Char.chr (Z.to_int (Z.logand (Z.shift_right z (8 * i)) (Z.of_int 0xff))))

let check_range name nbits z =
  if Z.sign z < 0 then
    invalid_arg (Printf.sprintf "Scale.%s: negative value" name);
  if Z.numbits z > nbits then
    invalid_arg (Printf.sprintf "Scale.%s: value does not fit %d bits" name nbits)

let encode_u8 n = check_range "encode_u8" 8 (Z.of_int n); String.make 1 (Char.chr n)
let encode_u16 n = check_range "encode_u16" 16 (Z.of_int n); le_fixed 2 (Z.of_int n)
let encode_u32 n = check_range "encode_u32" 32 (Z.of_int n); le_fixed 4 (Z.of_int n)
let encode_u64 z = check_range "encode_u64" 64 z; le_fixed 8 z
let encode_u128 z = check_range "encode_u128" 128 z; le_fixed 16 z

let z_of_le s =
  let acc = ref Z.zero in
  for i = String.length s - 1 downto 0 do
    acc := Z.logor (Z.shift_left !acc 8) (Z.of_int (Char.code s.[i]))
  done;
  !acc

(* ---- compact / general integers ----

   Two low bits of the first byte select the mode:
   0b00 single byte, value = b >> 2                       (0 .. 2^6-1)
   0b01 two bytes LE, value = u16 >> 2                    (.. 2^14-1)
   0b10 four bytes LE, value = u32 >> 2                   (.. 2^30-1)
   0b11 big-integer: first byte >> 2 is (len-4), then len LE value bytes

   Each mode has a disjoint value range, so the mode is determined by the
   value and every value has a single encoding. *)

let compact_max_bytes = 67

let encode_compact z =
  if Z.sign z < 0 then invalid_arg "Scale.encode_compact: negative value";
  if Z.lt z (Z.of_int 0x40) then encode_u8 (Z.to_int z lsl 2)
  else if Z.lt z (Z.of_int 0x4000) then le_fixed 2 (Z.logor (Z.shift_left z 2) Z.one)
  else if Z.lt z (Z.shift_left Z.one 30) then
    le_fixed 4 (Z.logor (Z.shift_left z 2) (Z.of_int 2))
  else begin
    let nbytes = (Z.numbits z + 7) / 8 in
    if nbytes > compact_max_bytes then invalid_arg "Scale.encode_compact: value too large";
    encode_u8 (((nbytes - 4) lsl 2) lor 3) ^ le_fixed nbytes z
  end

exception Error of string

(* [read_compact s pos] decodes one compact integer, returning it and the
   position just past it. Encodings outside their mode's value range are
   rejected: "01 00" spells zero in two-byte mode, but zero's only valid
   encoding is "00". *)
let read_compact s pos =
  let n = String.length s in
  if pos >= n then raise (Error "scale: truncated compact");
  let b0 = Char.code s.[pos] in
  match b0 land 0b11 with
  | 0 -> (Z.of_int (b0 lsr 2), pos + 1)
  | 1 ->
    if pos + 2 > n then raise (Error "scale: truncated compact (2-byte)");
    let v = (((Char.code s.[pos + 1]) lsl 8) lor b0) lsr 2 in
    if v < 0x40 then raise (Error "scale: non-canonical compact (fits one byte)");
    (Z.of_int v, pos + 2)
  | 2 ->
    if pos + 4 > n then raise (Error "scale: truncated compact (4-byte)");
    let v = ref 0 in
    for i = 0 to 3 do
      v := !v lor (Char.code s.[pos + i] lsl (8 * i))
    done;
    let v = !v lsr 2 in
    if v < 0x4000 then raise (Error "scale: non-canonical compact (fits two bytes)");
    (Z.of_int v, pos + 4)
  | _ ->
    let nbytes = (b0 lsr 2) + 4 in
    if pos + 1 + nbytes > n then raise (Error "scale: truncated compact (big)");
    (* little-endian, so the most significant byte is the last one; a zero
       there means the value was padded out to a longer encoding *)
    if Char.code s.[pos + nbytes] = 0 then
      raise (Error "scale: non-canonical compact (leading zero byte)");
    let v = z_of_le (String.sub s (pos + 1) nbytes) in
    if Z.lt v (Z.shift_left Z.one 30) then
      raise (Error "scale: non-canonical compact (fits four bytes)");
    (v, pos + 1 + nbytes)

let compact_of_octets s =
  match read_compact s 0 with
  | v, pos -> if pos = String.length s then Ok v else Error "scale: trailing bytes"
  | exception Error m -> Error m

(* ---- common composite encoders ---- *)

let encode_bool b = if b then "\001" else "\000"

let encode_option enc = function
  | None -> "\000"
  | Some x -> "\001" ^ enc x

(* Vec<u8> / [Bytes] / [Text]: compact length prefix then the raw bytes. *)
let encode_bytes s = encode_compact (Z.of_int (String.length s)) ^ s
let encode_string = encode_bytes

(* Vec<T>: compact count then each element. *)
let encode_vec enc xs =
  encode_compact (Z.of_int (List.length xs)) ^ String.concat "" (List.map enc xs)

let read_bytes s pos =
  let len, pos = read_compact s pos in
  (* a compact can spell a length far beyond [max_int]; comparing as a Z
     avoids [Z.to_int] raising out of a function whose callers expect a
     [result] *)
  if Z.gt len (Z.of_int (String.length s)) then
    raise (Error "scale: length exceeds input");
  let len = Z.to_int len in
  if pos + len > String.length s then raise (Error "scale: truncated bytes");
  (String.sub s pos len, pos + len)

let bytes_of_octets s =
  match read_bytes s 0 with
  | v, pos -> if pos = String.length s then Ok v else Error "scale: trailing bytes"
  | exception Error m -> Error m
