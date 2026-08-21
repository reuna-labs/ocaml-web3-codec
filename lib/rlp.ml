(* RLP (Recursive Length Prefix), Ethereum's structural serialization for
   transactions, receipts and trie nodes.
   https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/

   Decoding is strict about canonical form: a value has exactly one valid
   encoding, so re-encoding whatever [decode] returns reproduces the input
   bytes. That property is what makes an RLP hash meaningful, so every
   non-canonical spelling is rejected rather than accepted leniently. *)

type t =
  | Str of string
  | List of t list

(* Ethereum's RLP never nests anywhere near this deep; the bound exists so
   that adversarial input cannot drive unbounded recursion. *)
let max_depth = 1024

(* Minimal big-endian encoding of a non-negative integer; 0 -> "" (RLP
   encodes scalars without leading zero bytes, so zero is the empty
   string). *)
let be_of_z z =
  if Z.sign z < 0 then
    invalid_arg "Rlp.of_z: RLP has no representation for negative integers";
  if Z.sign z = 0 then ""
  else begin
    let n = (Z.numbits z + 7) / 8 in
    String.init n (fun i ->
        Char.chr (Z.to_int (Z.logand (Z.shift_right z (8 * (n - 1 - i))) (Z.of_int 0xff))))
  end

let z_of_be s =
  String.fold_left (fun acc c -> Z.add (Z.mul acc (Z.of_int 256)) (Z.of_int (Char.code c))) Z.zero s

let of_z z = Str (be_of_z z)
let of_int n = of_z (Z.of_int n)
let of_string s = Str s

let to_string = function
  | Str s -> Ok s
  | List _ -> Error "rlp: expected a string, got a list"

let to_z = function
  | Str s -> Ok (z_of_be s)
  | List _ -> Error "rlp: expected a string, got a list"

(* [prefix off len] is the RLP length header for a payload of [len] bytes,
   [off] being 0x80 for strings / 0xc0 for lists. *)
let prefix off len =
  if len < 56 then String.make 1 (Char.chr (off + len))
  else
    let lb = be_of_z (Z.of_int len) in
    String.make 1 (Char.chr (off + 55 + String.length lb)) ^ lb

let rec encode = function
  | Str s ->
    if String.length s = 1 && Char.code s.[0] < 0x80 then s
    else prefix 0x80 (String.length s) ^ s
  | List items ->
    let payload = String.concat "" (List.map encode items) in
    prefix 0xc0 (String.length payload) ^ payload

exception Error of string

let decode s =
  let n = String.length s in
  let need pos count =
    if count < 0 || pos + count > n then raise (Error "rlp: truncated input")
  in
  (* A length field is at most 8 bytes, which does not fit an OCaml int.
     Accumulating unguarded lets 0x8000000000000064 wrap to 100, so that
     "ff 80 00 00 00 00 00 00 64" and the canonical "f8 64" decode to the
     same value -- a malleability break. Bailing as soon as the running
     value passes the input length keeps the accumulator far below the
     overflow point and rejects the long spelling outright. *)
  let read_len pos count =
    need pos count;
    if count = 0 then raise (Error "rlp: empty length field");
    if Char.code s.[pos] = 0 then raise (Error "rlp: leading zero in length");
    let v = ref 0 in
    for i = 0 to count - 1 do
      v := (!v lsl 8) lor Char.code s.[pos + i];
      if !v > n then raise (Error "rlp: length exceeds input")
    done;
    !v
  in
  let rec item pos depth =
    if depth > max_depth then raise (Error "rlp: nesting too deep");
    need pos 1;
    let b = Char.code s.[pos] in
    if b < 0x80 then (Str (String.sub s pos 1), pos + 1)
    else if b < 0xb8 then begin
      let len = b - 0x80 in
      need (pos + 1) len;
      if len = 1 && Char.code s.[pos + 1] < 0x80 then
        raise (Error "rlp: single byte encoded with a length prefix");
      (Str (String.sub s (pos + 1) len), pos + 1 + len)
    end
    else if b < 0xc0 then begin
      let nl = b - 0xb7 in
      let len = read_len (pos + 1) nl in
      if len < 56 then raise (Error "rlp: long form used for a short string");
      need (pos + 1 + nl) len;
      (Str (String.sub s (pos + 1 + nl) len), pos + 1 + nl + len)
    end
    else if b < 0xf8 then begin
      let len = b - 0xc0 in
      need (pos + 1) len;
      (List (items_in (pos + 1) (pos + 1 + len) depth), pos + 1 + len)
    end
    else begin
      let nl = b - 0xf7 in
      let len = read_len (pos + 1) nl in
      if len < 56 then raise (Error "rlp: long form used for a short list");
      need (pos + 1 + nl) len;
      (List (items_in (pos + 1 + nl) (pos + 1 + nl + len) depth), pos + 1 + nl + len)
    end
  (* accumulate rather than recurse per item, so a long list costs heap
     rather than stack *)
  and items_in pos stop depth =
    let rec go pos acc =
      if pos = stop then List.rev acc
      else if pos > stop then raise (Error "rlp: item overruns its list")
      else
        let it, pos' = item pos (depth + 1) in
        go pos' (it :: acc)
    in
    go pos []
  in
  match item 0 0 with
  | v, pos -> if pos = n then Ok v else Error "rlp: trailing bytes after value"
  | exception Error m -> Error m
