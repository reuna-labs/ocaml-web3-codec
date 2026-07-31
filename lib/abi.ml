(* Ethereum Contract ABI encoding, the head/tail scheme used for
   function call data and event/return values.
   https://docs.soliditylang.org/en/latest/abi-spec.html

   Function selectors use keccak256 (Ethereum's pre-NIST Keccak padding),
   taken here from digestif's [KECCAK_256]. *)

type value =
  | Uint of Z.t
  | Int of Z.t
  | Bool of bool
  | Address of string       (* 20 bytes *)
  | FixedBytes of string    (* bytesN, 1..32 bytes, left-aligned *)
  | Bytes of string         (* dynamic *)
  | String of string
  | Array of value list     (* T[] *)
  | FixedArray of value list (* T[k] *)
  | Tuple of value list

type ty =
  | TUint of int
  | TInt of int
  | TBool
  | TAddress
  | TFixedBytes of int
  | TBytes
  | TString
  | TArray of ty
  | TFixedArray of ty * int
  | TTuple of ty list

(* ---- shared helpers ---- *)

let z_of_be s =
  String.fold_left (fun acc c -> Z.add (Z.mul acc (Z.of_int 256)) (Z.of_int (Char.code c))) Z.zero s

let two256 = Z.shift_left Z.one 256

(* 32-byte big-endian, two's complement (so negatives sign-extend). *)
let word_of_z z =
  let m = Z.erem z two256 in
  String.init 32 (fun i ->
      Char.chr (Z.to_int (Z.logand (Z.shift_right m (8 * (31 - i))) (Z.of_int 0xff))))

let pad_right32 s =
  let r = String.length s mod 32 in
  if r = 0 then s else s ^ String.make (32 - r) '\000'

(* ---- encoding ---- *)

let rec is_dynamic = function
  | Bytes _ | String _ | Array _ -> true
  | FixedArray vs | Tuple vs -> List.exists is_dynamic vs
  | _ -> false

let rec enc = function
  | Uint z | Int z -> word_of_z z
  | Bool b -> word_of_z (if b then Z.one else Z.zero)
  | Address a -> word_of_z (z_of_be a)
  | FixedBytes b -> pad_right32 b
  | Bytes b | String b -> word_of_z (Z.of_int (String.length b)) ^ pad_right32 b
  | Array vs -> word_of_z (Z.of_int (List.length vs)) ^ enc_seq vs
  | FixedArray vs -> enc_seq vs
  | Tuple vs -> enc_seq vs

and enc_seq vs =
  let parts = List.map (fun v -> (is_dynamic v, enc v)) vs in
  let head_size =
    List.fold_left (fun a (d, e) -> a + (if d then 32 else String.length e)) 0 parts
  in
  let headb = Buffer.create 64 and tailb = Buffer.create 64 in
  let off = ref head_size in
  List.iter
    (fun (d, e) ->
      if d then begin
        Buffer.add_string headb (word_of_z (Z.of_int !off));
        Buffer.add_string tailb e;
        off := !off + String.length e
      end
      else Buffer.add_string headb e)
    parts;
  Buffer.contents headb ^ Buffer.contents tailb

let encode values = enc_seq values

let keccak s = Digestif.KECCAK_256.(to_raw_string (digest_string s))
let selector signature = String.sub (keccak signature) 0 4
let encode_call ~signature values = selector signature ^ enc_seq values

(* ---- decoding ---- *)

let rec is_dyn = function
  | TBytes | TString | TArray _ -> true
  | TFixedArray (t, _) -> is_dyn t
  | TTuple ts -> List.exists is_dyn ts
  | _ -> false

let rec static_size = function
  | TFixedArray (t, k) -> k * static_size t
  | TTuple ts -> List.fold_left (fun a t -> a + static_size t) 0 ts
  | _ -> 32

exception Derr of string

let word_z data pos =
  if pos + 32 > String.length data then raise (Derr "abi: truncated word");
  z_of_be (String.sub data pos 32)

let word_int data pos = Z.to_int (word_z data pos)

let rec decode_tuple tys data base =
  let head = ref 0 in
  List.map
    (fun ty ->
      if is_dyn ty then begin
        let off = word_int data (base + !head) in
        head := !head + 32;
        decode_dynamic ty data (base + off)
      end
      else begin
        let v = decode_static ty data (base + !head) in
        head := !head + static_size ty;
        v
      end)
    tys

and decode_static ty data pos =
  match ty with
  | TUint _ -> Uint (word_z data pos)
  | TInt _ ->
    let z = word_z data pos in
    Int (if Z.testbit z 255 then Z.sub z two256 else z)
  | TBool -> Bool (not (Z.equal (word_z data pos) Z.zero))
  | TAddress ->
    if pos + 32 > String.length data then raise (Derr "abi: truncated address");
    Address (String.sub data (pos + 12) 20)
  | TFixedBytes n ->
    if pos + 32 > String.length data then raise (Derr "abi: truncated bytesN");
    FixedBytes (String.sub data pos n)
  | TFixedArray (t, k) -> FixedArray (List.init k (fun i -> decode_static t data (pos + (i * static_size t))))
  | TTuple ts -> Tuple (decode_tuple ts data pos)
  | TBytes | TString | TArray _ -> raise (Derr "abi: dynamic type decoded as static")

and decode_dynamic ty data pos =
  match ty with
  | TBytes | TString ->
    let len = word_int data pos in
    if pos + 32 + len > String.length data then raise (Derr "abi: truncated bytes/string");
    let s = String.sub data (pos + 32) len in
    if ty = TString then String s else Bytes s
  | TArray t ->
    let len = word_int data pos in
    Array (decode_tuple (List.init len (fun _ -> t)) data (pos + 32))
  | TFixedArray (t, k) -> FixedArray (decode_tuple (List.init k (fun _ -> t)) data pos)
  | TTuple ts -> Tuple (decode_tuple ts data pos)
  | _ -> raise (Derr "abi: static type decoded as dynamic")

let decode tys data =
  try Ok (decode_tuple tys data 0)
  with
  | Derr m -> Error m
  | Invalid_argument _ -> Error "abi: index out of bounds"

(* Strip the 4-byte selector, then decode the parameters. *)
let decode_call tys data =
  if String.length data < 4 then Error "abi: call data shorter than a selector"
  else decode tys (String.sub data 4 (String.length data - 4))

let to_z = function
  | Uint z | Int z -> Some z
  | Bool b -> Some (if b then Z.one else Z.zero)
  | _ -> None
