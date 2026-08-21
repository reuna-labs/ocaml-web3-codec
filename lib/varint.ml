(* Unsigned varint as multiformats uses it: LEB128, seven bits per byte,
   low group first, high bit set on every byte but the last.
   https://github.com/multiformats/unsigned-varint

   The spec requires a *minimal* encoding, and that requirement is the
   reason this module is careful. Every multiformat below is content-
   addressed: a CID is a hash of these bytes. If "01" and "81 00" both
   decoded to 1, one value would have many spellings and the hash would
   stop pinning down the payload -- the same malleability this repo
   already had to close in RLP length fields and SCALE compacts. *)

exception Error of string

(* The spec caps a varint at 9 bytes, i.e. 63 bits. OCaml's native int is
   63-bit *signed*, so it stops one bit short of that: values from 2^62 up
   would wrap. Rather than silently truncate, values above [max_value] are
   rejected. No multiformats code or length comes near this. *)
let max_bytes = 9
let max_value = max_int

let write n =
  if n < 0 then invalid_arg "Varint.write: negative value";
  let b = Buffer.create 4 in
  let rec go n =
    if n < 0x80 then Buffer.add_char b (Char.chr n)
    else begin
      Buffer.add_char b (Char.chr ((n land 0x7f) lor 0x80));
      go (n lsr 7)
    end
  in
  go n;
  Buffer.contents b

(* [read s pos] returns the value and the position just past it. *)
let read s pos =
  let n = String.length s in
  let rec go pos shift acc count =
    if pos >= n then raise (Error "varint: truncated");
    if count >= max_bytes then raise (Error "varint: longer than 9 bytes");
    let b = Char.code s.[pos] in
    let payload = b land 0x7f in
    (* refuse before shifting rather than after wrapping *)
    if shift >= 63 || (shift > 0 && payload > max_value lsr shift) then
      raise (Error "varint: value too large for a native int");
    let acc = acc lor (payload lsl shift) in
    if b land 0x80 <> 0 then go (pos + 1) (shift + 7) acc (count + 1)
    else begin
      (* minimality: a final byte of 0x00 means the group carried nothing,
         so a shorter encoding of the same value existed. The single byte
         "00" is the one legitimate case -- it is how zero is spelled. *)
      if b = 0 && count > 0 then raise (Error "varint: non-minimal encoding");
      (acc, pos + 1)
    end
  in
  go pos 0 0 0

let of_octets s =
  match read s 0 with
  | v, pos -> if pos = String.length s then Ok v else Error "varint: trailing bytes"
  | exception Error m -> Error m

(* [read_result] is the reader-style entry point for callers assembling a
   larger structure, who need the position back but not an exception. *)
let read_result s pos =
  match read s pos with v, p -> Ok (v, p) | exception Error m -> Error m
