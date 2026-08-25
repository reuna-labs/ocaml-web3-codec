(** Bech32 (BIP173) and Bech32m (BIP350), the base-32 checksummed encoding
    behind SegWit addresses. SegWit v0 uses Bech32; v1+ (Taproot) uses
    Bech32m. *)

type encoding = Bech32 | Bech32m

(** BIP173's 90-character cap, and the default for [?max_length] below. The
    BCH code only guarantees detection of up to 4 character errors within
    this length, so it is enforced in both directions rather than treated as
    advisory.

    It is a default rather than a constant because Bech32 outgrew BIP173:
    the Cosmos SDK spells addresses in Bech32 and does not enforce the cap,
    so a decoder fixed at 90 cannot read a long-HRP app-chain address.
    Raising it weakens the checksum guarantee, which is why it has to be
    said at the call site. *)
val max_length : int

(** Longest human-readable part permitted by BIP173. *)
val max_hrp_length : int

(** [convertbits ?pad data ~from ~into] regroups [from]-bit values into
    [into]-bit values, MSB first. [None] if a value is out of range, or if
    [~pad:false] and the leftover bits are not zero padding. Callers need
    this to turn an 8-bit witness program into the 5-bit groups {!encode}
    takes. *)
val convertbits : ?pad:bool -> int list -> from:int -> into:int -> int list option

(** [encode enc ~hrp ~data] with [data] as 5-bit groups.
    @raise Invalid_argument if [hrp] is not 1..{!max_hrp_length} characters
    in ASCII 33..126, if any group is outside 0..31, or if the result would
    exceed {!max_length}. *)
val encode : ?max_length:int -> encoding -> hrp:string -> data:int list -> string

(** [Ok (encoding, hrp, data)] with [data] as 5-bit groups, checksum
    removed. [Error] on length, mixed case, separator, human-readable part,
    character or checksum problems. Never raises. *)
val decode : ?max_length:int -> string -> (encoding * string * int list, string) result

(** [encode_segwit ~hrp ~version ~program] picks Bech32 for v0 and Bech32m
    for v1+, as BIP350 requires. Never raises. *)
val encode_segwit : hrp:string -> version:int -> program:string -> (string, string) result

(** [Ok (version, program)]. Rejects a Bech32m checksum on v0 and a Bech32
    checksum on v1+, which is what keeps a Taproot address from being read
    as a v0 one. [hrp] is matched case-insensitively, and [s] may be all
    upper or all lower case. Never raises. *)
val decode_segwit : hrp:string -> string -> (int * string, string) result
