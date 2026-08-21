(** The multicodec registry — a varint code saying what some bytes are.
    {{:https://github.com/multiformats/multicodec} registry}

    A code is an integer and every integer is a valid {!t}, including codes
    absent from the bundled table. That is deliberate: an unknown code must
    still round-trip, or a CID naming a codec this library has not heard of
    would be unparseable rather than merely unnamed. Use {!is_known} or
    {!name} to tell the two apart. *)

type tag = Multihash | Ipld | Multiaddr | Key | Serialization | Misc

type t = int

(** Every entry in the bundled table: code, name, tag. A curated subset of
    the upstream registry covering the hashes, IPLD codecs, multiaddr
    protocols and key types this library reaches, plus those the sibling
    [mirage-crypto-blockchain] package can compute.

    Codes and names were checked against multiformats/multicodec
    [table.csv] on 2026-08-21. Where two registries name one code
    differently the domain's own name wins: 0x309 is ["memorytransport"]
    here and ["memory"] in {!Multiaddr}'s protocol table. *)
val table : (int * string * tag) list

val of_code : int -> t
val to_code : t -> int

(** [None] for a code outside the bundled table. *)
val name : t -> string option

val tag : t -> tag option
val of_name : string -> t option
val is_known : t -> bool

(** The registered name, or ["0x…"] for an unknown code. *)
val to_string : t -> string

(** The code as a minimal varint — see {!Varint}. *)
val write : t -> string

(** @raise Varint.Error on a truncated or non-minimal varint. *)
val read : string -> int -> t * int
