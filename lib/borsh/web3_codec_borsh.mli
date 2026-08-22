(** Borsh (Binary Object Representation Serializer for Hashing), the
    deterministic little-endian codec used by Solana and NEAR.

    Borsh output is fed to hashes and signatures, so determinism is the
    point: the encoders range-check rather than truncate, and the decoders
    reject any spelling the encoders would not produce. *)

exception Error of string

(** These raise [Invalid_argument] if the value does not fit the named
    type -- notably [encode_u64] of a value >= 2^64, which would otherwise
    silently wrap a lamport amount. *)

val encode_u8 : int -> string
val encode_u16 : int -> string
val encode_u32 : int -> string
val encode_u64 : Z.t -> string
val encode_u128 : Z.t -> string
val encode_i8 : int -> string
val encode_i16 : int -> string
val encode_i32 : int -> string
val encode_i64 : Z.t -> string
val encode_i128 : Z.t -> string

val encode_bool : bool -> string
val encode_option : ('a -> string) -> 'a option -> string

(** [Vec<u8>]: u32 length prefix then the raw bytes, no UTF-8 requirement. *)
val encode_bytes : string -> string

(** Borsh strings are UTF-8 by definition.
    @raise Invalid_argument if [s] is not valid UTF-8; use {!encode_bytes}
    for opaque bytes. *)
val encode_string : string -> string

val encode_vec : ('a -> string) -> 'a list -> string

(** [[T; N]]: bare concatenation, no length prefix. *)
val encode_fixed_array : ('a -> string) -> 'a list -> string

(** u8 discriminant then the variant payload. *)
val encode_enum : variant:int -> string -> string

(** Reader style: [read_* s pos] returns the value and the next position.
    All raise {!Error} on truncated input. *)

val read_u8 : string -> int -> int * int
val read_u16 : string -> int -> int * int
val read_u32 : string -> int -> int * int
val read_u64 : string -> int -> Z.t * int
val read_u128 : string -> int -> Z.t * int
val read_i8 : string -> int -> int * int
val read_i16 : string -> int -> int * int
val read_i32 : string -> int -> int * int
val read_i64 : string -> int -> Z.t * int
val read_i128 : string -> int -> Z.t * int

(** @raise Error unless the byte is exactly 0 or 1. *)
val read_bool : string -> int -> bool * int

val read_bytes : string -> int -> string * int

(** @raise Error if the bytes are not valid UTF-8. *)
val read_string : string -> int -> string * int

(** @raise Error unless the tag byte is exactly 0 or 1. *)
val read_option : (string -> int -> 'a * int) -> string -> int -> 'a option * int

(** @raise Error if the count exceeds the bytes remaining. Assumes
    [read_v] consumes at least one byte per element, which every reader
    here does. *)
val read_vec : (string -> int -> 'a * int) -> string -> int -> 'a list * int

(** Run a reader over a whole buffer, requiring it to be fully consumed.
    Never raises. *)
val of_octets : (string -> int -> 'a * int) -> string -> ('a, string) result
