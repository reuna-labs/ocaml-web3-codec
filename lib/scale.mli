(** SCALE (Simple Concatenated Aggregate Little-Endian), the codec used by
    Substrate / Polkadot.

    Compact integers have one valid spelling per value and {!read_compact}
    enforces it, so a decoded extrinsic re-encodes to the bytes it came
    from. The fixed-width encoders range-check instead of truncating: a
    balance that does not fit its type is a bug worth hearing about, not
    one to silently reduce mod 2^n. *)

exception Error of string

(** Largest byte count a compact integer may use. *)
val compact_max_bytes : int

(** These raise [Invalid_argument] if the value is negative or wider than
    the named type. *)

val encode_u8 : int -> string
val encode_u16 : int -> string
val encode_u32 : int -> string
val encode_u64 : Z.t -> string
val encode_u128 : Z.t -> string

(** @raise Invalid_argument if negative, or wider than
    {!compact_max_bytes}. *)
val encode_compact : Z.t -> string

val encode_bool : bool -> string
val encode_option : ('a -> string) -> 'a option -> string

(** [Vec<u8>] / [Bytes] / [Text]: compact length prefix then raw bytes. *)
val encode_bytes : string -> string

val encode_string : string -> string

(** [Vec<T>]: compact count then each element. *)
val encode_vec : ('a -> string) -> 'a list -> string

(** [read_compact s pos] returns the value and the position just past it.
    @raise Error on truncated input or a non-canonical encoding (one whose
    value would fit a shorter mode, or which carries a leading zero byte). *)
val read_compact : string -> int -> Z.t * int

(** @raise Error on truncated input, a non-canonical length, or a length
    larger than the input. *)
val read_bytes : string -> int -> string * int

(** Whole-buffer wrappers; both require the input to be fully consumed and
    never raise. *)

val compact_of_octets : string -> (Z.t, string) result
val bytes_of_octets : string -> (string, string) result
