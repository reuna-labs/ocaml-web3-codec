(** Radix conversion for bases whose radix is not a power of two — base10,
    base36 and base58 — where the input must be treated as one big integer
    rather than regrouped bit by bit.

    This is quadratic in the input length, which is why every entry point
    takes a [~max_length]. The power-of-two bases in {!Bitbase} are linear
    and need no such bound.

    Leading zero bytes are preserved as leading zero-symbols; they carry no
    value in the integer, so without that they would not round-trip. *)

type t

(** Default bound, generous enough for any realistic multibase payload
    while keeping the quadratic cost small. *)
val default_max_length : int

(** @raise Invalid_argument on an alphabet shorter than two symbols or one
    with a repeated character. *)
val make : alphabet:string -> t

(** [encode ?max_length ?name t s]. [name] only prefixes error text.
    @raise Invalid_argument if [s] is longer than [max_length]. *)
val encode : ?max_length:int -> ?name:string -> t -> string -> string

(** [Error] on a character outside the alphabet or input longer than
    [max_length]. Never raises. *)
val decode : ?max_length:int -> ?name:string -> t -> string -> (string, string) result

(** Bitcoin's base58 alphabet, as used by Base58Check, base58btc multibase
    and CIDv0. *)
val btc : t

(** Flickr's base58 alphabet — the same characters, lower case first. *)
val flickr : t

val base36 : t
val base36_upper : t
val base10 : t
