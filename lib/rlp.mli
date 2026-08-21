(** RLP (Recursive Length Prefix), Ethereum's structural serialization for
    transactions, receipts and trie nodes.

    Decoding is strict about canonical form, so that re-encoding a decoded
    value reproduces the input byte for byte. Anything less would let two
    spellings of one value hash differently. *)

type t =
  | Str of string
  | List of t list

(** Maximum list nesting {!decode} will follow before giving up. Ethereum's
    own structures nest far below this; the bound exists so adversarial
    input cannot drive unbounded recursion. *)
val max_depth : int

(** [of_z z] encodes a non-negative scalar minimally ([Z.zero] becomes the
    empty string, as RLP requires).
    @raise Invalid_argument if [z] is negative -- RLP cannot represent one,
    and silently encoding it as zero would corrupt a signed payload. *)
val of_z : Z.t -> t

(** @raise Invalid_argument if [n] is negative. See {!of_z}. *)
val of_int : int -> t

val of_string : string -> t
val to_string : t -> (string, string) result
val to_z : t -> (Z.t, string) result

val encode : t -> string

(** [Error] on truncated input, trailing bytes, excessive nesting, or any
    non-canonical encoding (a long-form length that would fit the short
    form, a leading zero in a length, a single low byte given a length
    prefix, or a length field too large for the input). Never raises. *)
val decode : string -> (t, string) result
