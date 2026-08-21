(** Unsigned varint (LEB128) as specified by multiformats.
    {{:https://github.com/multiformats/unsigned-varint} spec}

    Decoding enforces the spec's minimal-encoding rule, so a value has
    exactly one spelling. That is what lets a CID be a stable hash of these
    bytes rather than one of several equivalent renderings. *)

exception Error of string

(** The spec's 9-byte ceiling. *)
val max_bytes : int

(** Largest value this module will decode. OCaml's native int is 63-bit
    signed, one bit short of the spec's 63-bit unsigned range, so values at
    or above 2{^62} are rejected rather than wrapped. No multiformats codec
    code, length or protocol number approaches this. *)
val max_value : int

(** @raise Invalid_argument if [n] is negative. *)
val write : int -> string

(** [read s pos] returns the value and the position just past it.
    @raise Error on truncated input, an encoding longer than {!max_bytes},
    a value above {!max_value}, or a non-minimal encoding. *)
val read : string -> int -> int * int

(** {!read} as a result, for callers assembling a larger structure.
    Never raises. *)
val read_result : string -> int -> (int * int, string) result

(** Decode a whole buffer, requiring it to be fully consumed.
    Never raises. *)
val of_octets : string -> (int, string) result
