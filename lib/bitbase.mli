(** Generic power-of-two base encoding — bytes regrouped into fixed-width
    symbols, most significant bit first. Base2, base8, base16, base32 and
    base64 are all this function with different parameters; {!Base16},
    {!Base32} and {!Base64} are the named faces over it.

    Decoding is canonical: non-zero trailing bits and symbol counts that
    leave a whole symbol unused are both rejected, so one payload has one
    spelling. Being linear, it needs no input length cap — unlike the radix
    bases in {!Basen}. *)

type t

(** [make ~bits ~alphabet] with [bits] in 1..6 and an alphabet of exactly
    [2^bits] distinct characters.
    @raise Invalid_argument on a bad width, a wrong-sized alphabet, a
    repeated character, or an alphabet containing ['='], which is reserved
    for padding. *)
val make : bits:int -> alphabet:string -> t

(** Symbols per whole-byte group — the period padding rounds up to: 4 for
    base64, 8 for base32. *)
val group : t -> int

(** [encode ?pad t s]. With [~pad:true] the output is padded with ['=']
    to a multiple of {!group}. Never raises. *)
val encode : ?pad:bool -> t -> string -> string

(** [Error] on an invalid character, bad padding, a trailing symbol that
    carries no data, or non-zero trailing bits. [~pad] must match how the
    input was produced: with [~pad:false] an ['='] is simply an invalid
    character. Never raises. *)
val decode : ?pad:bool -> t -> string -> (string, string) result
