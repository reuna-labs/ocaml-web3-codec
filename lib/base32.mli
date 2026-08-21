(** Base32: RFC4648's standard and extended-hex alphabets, plus z-base-32
    (Zooko's human-oriented variant, which multibase calls [base32z]).

    Decoding is canonical — non-zero trailing bits are rejected, as is a
    symbol count that leaves a whole symbol unused, which is what makes
    counts of 1, 3 and 6 within an 8-symbol group invalid. *)

type alphabet =
  | Rfc4648        (** [abcdefghijklmnopqrstuvwxyz234567] *)
  | Rfc4648_upper
  | Hex            (** extended hex, [0123456789abcdefghijklmnopqrstuv] *)
  | Hex_upper
  | Z_base_32      (** [ybndrfg8ejkmcpqxot1uwisza345h769] *)

(** [~pad:true] pads with ['='] to a multiple of 8 symbols. Never raises. *)
val encode : ?alphabet:alphabet -> ?pad:bool -> string -> string

(** [~pad] must match how the input was produced; with [~pad:false] an
    ['='] is simply an invalid character. Never raises. *)
val decode : ?alphabet:alphabet -> ?pad:bool -> string -> (string, string) result
