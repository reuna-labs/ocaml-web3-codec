(** Hexadecimal, RFC4648 base16.

    Byte-aligned, so there is no padding and no trailing-bit case. Case is
    significant: multibase gives [base16] and [base16upper] separate
    prefixes, so a decoder that folded case would give one payload two
    spellings under one prefix. *)

val encode : ?upper:bool -> string -> string

(** [Error] on an odd length or a character outside the selected alphabet.
    Never raises. *)
val decode : ?upper:bool -> string -> (string, string) result
