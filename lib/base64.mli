(** Base64, RFC4648 standard and URL-safe alphabets.

    Decoding is canonical: non-zero trailing bits are rejected, so
    ["QQ"] decodes to ["A"] but ["QR"] -- which differs only in bits no
    byte uses -- does not. A decoder that ignored those bits would give one
    payload many spellings. *)

type alphabet =
  | Standard  (** [+] and [/] *)
  | Url       (** [-] and [_] *)

(** [~pad:true] pads with ['='] to a multiple of 4 symbols. Never raises. *)
val encode : ?alphabet:alphabet -> ?pad:bool -> string -> string

(** [~pad] must match how the input was produced. Never raises. *)
val decode : ?alphabet:alphabet -> ?pad:bool -> string -> (string, string) result
