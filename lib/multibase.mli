(** Multibase — a self-describing base encoding, where one leading
    character names the base the rest is written in.
    {{:https://github.com/multiformats/multibase} spec}

    Every base decodes canonically, so a payload has exactly one spelling
    per base: {!Bitbase} rejects non-zero trailing bits and {!Basen}
    preserves leading zero bytes. CIDs are routinely compared as text, so
    that uniqueness is load-bearing.

    [base256emoji] is not implemented; its 256-emoji alphabet is large and
    it is essentially unused. Its prefix therefore decodes as an unknown
    prefix rather than silently as something else. *)

type base =
  | Identity
  | Base2 | Base8 | Base10
  | Base16 | Base16upper
  | Base32 | Base32upper | Base32pad | Base32padupper
  | Base32hex | Base32hexupper | Base32hexpad | Base32hexpadupper
  | Base32z
  | Base36 | Base36upper
  | Base58btc | Base58flickr
  | Base64 | Base64pad | Base64url | Base64urlpad

(** Every base this module supports. *)
val all : base list

val prefix : base -> char
val of_prefix : char -> base option
val name : base -> string
val of_name : string -> base option

(** Bound on input to the quadratic radix bases (base10, base36, base58);
    see {!Basen}. *)
val max_radix_length : int

(** [encode b s] prefixed with the base's character.
    @raise Invalid_argument if [b] is a radix base and [s] is longer than
    {!max_radix_length}. The power-of-two bases have no such bound. *)
val encode : base -> string -> string

(** [Ok (base, payload)]. [Error] on empty input, an unknown prefix, or a
    payload the named base rejects. Never raises. *)
val decode : string -> (base * string, string) result
