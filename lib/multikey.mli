(** Multikey — a key that names its own algorithm:
    [<varint key codec><key bytes>].

    In base58btc the text form is exactly the W3C Multikey / did:key
    encoding, so an ed25519 key renders as ["z6Mk…"] and a secp256k1 key as
    ["zQ3s…"]. Those prefixes are not special-cased; they fall out of the
    codec varint.

    {b This is a structural codec, not key validation.} The library has no
    elliptic-curve code. It checks the byte length that a key type declares
    and nothing else — it cannot tell you a point lies on its curve or that
    a scalar is in range. A successful decode means the bytes were
    well-framed, nothing more. *)

type t

val codec : t -> Multicodec.t
val key_bytes : t -> string

(** Byte length for key types that have a fixed one. [None] for RSA, whose
    DER encoding varies, and for unknown codecs. *)
val expected_length : int -> int option

(** [Error] if the key length disagrees with {!expected_length}. *)
val make : codec:Multicodec.t -> key:string -> (t, string) result

val to_octets : t -> string

(** [Error] on a malformed codec varint or a key whose length disagrees
    with its type. Never raises. *)
val of_octets : string -> (t, string) result

(** Defaults to base58btc, which is what did:key and W3C Multikey use. *)
val to_string : ?base:Multibase.base -> t -> string

val of_string : string -> (t, string) result

(** ["did:key:z…"]. *)
val to_did_key : t -> string

(** [Error] unless the URI has the [did:key:] prefix and a base58btc
    payload — did:key does not admit other multibases. Never raises. *)
val of_did_key : string -> (t, string) result
