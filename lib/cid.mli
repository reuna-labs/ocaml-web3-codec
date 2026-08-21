(** CID, the IPLD content identifier — the format that ties multihash,
    multicodec and multibase together.
    {{:https://github.com/multiformats/cid} spec}

    CIDv1 is [<varint 1><varint content codec><multihash>], written in text
    through {!Multibase}.

    CIDv0 is not a degenerate v1. It is bare: 34 bytes of sha2-256
    multihash, no version varint, always dag-pb, and in text always
    base58btc with no multibase prefix. It is modelled as its own shape so
    the two cannot be confused — and because a v0 CID has exactly one
    spelling, while a v1 has one per base. *)

type version = V0 | V1

type t

val version : t -> version
val codec : t -> Multicodec.t
val hash : t -> Multihash.t

(** [Error] unless the multihash is a 32-byte sha2-256 digest. *)
val v0 : Multihash.t -> (t, string) result

val v1 : codec:Multicodec.t -> Multihash.t -> t

(** Always possible: every v0 is a dag-pb sha2-256 v1. *)
val to_v1 : t -> t

(** [Error] unless the codec is dag-pb and the hash a 32-byte sha2-256
    digest — most v1 CIDs have no v0 form. *)
val to_v0 : t -> (t, string) result

val to_octets : t -> string

(** [Error] on a malformed varint, an unsupported version, a version 0
    written explicitly as a varint (v0 has no version field, so that is
    ambiguous), or trailing bytes. Never raises. *)
val of_octets : string -> (t, string) result

(** [base] is ignored for a v0 CID, which is always bare base58btc.
    Defaults to base32, the usual choice for v1. *)
val to_string : ?base:Multibase.base -> t -> string

(** Accepts a multibase-prefixed v1 or a bare base58btc v0, dispatching on
    whether the first character is a multibase prefix. Never raises. *)
val of_string : string -> (t, string) result

(** Compares the binary forms, so two renderings of one v1 CID in different
    bases are equal. *)
val equal : t -> t -> bool
