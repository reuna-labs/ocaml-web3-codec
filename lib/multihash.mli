(** Multihash — a digest carrying the identity of the function that
    produced it: [<varint code><varint length><digest>].
    {{:https://github.com/multiformats/multihash} spec}

    Parsing and computing are separate. The container is
    algorithm-agnostic, so {!of_octets} accepts any code, including ones
    this library cannot produce — you can route a BLAKE3 multihash without
    being able to make one. {!digest} is the narrow operation and reports
    unsupported algorithms as [Error] rather than substituting a different
    hash.

    Computable here: identity, sha1, sha2-224/256/384/512, sha2-512-224,
    sha2-512-256, sha3-224/256/384/512, shake-128, shake-256,
    keccak-224/256/384/512, dbl-sha2-256, md5, blake2b-160/256/384/512 and
    blake2s-128/160/224/256. Notably {b not} computable: blake3, ripemd-*, and
    poseidon. Use {!supported} to ask.

    shake-128 and shake-256 are emitted at 32 and 64 bytes. SHAKE is an
    extendable-output function with no default length in FIPS 202, so the size
    is a choice rather than a property of the algorithm; these are the ones
    go-multihash uses, so digests round-trip with the wider ecosystem. *)

type t

(** @raise Invalid_argument on an absurdly long digest. No
    algorithm-specific length check is applied: truncated digests are
    legitimate multihashes. *)
val make : code:Multicodec.t -> digest:string -> t

val code : t -> Multicodec.t
val digest_bytes : t -> string
val to_octets : t -> string

(** [read s pos] parses one multihash and returns the position just past
    it, so CID and multiaddr can embed one. [Error] if a varint is
    malformed or the declared length exceeds the bytes remaining. Never
    raises. *)
val read : string -> int -> (t * int, string) result

(** Like {!read} but requires the whole buffer to be consumed. *)
val of_octets : string -> (t, string) result

(** Whether {!digest} can compute this algorithm. *)
val supported : Multicodec.t -> bool

(** [Error] if the algorithm is not computable here. *)
val digest : Multicodec.t -> string -> (t, string) result

(** [verify t s] recomputes the digest of [s] and compares, honouring a
    truncated digest by comparing only its length. [Error] — never
    [Ok false] — when the algorithm cannot be computed here, so an
    unverifiable digest is never reported as valid. *)
val verify : t -> string -> (bool, string) result

(** Human-readable [name-length-hex]. Not a wire format. *)
val to_string : t -> string
