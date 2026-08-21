(** SS58, Substrate/Polkadot's address format: a network prefix and an
    account id, Base58-encoded with a Blake2b checksum.

    Covers the common case of a 32-byte account id and a single-byte
    network prefix (< 64), which includes Polkadot (0), Kusama (2) and the
    generic Substrate prefix (42). Two-byte prefixes (>= 64) are not
    supported and their addresses are rejected by {!decode} on length. *)

(** [encode ~network pubkey]
    @raise Invalid_argument unless [network < 64] and [pubkey] is 32 bytes. *)
val encode : network:int -> string -> string

(** [Ok (network, account_id)], or [Error] on a bad checksum, an
    undecodable string, or a payload that is not 35 bytes. Never raises. *)
val decode : string -> (int * string, string) result
