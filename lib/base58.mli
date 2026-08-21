(** Base58 and Base58Check (Bitcoin legacy addresses and WIF keys, TRON,
    Solana). Base58Check appends a 4-byte SHA256d checksum. *)

(** Longest accepted input, in bytes for {!encode} and characters for
    {!decode}. Base conversion is quadratic in the input length, and every
    real payload is short (a legacy address is 34 characters, a WIF key 52,
    an extended key 112), so longer input is refused rather than paid for. *)
val max_length : int

(** @raise Invalid_argument if the input exceeds {!max_length} bytes. *)
val encode : string -> string

(** [Error] on a character outside the alphabet, or input longer than
    {!max_length}. Never raises. *)
val decode : string -> (string, string) result

(** @raise Invalid_argument if the payload plus its 4-byte checksum exceeds
    {!max_length}. *)
val encode_check : string -> string

(** [Error] on a bad checksum, a short payload, or an undecodable string.
    Never raises. *)
val decode_check : string -> (string, string) result
