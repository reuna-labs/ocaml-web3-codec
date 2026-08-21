(** Multiaddr — a self-describing network address such as
    [/ip4/127.0.0.1/tcp/1234].
    {{:https://github.com/multiformats/multiaddr} spec}

    Binary form is a sequence of [<varint code><value>], where the value is
    fixed-width, absent, or varint-length-prefixed.

    An unknown protocol code is rejected rather than skipped. Its width is
    not knowable, and guessing wrong would silently re-frame every
    component after it — turning an address into a different valid-looking
    address rather than into an error. *)

type size =
  | Zero          (** no value, e.g. [/tls] *)
  | Fixed of int  (** value is exactly this many bytes *)
  | Variable      (** value is varint-length-prefixed *)

type proto = private {
  code : int;
  name : string;
  size : size;
  is_path : bool;  (** [/unix], whose value takes the rest of the string *)
}

(** Every protocol this module knows. *)
val protos : proto list

val proto_of_code : int -> proto option
val proto_of_name : string -> proto option

type component
type t = component list

val proto : component -> proto

(** The raw binary value — a 4-byte address for [ip4], 2 big-endian bytes
    for a port, the multihash bytes for [p2p]. *)
val value : component -> string

val protocols : t -> proto list

(** Append one address to another, e.g. a [/p2p/…] onto a transport. *)
val encapsulate : t -> t -> t

(** Compares binary forms. *)
val equal : t -> t -> bool

val to_octets : t -> string

(** [Error] on a malformed varint, an unknown protocol code, or a value
    truncated relative to its declared width. Never raises. *)
val of_octets : string -> (t, string) result

(** Renders values per protocol: dotted quad for [ip4], RFC 5952 for
    [ip6], decimal for ports, base58btc for [p2p], base32 plus [:port] for
    onion, multibase for [certhash]. *)
val to_string : t -> string

(** [Error] on an address not starting with ['/'], an empty or trailing
    component, an unknown protocol name, a missing value, or a value the
    protocol rejects. Never raises. *)
val of_string : string -> (t, string) result
