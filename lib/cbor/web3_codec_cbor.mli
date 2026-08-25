(** CBOR (RFC 8949), with the deterministic encodings that hash-bearing
    protocols need.

    CBOR is a self-describing format, so the same value has many valid
    spellings. That is fine until something signs one of them. This library
    therefore separates the two halves sharply:

    - the {b decoder is permissive}, because real chains carry non-canonical
      CBOR and refusing to read it would be refusing to read the chain;
    - the {b encoder is strict}, emitting exactly one spelling per {!profile}.

    What it will not do is quietly resolve an ambiguity. Duplicate map keys are
    rejected rather than last-one-wins: a decoder that accepts them lets a
    sender show one value to a checker and another to a consumer.

    Because a decoder can never reproduce the exact bytes it was given -- it
    cannot know which of several valid spellings the sender chose -- anything
    that hashes a decoded structure must keep the original bytes. {!read_span}
    reports them. This is not an optimisation; without it, re-encoding a
    transaction body changes its identifier. *)

(** {1 Values} *)

(** The width a floating-point value was encoded at. Carried so that a value
    read at one width is written back at the same one; CBOR's half and single
    forms are both exactly representable as an OCaml float, so no precision is
    lost either way. *)
type fwidth = Half | Single | Double

type t =
  | Uint of int64
      (** Major type 0, as an {b unsigned} bit pattern covering
          [0 .. 2^64-1]. [-1L] means [18446744073709551615], not minus one.
          Use {!uint_to_string} rather than [Int64.to_string]. *)
  | Nint of int64
      (** Major type 1, holding the encoded [n] as an unsigned bit pattern.
          The value is [-1 - n], so [Nint 0L] is [-1] and [Nint (-1L)] is
          [-2^64]. Negative CBOR integers reach one further from zero than
          [Int64] does, which is why this is not simply an [Int64]. *)
  | Big of { negative : bool; magnitude : string }
      (** Tags 2 and 3: an arbitrary-precision integer as a big-endian
          magnitude. The value is [magnitude] when [negative] is false and
          [-1 - magnitude] when it is true.

          Deliberately not interpreted. Nothing here does arithmetic on a
          bignum, so nothing here needs a bignum library -- which is what lets
          an Ed25519-only consumer link this into a unikernel with no GMP in
          it. Callers who want arithmetic convert at their own boundary. *)
  | Bytes of string
  | Text of string  (** Major type 3. Not validated as UTF-8; see {!encode}. *)
  | Array of t list
  | Map of (t * t) list
      (** Order is {b as it appeared}. The decoder never sorts, because a
          caller comparing a re-encode against the original bytes needs to see
          what the sender actually sent. {!encode} sorts. *)
  | Tag of int * t
      (** Tags other than 2 and 3, which become {!Big}. *)
  | Bool of bool
  | Null
  | Undefined
  | Simple of int
      (** Major type 7 simple values other than 20-23, which have their own
          constructors above. Values 24-31 are not well-formed and are
          rejected in both directions. *)
  | Float of fwidth * float

(** {1 Errors} *)

exception Error of string
(** Raised by the [read_*] family on malformed or over-budget input. The
    [of_octets] family catches it. *)

(** {1 Allocation budget}

    Every decoder entry point takes a budget, because the input is usually a
    remote peer's and a length header is a promise, not a fact. Limits are
    checked {b before} allocating, so a hostile eight-byte length cannot
    exhaust memory before it is found to be a lie. *)

type limits = {
  max_input_bytes : int;
  max_nesting : int;  (** Guards stack exhaustion through nested containers. *)
  max_items : int;  (** Total array elements plus map pairs, across the value. *)
  max_string_bytes : int;  (** Applies to each byte or text string. *)
}

val default_limits : limits

(** {1 Encoding} *)

type profile =
  | Canonical
      (** RFC 8949 section 4.2.1 "core deterministic encoding": shortest-form
          integers, definite lengths throughout, and map keys sorted by the
          bytewise lexicographic order of their {b encoded} form. *)
  | Rfc7049
      (** RFC 7049 section 3.9, which differs from {!Canonical} in one way that
          matters: keys sort by {b length first}, then bytewise. Some protocols
          still specify this ordering for a specific structure -- Cardano's
          script-data "language views" is one -- so getting it wrong there
          produces a wrong hash and a rejected transaction rather than a
          parse error. Do not reach for it otherwise. *)

val encode : ?profile:profile -> t -> string
(** [encode ?profile v] is the deterministic encoding of [v]. [profile]
    defaults to {!Canonical}.

    @raise Invalid_argument if [v] cannot be encoded at all: a {!Simple} outside
    [0..19] or [32..255], a {!Tag} with a negative or oversized number, or a
    {!Big} whose magnitude has leading zero bytes (which would give one integer
    two spellings). *)

val encode_exn : ?profile:profile -> t -> string
(** Alias for {!encode}, for callers who prefer the name to say so. *)

(** {1 Decoding}

    Reader style, as elsewhere in this library: [read v pos] returns the value
    and the position just past it. *)

type span = { off : int; len : int }
(** A half-open byte range [\[off, off+len)] of the input. *)

val read : ?limits:limits -> string -> int -> t * int
(** @raise Error on malformed, truncated or over-budget input. *)

val read_span : ?limits:limits -> string -> int -> t * span * int
(** As {!read}, and also the exact bytes the value occupied.

    This is what makes a decoded structure re-hashable. A protocol that
    identifies a structure by the hash of its encoding cannot recover that hash
    from the decoded value, because the encoder would have to guess which valid
    spelling the sender used. Keep the span, hash the span. *)

val of_octets : ?limits:limits -> string -> (t, string) result
(** Decodes a complete value and requires the whole input to be consumed;
    trailing bytes are an error rather than something to ignore. Never
    raises. *)

(** {1 Canonical form} *)

val is_canonical : ?profile:profile -> string -> bool
(** [is_canonical ?profile s] is [true] when [s] decodes and re-encodes to
    itself under [profile] -- that is, when the sender used the same spelling
    this library would have. Never raises; malformed input is not canonical.

    Useful as an assertion about data you produced. It is {b not} a validity
    check on data you received: chains accept non-canonical CBOR, so rejecting
    it here would reject real transactions. *)

(** {1 Unsigned helpers}

    {!Uint} and {!Nint} hold bit patterns, so the ordinary [Int64] operations
    are wrong on them above [2^63]. These are not. *)

val uint : int64 -> t
val uint_of_int : int -> t
(** @raise Invalid_argument on a negative [int]. *)

val uint_to_string : int64 -> string
(** Decimal, interpreting the bit pattern as unsigned. *)

val int_value : t -> int option
(** The value as an OCaml [int] when it fits exactly, for {!Uint}, {!Nint} and
    {!Big} alike. [None] rather than a wrapped result when it does not -- an
    integer that silently wraps is how a quantity becomes the wrong quantity. *)

val compare_canonical : t -> t -> int
(** Orders values by their {!Canonical} encodings: the map-key order
    {!encode} applies. Exposed because callers building a map often want to
    check it is already sorted rather than re-sorting it. *)
