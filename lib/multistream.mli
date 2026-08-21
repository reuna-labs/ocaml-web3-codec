(** multistream-select 1.0 — protocol negotiation over a stream.
    {{:https://github.com/multiformats/multistream-select} spec}

    Two separable things live here.

    {b Framing} is a codec: [<varint length><payload>"\n"], where the
    length counts the newline. Exact and complete.

    {b Negotiation} is a protocol, and this library does no I/O, so it is a
    pure state machine. Feed it the payloads you read; it tells you what to
    write and when a protocol has been agreed. The caller owns the
    socket. *)

(** ["/multistream/1.0.0"] — the header both sides open with. *)
val protocol_id : string

(** ["na"], sent to refuse a proposal. *)
val na : string

(** ["ls"], a request to list supported protocols. *)
val ls : string

(** @raise Invalid_argument if [payload] contains a newline, which would
    make the frame ambiguous. *)
val encode_message : string -> string

(** [read_message s pos] returns the payload without its newline, and the
    position just past the frame. [Error] on a malformed varint, a zero
    length, truncation, a frame that is not newline-terminated, or a
    payload containing an embedded newline — that last one would be
    indistinguishable from two frames, and refusing it keeps decoding the
    exact inverse of {!encode_message}.

    A consequence worth knowing: an [ls] {i response} nests
    newline-terminated entries inside one outer frame, so it is not
    decodable by this function. That is the same scope boundary
    {!List_requested} describes. Never raises. *)
val read_message : string -> int -> (string * int, string) result

(** {!read_message} over a whole buffer, requiring it to be consumed. *)
val decode_message : string -> (string, string) result

type role =
  | Initiator of string list  (** protocols to try, most preferred first *)
  | Responder of string list  (** protocols we can speak *)

type action =
  | Send of string      (** frame this with {!encode_message} and write it *)
  | Selected of string  (** both sides agreed on this protocol *)
  | List_requested
      (** the peer sent ["ls"]. No response is generated: the [ls] reply
          nests length-prefixed frames inside an outer frame, and rather
          than guess at a wire format that could not be checked against a
          reference implementation here, this surfaces the request and
          leaves the reply to the caller. *)
  | Failed of string

type state

(** Returns the opening state and the header to send. *)
val start : role -> state * action list

(** Drive the machine with one received payload. *)
val on_message : state -> string -> state * action list

val is_done : state -> bool
