(* multistream-select 1.0: protocol negotiation over a stream.
   https://github.com/multiformats/multistream-select

   Two separable things live here.

   The framing is a codec: <varint length><payload>"\n", where the length
   counts the newline. That is exact and fully implemented.

   The negotiation is a protocol, and this library does no I/O, so it is a
   pure state machine: feed it the payloads you read, and it tells you what
   to write and when a protocol has been agreed. The caller owns the
   socket. *)

let protocol_id = "/multistream/1.0.0"
let na = "na"
let ls = "ls"

(* ---- framing ---- *)

let encode_message payload =
  if String.contains payload '\n' then
    invalid_arg "Multistream.encode_message: payload must not contain a newline";
  Varint.write (String.length payload + 1) ^ payload ^ "\n"

let read_message s pos =
  match Varint.read_result s pos with
  | Error m -> Error m
  | Ok (len, pos) ->
    if len = 0 then Error "multistream: zero-length message"
    else if len > String.length s - pos then Error "multistream: truncated message"
    else if s.[pos + len - 1] <> '\n' then Error "multistream: message not newline-terminated"
    else
      let payload = String.sub s pos (len - 1) in
      (* An embedded newline would make this frame indistinguishable from
         two frames, so it is refused -- and refusing here keeps decoding
         the exact inverse of {!encode_message}, which will not produce
         one either. *)
      if String.contains payload '\n' then
        Error "multistream: payload contains an embedded newline"
      else Ok (payload, pos + len)

let decode_message s =
  match read_message s 0 with
  | Error _ as e -> e
  | Ok (v, pos) -> if pos = String.length s then Ok v else Error "multistream: trailing bytes"

(* ---- negotiation ---- *)

type role =
  | Initiator of string list  (** protocols to try, most preferred first *)
  | Responder of string list  (** protocols we can speak *)

type action =
  | Send of string       (** payload to frame with {!encode_message} and write *)
  | Selected of string   (** both sides agreed on this protocol *)
  | List_requested       (** peer sent "ls"; see the .mli on why we stop here *)
  | Failed of string

type phase = Awaiting_header | Negotiating | Done

type state = { role : role; phase : phase; remaining : string list }

let start role =
  let remaining = match role with Initiator ps -> ps | Responder _ -> [] in
  ({ role; phase = Awaiting_header; remaining }, [ Send protocol_id ])

(* the initiator drives: after the header, it offers its next protocol *)
let offer_next st =
  match st.remaining with
  | [] ->
    ({ st with phase = Done }, [ Failed "multistream: peer supports none of our protocols" ])
  | p :: rest -> ({ st with phase = Negotiating; remaining = rest }, [ Send p ])

let on_message st msg =
  match st.phase with
  | Done -> (st, [ Failed "multistream: negotiation already finished" ])
  | Awaiting_header ->
    if msg <> protocol_id then
      ({ st with phase = Done },
       [ Failed (Printf.sprintf "multistream: expected %S, got %S" protocol_id msg) ])
    else (
      match st.role with
      | Initiator _ -> offer_next st
      | Responder _ -> ({ st with phase = Negotiating }, []))
  | Negotiating -> (
    match st.role with
    | Initiator _ ->
      if msg = na then offer_next st
      else if msg = ls then (st, [ List_requested ])
      else
        (* the responder echoes the protocol it accepted; anything else
           would mean it agreed to something we never offered *)
        ({ st with phase = Done }, [ Selected msg ])
    | Responder supported ->
      if msg = ls then (st, [ List_requested ])
      else if List.mem msg supported then
        ({ st with phase = Done }, [ Send msg; Selected msg ])
      else (st, [ Send na ]))

let is_done st = st.phase = Done
