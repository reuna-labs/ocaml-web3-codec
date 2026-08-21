(* Multiaddr: a self-describing network address, /ip4/127.0.0.1/tcp/1234.
   https://github.com/multiformats/multiaddr

   Binary form is a sequence of <varint code><value>, where a value is
   fixed-width, absent, or varint-length-prefixed. The text form spells the
   same components with a per-protocol rendering of the value.

   An unknown protocol code cannot be printed -- there is no name for it --
   and it cannot be parsed from text either. Binary parsing therefore fails
   on unknown codes rather than guessing a width, because guessing wrong
   would silently re-frame every component after it. *)

type size = Zero | Fixed of int (* bytes *) | Variable

type proto = { code : int; name : string; size : size; is_path : bool }

let protos =
  [ { code = 0x04; name = "ip4"; size = Fixed 4; is_path = false };
    { code = 0x06; name = "tcp"; size = Fixed 2; is_path = false };
    { code = 0x21; name = "dccp"; size = Fixed 2; is_path = false };
    { code = 0x29; name = "ip6"; size = Fixed 16; is_path = false };
    { code = 0x2a; name = "ip6zone"; size = Variable; is_path = false };
    { code = 0x35; name = "dns"; size = Variable; is_path = false };
    { code = 0x36; name = "dns4"; size = Variable; is_path = false };
    { code = 0x37; name = "dns6"; size = Variable; is_path = false };
    { code = 0x38; name = "dnsaddr"; size = Variable; is_path = false };
    { code = 0x84; name = "sctp"; size = Fixed 2; is_path = false };
    { code = 0x0111; name = "udp"; size = Fixed 2; is_path = false };
    { code = 0x0113; name = "p2p-webrtc-star"; size = Zero; is_path = false };
    { code = 0x0114; name = "p2p-webrtc-direct"; size = Zero; is_path = false };
    { code = 0x0122; name = "p2p-circuit"; size = Zero; is_path = false };
    { code = 0x012d; name = "udt"; size = Zero; is_path = false };
    { code = 0x012e; name = "utp"; size = Zero; is_path = false };
    { code = 0x0190; name = "unix"; size = Variable; is_path = true };
    { code = 0x01a5; name = "p2p"; size = Variable; is_path = false };
    { code = 0x01bb; name = "https"; size = Zero; is_path = false };
    { code = 0x01bc; name = "onion"; size = Fixed 12; is_path = false };
    { code = 0x01bd; name = "onion3"; size = Fixed 37; is_path = false };
    { code = 0x01be; name = "garlic64"; size = Variable; is_path = false };
    { code = 0x01bf; name = "garlic32"; size = Variable; is_path = false };
    { code = 0x01c0; name = "tls"; size = Zero; is_path = false };
    { code = 0x01c1; name = "sni"; size = Variable; is_path = false };
    { code = 0x01c6; name = "noise"; size = Zero; is_path = false };
    { code = 0x01cc; name = "quic"; size = Zero; is_path = false };
    { code = 0x01cd; name = "quic-v1"; size = Zero; is_path = false };
    { code = 0x01d1; name = "webtransport"; size = Zero; is_path = false };
    { code = 0x01d2; name = "certhash"; size = Variable; is_path = false };
    { code = 0x01dd; name = "ws"; size = Zero; is_path = false };
    { code = 0x01de; name = "wss"; size = Zero; is_path = false };
    { code = 0x01df; name = "p2p-websocket-star"; size = Zero; is_path = false };
    { code = 0x01e0; name = "http"; size = Zero; is_path = false };
    { code = 0x0309; name = "memory"; size = Variable; is_path = false } ]

let by_code = Hashtbl.create 64
let by_name = Hashtbl.create 64

let () =
  List.iter
    (fun p ->
      Hashtbl.replace by_code p.code p;
      Hashtbl.replace by_name p.name p)
    protos

let proto_of_code c = Hashtbl.find_opt by_code c
let proto_of_name n = Hashtbl.find_opt by_name n

type component = { proto : proto; value : string }
type t = component list

let proto c = c.proto
let value c = c.value

(* ---- textual value rendering, per protocol ---- *)

let be16 s = (Char.code s.[0] lsl 8) lor Char.code s.[1]
let of_be16 n = String.init 2 (fun i -> Char.chr ((n lsr (8 * (1 - i))) land 0xff))

let ip4_to_string v =
  String.concat "." (List.init 4 (fun i -> string_of_int (Char.code v.[i])))

let ip4_of_string s =
  match String.split_on_char '.' s with
  | [ a; b; c; d ] -> (
    let part x =
      match int_of_string_opt x with
      | Some n when n >= 0 && n <= 255 && (String.length x = 1 || x.[0] <> '0') -> Some n
      | _ -> None
    in
    match (part a, part b, part c, part d) with
    | Some a, Some b, Some c, Some d ->
      Ok (String.init 4 (fun i -> Char.chr (List.nth [ a; b; c; d ] i)))
    | _ -> Error "multiaddr: malformed ip4 address")
  | _ -> Error "multiaddr: malformed ip4 address"

(* RFC 5952: lower-case hex, the longest run of two or more zero groups
   collapsed to "::", leftmost run winning a tie. *)
let ip6_to_string v =
  let g = Array.init 8 (fun i -> be16 (String.sub v (i * 2) 2)) in
  let best_start = ref (-1) and best_len = ref 0 in
  let i = ref 0 in
  while !i < 8 do
    if g.(!i) = 0 then begin
      let j = ref !i in
      while !j < 8 && g.(!j) = 0 do incr j done;
      let len = !j - !i in
      if len > !best_len then begin
        best_len := len;
        best_start := !i
      end;
      i := !j
    end
    else incr i
  done;
  let hex k = Printf.sprintf "%x" g.(k) in
  if !best_len < 2 then String.concat ":" (List.init 8 hex)
  else begin
    let left = List.init !best_start hex in
    let after = !best_start + !best_len in
    let right = List.init (8 - after) (fun k -> hex (after + k)) in
    String.concat ":" left ^ "::" ^ String.concat ":" right
  end

let ip6_of_string s =
  let parse_group g =
    if String.length g = 0 || String.length g > 4 then None
    else if
      String.for_all
        (fun c ->
          (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
        g
    then int_of_string_opt ("0x" ^ g)
    else None
  in
  let parse_groups l =
    List.fold_right
      (fun g acc ->
        match (parse_group g, acc) with Some v, Some tl -> Some (v :: tl) | _ -> None)
      l (Some [])
  in
  let split_nonempty str =
    List.filter (fun x -> x <> "") (String.split_on_char ':' str)
  in
  let find_dc str =
    let n = String.length str in
    let rec go i =
      if i + 1 >= n then None else if str.[i] = ':' && str.[i + 1] = ':' then Some i else go (i + 1)
    in
    go 0
  in
  let has_dc str = find_dc str <> None in
  match find_dc s with
  | Some i ->
    let left = String.sub s 0 i and right = String.sub s (i + 2) (String.length s - i - 2) in
    (* exactly one "::" is permitted *)
    if has_dc left || has_dc right then Error "multiaddr: malformed ip6 address"
    else if (left <> "" && left.[String.length left - 1] = ':')
            || (right <> "" && right.[0] = ':')
    then Error "multiaddr: malformed ip6 address"
    else (
      match (parse_groups (split_nonempty left), parse_groups (split_nonempty right)) with
      | Some l, Some r ->
        let fill = 8 - List.length l - List.length r in
        (* "::" must stand for at least one group, else it should have been
           written out in full *)
        if fill < 1 then Error "multiaddr: malformed ip6 address"
        else Ok (String.concat "" (List.map of_be16 (l @ List.init fill (fun _ -> 0) @ r)))
      | _ -> Error "multiaddr: malformed ip6 address")
  | None -> (
    let gs = String.split_on_char ':' s in
    if List.length gs <> 8 then Error "multiaddr: malformed ip6 address"
    else
      match parse_groups gs with
      | Some l -> Ok (String.concat "" (List.map of_be16 l))
      | None -> Error "multiaddr: malformed ip6 address")

let port_to_string v = string_of_int (be16 v)

let port_of_string s =
  match int_of_string_opt s with
  | Some n when n >= 0 && n <= 65535 -> Ok (of_be16 n)
  | _ -> Error "multiaddr: port out of range"

(* onion is 10 address bytes + 2 port bytes, onion3 is 35 + 2 *)
let onion_to_string ~addr_len v =
  let a = String.sub v 0 addr_len and p = String.sub v addr_len 2 in
  Base32.encode a ^ ":" ^ string_of_int (be16 p)

let onion_of_string ~addr_len s =
  match String.rindex_opt s ':' with
  | None -> Error "multiaddr: onion address needs a :port"
  | Some i -> (
    let a = String.sub s 0 i and p = String.sub s (i + 1) (String.length s - i - 1) in
    match Base32.decode a with
    | Error m -> Error m
    | Ok raw ->
      if String.length raw <> addr_len then
        Error (Printf.sprintf "multiaddr: onion address must be %d bytes" addr_len)
      else (
        match int_of_string_opt p with
        | Some n when n > 0 && n <= 65535 -> Ok (raw ^ of_be16 n)
        | _ -> Error "multiaddr: onion port out of range"))

let value_to_string p v =
  match p.name with
  | "ip4" -> Ok (ip4_to_string v)
  | "ip6" -> Ok (ip6_to_string v)
  | "tcp" | "udp" | "dccp" | "sctp" -> Ok (port_to_string v)
  | "p2p" -> (
    match Multihash.of_octets v with
    | Ok _ -> Ok (Basen.encode ~name:"p2p" Basen.btc v)
    | Error m -> Error m)
  | "onion" -> Ok (onion_to_string ~addr_len:10 v)
  | "onion3" -> Ok (onion_to_string ~addr_len:35 v)
  | "certhash" -> Ok (Multibase.encode Multibase.Base64url v)
  | _ -> Ok v (* dns, unix, sni, garlic, memory, ip6zone: plain text *)

let value_of_string p s =
  match p.name with
  | "ip4" -> ip4_of_string s
  | "ip6" -> ip6_of_string s
  | "tcp" | "udp" | "dccp" | "sctp" -> port_of_string s
  | "p2p" -> (
    match Basen.decode ~name:"p2p" Basen.btc s with
    | Error m -> Error m
    | Ok raw -> ( match Multihash.of_octets raw with Ok _ -> Ok raw | Error m -> Error m))
  | "onion" -> onion_of_string ~addr_len:10 s
  | "onion3" -> onion_of_string ~addr_len:35 s
  | "certhash" -> (
    match Multibase.decode s with Ok (_, v) -> Ok v | Error m -> Error m)
  | _ -> if s = "" then Error ("multiaddr: " ^ p.name ^ " needs a value") else Ok s

(* ---- binary ---- *)

let to_octets t =
  String.concat ""
    (List.map
       (fun c ->
         let head = Varint.write c.proto.code in
         match c.proto.size with
         | Zero -> head
         | Fixed _ -> head ^ c.value
         | Variable -> head ^ Varint.write (String.length c.value) ^ c.value)
       t)

let of_octets s =
  let n = String.length s in
  let rec go pos acc =
    if pos = n then Ok (List.rev acc)
    else
      match Varint.read_result s pos with
      | Error m -> Error m
      | Ok (code, pos) -> (
        match proto_of_code code with
        | None ->
          (* refusing beats guessing: an unknown width would silently
             re-frame every component after this one *)
          Error (Printf.sprintf "multiaddr: unknown protocol code 0x%x" code)
        | Some p -> (
          match p.size with
          | Zero -> go pos ({ proto = p; value = "" } :: acc)
          | Fixed k ->
            if pos + k > n then Error ("multiaddr: truncated " ^ p.name)
            else go (pos + k) ({ proto = p; value = String.sub s pos k } :: acc)
          | Variable -> (
            match Varint.read_result s pos with
            | Error m -> Error m
            | Ok (len, pos) ->
              if len > n - pos then Error ("multiaddr: truncated " ^ p.name)
              else go (pos + len) ({ proto = p; value = String.sub s pos len } :: acc))))
  in
  go 0 []

(* ---- text ---- *)

let to_string t =
  let b = Buffer.create 64 in
  List.iter
    (fun c ->
      Buffer.add_char b '/';
      Buffer.add_string b c.proto.name;
      match c.proto.size with
      | Zero -> ()
      | _ -> (
        match value_to_string c.proto c.value with
        | Ok s ->
          if c.proto.is_path then Buffer.add_string b (if s <> "" && s.[0] = '/' then s else "/" ^ s)
          else begin Buffer.add_char b '/'; Buffer.add_string b s end
        | Error _ -> Buffer.add_string b "/?"))
    t;
  Buffer.contents b

let of_string s =
  if String.length s = 0 || s.[0] <> '/' then Error "multiaddr: must start with '/'"
  else begin
    let parts = String.split_on_char '/' s in
    (* leading '/' yields an empty first element *)
    let parts = match parts with "" :: tl -> tl | l -> l in
    let rec go parts acc =
      match parts with
      | [] -> Ok (List.rev acc)
      | name :: rest -> (
        match proto_of_name name with
        | None -> Error (Printf.sprintf "multiaddr: unknown protocol %S" name)
        | Some p -> (
          match p.size with
          | Zero -> go rest ({ proto = p; value = "" } :: acc)
          | _ ->
            if p.is_path then
              (* a path protocol takes everything left, slashes included *)
              let path = "/" ^ String.concat "/" rest in
              if path = "/" then Error ("multiaddr: " ^ p.name ^ " needs a path")
              else
                match value_of_string p path with
                | Error m -> Error m
                | Ok v -> Ok (List.rev ({ proto = p; value = v } :: acc))
            else (
              match rest with
              | [] -> Error (Printf.sprintf "multiaddr: %s needs a value" p.name)
              | v :: rest -> (
                match value_of_string p v with
                | Error m -> Error m
                | Ok raw ->
                  let ok =
                    match p.size with Fixed k -> String.length raw = k | _ -> true
                  in
                  if not ok then Error (Printf.sprintf "multiaddr: %s has the wrong width" p.name)
                  else go rest ({ proto = p; value = raw } :: acc)))))
    in
    (* a trailing '/' leaves an empty element; reject rather than ignore *)
    if List.exists (fun p -> p = "") parts then Error "multiaddr: empty component"
    else go parts []
  end

let protocols t = List.map (fun c -> c.proto) t
let encapsulate a b = a @ b
let equal a b = String.equal (to_octets a) (to_octets b)
