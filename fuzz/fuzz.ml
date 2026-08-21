(* Mutation fuzzer for every decoder in the library.

   Uniform random bytes almost never form a valid header, so they exercise
   the first length check and little else. This instead starts from a
   corpus of *valid* encodings and mutates them -- bit flips, byte
   substitutions, truncations, extensions, splices -- which keeps the input
   near the boundary where the interesting branches live.

   Two invariants are checked on every input:

     1. no decoder raises; a function whose type says [result] must return
        one, including for [Z.Overflow], [Invalid_argument] and
        [Out_of_memory].
     2. for the formats that promise a canonical encoding (RLP, SCALE
        compact, Borsh byte strings), anything that decodes must re-encode
        to exactly the bytes it came from.

   Run: dune exec fuzz/fuzz.exe -- [iterations] [seed] *)

open Web3_codec

let hexenc s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let failures = ref 0
let report kind input msg =
  incr failures;
  Printf.printf "\n!! %s\n   input: %s\n   %s\n%!" kind (hexenc input) msg

(* ---- corpus of valid encodings ---- *)

let corpus =
  let rlp =
    List.map Rlp.encode
      Rlp.[ Str "dog"; Str ""; List []; of_int 0; of_int 1024;
            List [ Str "cat"; Str "dog" ];
            Str (String.make 60 'x');
            List [ List []; List [ List [] ]; List [ List []; List [ List [] ] ] ];
            List (List.init 30 (fun i -> Str (String.make (i mod 5) 'a'))) ]
  in
  let scale =
    List.map Scale.encode_compact
      (List.map Z.of_string [ "0"; "1"; "63"; "64"; "16383"; "16384"; "1073741823";
                              "1073741824"; "100000000000000";
                              "340282366920938463463374607431768211455" ])
    @ [ Scale.encode_bytes ""; Scale.encode_bytes "hello"; Scale.encode_bytes (String.make 200 'z') ]
  in
  let borsh =
    [ Borsh.encode_bytes ""; Borsh.encode_bytes "hello";
      Borsh.encode_string "héllo ☃";
      Borsh.encode_vec Borsh.encode_u8 [ 1; 2; 3; 255 ];
      Borsh.encode_option Borsh.encode_u32 (Some 999);
      Borsh.encode_option Borsh.encode_u32 None;
      Borsh.encode_u64 (Z.of_string "18446744073709551615") ]
  in
  let b58 =
    [ "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"; "2g"; "1"; "11";
      Base58.encode_check (String.make 20 '\x01');
      Base58.encode (String.make 32 '\xab') ]
  in
  let bech32 =
    [ "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
      "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5";
      "A1LQFN3A"; "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx" ]
  in
  let ss58 = [ Ss58.encode ~network:42 (String.make 32 '\xd4'); Ss58.encode ~network:0 (String.make 32 '\x01') ] in
  let abi =
    [ Abi.encode_exn [ Abi.Uint (Z.of_int 69); Abi.Bool true ];
      Abi.encode_exn [ Abi.Bytes "dave"; Abi.Bool true;
                       Abi.Array [ Abi.Uint Z.one; Abi.Uint (Z.of_int 2) ] ];
      Abi.encode_exn [ Abi.Address (String.make 20 '\x5b'); Abi.Uint (Z.of_int 1000000) ];
      Abi.encode_exn [ Abi.Tuple [ Abi.Uint (Z.of_int 7); Abi.Address (String.make 20 '\x02') ] ];
      Abi.encode_exn [ Abi.String "Hello, world!" ] ]
  in
  let multiformats =
    let mh c p = Multihash.to_octets (Result.get_ok (Multihash.digest (Multicodec.of_code c) p)) in
    let sha = Result.get_ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
    let cid = Cid.v1 ~codec:(Multicodec.of_code 0x55) sha in
    let v0 = Result.get_ok (Cid.v0 sha) in
    List.map Varint.write [ 0; 1; 127; 128; 255; 300; 16384; 0x7fffffff ]
    @ [ mh 0x12 "hello world"; mh 0x00 ""; mh 0x16 "abc"; mh 0xb220 "abc" ]
    @ [ Cid.to_octets cid; Cid.to_octets v0 ]
    @ List.map (fun b -> Cid.to_string ~base:b cid) Multibase.all
    @ [ Cid.to_string v0 ]
    @ List.map (fun b -> Multibase.encode b "yes mani !") Multibase.all
    @ List.filter_map
        (fun a -> match Multiaddr.of_string a with Ok m -> Some (Multiaddr.to_octets m) | Error _ -> None)
        [ "/ip4/127.0.0.1/udp/1234"; "/ip6/::1/tcp/8080"; "/dns4/example.com/tcp/443/tls/ws";
          "/unix/tmp/p2p.sock"; "/ip4/1.2.3.4/udp/4001/quic-v1/webtransport";
          "/ip4/127.0.0.1/tcp/1234/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC" ]
    @ [ Multistream.encode_message Multistream.protocol_id;
        Multistream.encode_message "/ipfs/id/1.0.0";
        Multistream.encode_message "na" ]
    @ [ Multikey.to_octets
          (Result.get_ok
             (Multikey.make ~codec:(Multicodec.of_code 0xed) ~key:(String.make 32 '\xab'))) ]
  in
  Array.of_list (rlp @ scale @ borsh @ b58 @ bech32 @ ss58 @ abi @ multiformats)

(* ---- mutation ---- *)

let mutate st s =
  let n = String.length s in
  let b = Bytes.of_string s in
  match Random.State.int st 7 with
  | 0 when n > 0 -> (* bit flip *)
    let i = Random.State.int st n in
    Bytes.set b i (Char.chr (Char.code (Bytes.get b i) lxor (1 lsl Random.State.int st 8)));
    Bytes.to_string b
  | 1 when n > 0 -> (* byte substitution *)
    let i = Random.State.int st n in
    Bytes.set b i (Char.chr (Random.State.int st 256));
    Bytes.to_string b
  | 2 when n > 0 -> (* truncate *)
    String.sub s 0 (Random.State.int st n)
  | 3 -> (* extend *)
    s ^ String.init (1 + Random.State.int st 8) (fun _ -> Char.chr (Random.State.int st 256))
  | 4 -> (* splice with another corpus entry *)
    let t = corpus.(Random.State.int st (Array.length corpus)) in
    let cut = if n = 0 then 0 else Random.State.int st n in
    String.sub s 0 cut ^ t
  | 5 when n > 0 -> (* set a byte to an interesting boundary value *)
    let i = Random.State.int st n in
    let interesting = [| 0x00; 0x01; 0x7f; 0x80; 0xb7; 0xb8; 0xbf; 0xc0; 0xf7; 0xf8; 0xff |] in
    Bytes.set b i (Char.chr interesting.(Random.State.int st (Array.length interesting)));
    Bytes.to_string b
  | _ -> (* fresh random bytes *)
    String.init (Random.State.int st 64) (fun _ -> Char.chr (Random.State.int st 256))

(* ---- the checks ---- *)

let abi_tys =
  Abi.[ [ TUint 256 ]; [ TAddress; TUint 256 ]; [ TBytes ]; [ TString ];
        [ TArray (TUint 256) ]; [ TBytes; TBool; TArray (TUint 256) ];
        [ TTuple [ TUint 64; TAddress ] ]; [ TArray TBytes ];
        [ TFixedArray (TUint 256, 3) ]; [ TInt 8 ]; [ TBool ]; [ TFixedBytes 4 ] ]

let check input =
  (* invariant 1: never raises *)
  let guard name f =
    try f () with e -> report ("RAISED from " ^ name) input (Printexc.to_string e)
  in
  guard "Rlp.decode" (fun () ->
      match Rlp.decode input with
      | Error _ -> ()
      | Ok v ->
        (* invariant 2: canonical *)
        let re = Rlp.encode v in
        if not (String.equal re input) then
          report "RLP NON-CANONICAL" input ("re-encoded as " ^ hexenc re));
  guard "Scale.compact_of_octets" (fun () ->
      match Scale.compact_of_octets input with
      | Error _ -> ()
      | Ok z ->
        let re = Scale.encode_compact z in
        if not (String.equal re input) then
          report "SCALE COMPACT NON-CANONICAL" input ("re-encoded as " ^ hexenc re));
  guard "Scale.bytes_of_octets" (fun () -> ignore (Scale.bytes_of_octets input));
  guard "Borsh.read_bytes" (fun () ->
      match Borsh.of_octets Borsh.read_bytes input with
      | Error _ -> ()
      | Ok v ->
        let re = Borsh.encode_bytes v in
        if not (String.equal re input) then
          report "BORSH BYTES NON-CANONICAL" input ("re-encoded as " ^ hexenc re));
  guard "Borsh.read_string" (fun () -> ignore (Borsh.of_octets Borsh.read_string input));
  guard "Borsh.read_vec" (fun () -> ignore (Borsh.of_octets (Borsh.read_vec Borsh.read_u8) input));
  guard "Borsh.read_option" (fun () -> ignore (Borsh.of_octets (Borsh.read_option Borsh.read_u32) input));
  guard "Borsh.read_i64" (fun () -> ignore (Borsh.of_octets Borsh.read_i64 input));
  guard "Base58.decode" (fun () -> ignore (Base58.decode input));
  guard "Base58.decode_check" (fun () -> ignore (Base58.decode_check input));
  guard "Bech32.decode" (fun () -> ignore (Bech32.decode input));
  guard "Bech32.decode_segwit" (fun () -> ignore (Bech32.decode_segwit ~hrp:"bc" input));
  guard "Ss58.decode" (fun () -> ignore (Ss58.decode input));
  List.iter
    (fun tys ->
      guard "Abi.decode" (fun () -> ignore (Abi.decode tys input));
      guard "Abi.decode_call" (fun () -> ignore (Abi.decode_call tys input)))
    abi_tys;
  (* ---- multiformats: the same two invariants ---- *)
  let canonical name decode encode =
    guard name (fun () ->
        match decode input with
        | Error _ -> ()
        | Ok v ->
          let re = encode v in
          if not (String.equal re input) then
            report (String.uppercase_ascii name ^ " NON-CANONICAL") input ("re-encoded as " ^ hexenc re))
  in
  canonical "Varint.of_octets" Varint.of_octets Varint.write;
  canonical "Multihash.of_octets" Multihash.of_octets Multihash.to_octets;
  canonical "Cid.of_octets" Cid.of_octets Cid.to_octets;
  canonical "Multiaddr.of_octets" Multiaddr.of_octets Multiaddr.to_octets;
  canonical "Multistream.decode" Multistream.decode_message Multistream.encode_message;
  canonical "Multikey.of_octets" Multikey.of_octets Multikey.to_octets;
  canonical "Multibase.decode" Multibase.decode (fun (b, v) -> Multibase.encode b v);
  canonical "Base16.decode" Base16.decode Base16.encode;
  canonical "Base32.decode" Base32.decode Base32.encode;
  canonical "Base64.decode" Base64.decode Base64.encode;
  guard "Base32.decode ~pad" (fun () -> ignore (Base32.decode ~pad:true input));
  guard "Base64.decode ~pad" (fun () -> ignore (Base64.decode ~pad:true input));
  guard "Cid.of_string" (fun () -> ignore (Cid.of_string input));
  guard "Multiaddr.of_string" (fun () -> ignore (Multiaddr.of_string input));
  guard "Multikey.of_did_key" (fun () -> ignore (Multikey.of_did_key input))

(* A fuzzer that reports nothing is indistinguishable from a fuzzer that
   checks nothing, so prove the two detection paths actually fire. *)
let selftest () =
  let before = !failures in
  (try (fun () -> raise (Failure "planted")) () with e -> report "RAISED from planted" "" (Printexc.to_string e));
  if !failures <> before + 1 then (print_endline "SELFTEST FAILED: raise not detected"; exit 2);
  let v = Rlp.Str "dog" in
  let wrong = Rlp.encode v ^ "\x00" in
  if String.equal (Rlp.encode v) wrong then (print_endline "SELFTEST FAILED: comparison vacuous"; exit 2);
  report "NON-CANONICAL (planted)" wrong "planted mismatch";
  if !failures <> before + 2 then (print_endline "SELFTEST FAILED: mismatch not reported"; exit 2);
  (* the varint minimality rule -- the multiformats analogue of the RLP
     length-field overflow -- must reject the non-minimal spelling of 1 *)
  (match Varint.of_octets "\x81\x00" with
   | Ok _ -> print_endline "SELFTEST FAILED: non-minimal varint still accepted"; exit 2
   | Error _ -> ());
  (* the pre-hardening RLP malleability case must now be rejected outright *)
  (match Rlp.decode ("\xff\x80\x00\x00\x00\x00\x00\x00\x64" ^ String.make 100 '\x01') with
   | Ok _ -> print_endline "SELFTEST FAILED: RLP overflow input still accepted"; exit 2
   | Error _ -> ());
  failures := before;
  print_endline "selftest ok: raises are caught, mismatches are reported"

let () =
  if Array.length Sys.argv > 1 && Sys.argv.(1) = "selftest" then (selftest (); exit 0);
  let iters = try int_of_string Sys.argv.(1) with _ -> 200_000 in
  let seed = try int_of_string Sys.argv.(2) with _ -> 0 in
  let st = Random.State.make [| seed |] in
  Printf.printf "fuzzing %d iterations, seed %d, corpus of %d\n%!" iters seed (Array.length corpus);
  (* every corpus entry unmutated first *)
  Array.iter check corpus;
  let cur = ref corpus.(0) in
  for i = 1 to iters do
    (* mutate either a corpus entry or the previous input, to build chains *)
    let base =
      if Random.State.int st 2 = 0 then corpus.(Random.State.int st (Array.length corpus)) else !cur
    in
    let input = mutate st base in
    cur := input;
    check input;
    if i mod 50_000 = 0 then Printf.printf "  %d/%d, %d failures\n%!" i iters !failures
  done;
  Printf.printf "\ndone: %d iterations, %d failures\n" iters !failures;
  exit (if !failures = 0 then 0 else 1)
