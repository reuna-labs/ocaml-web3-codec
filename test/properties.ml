(* Property tests.

   Three kinds:
     - round-trip:      decode (encode x) = x
     - non-malleability: decode s = Ok x  =>  encode x = s
     - robustness:      no decoder raises on arbitrary bytes

   The second is the interesting one. It says a value has exactly one
   encoding, which is what makes a hash over these bytes meaningful, and it
   is a statement about *all* inputs -- the kind of claim a hand-written
   vector cannot make. *)

open Web3_codec

let hexenc s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let byte = QCheck.Gen.(map Char.chr (int_range 0 255))
let bytes_len n = QCheck.Gen.(string_size ~gen:byte (return n))
let bytes_upto n = QCheck.Gen.(string_size ~gen:byte (int_range 0 n))
let arb_bytes = QCheck.make ~print:hexenc (bytes_upto 300)

let rec gen_all = function
  | [] -> QCheck.Gen.return []
  | g :: gs -> QCheck.Gen.(g >>= fun x -> gen_all gs >|= fun xs -> x :: xs)

let z_of_be s =
  String.fold_left (fun a c -> Z.add (Z.mul a (Z.of_int 256)) (Z.of_int (Char.code c))) Z.zero s

(* ---------------- RLP ---------------- *)

let rec rlp_gen depth =
  let open QCheck.Gen in
  let leaf = map (fun s -> Rlp.Str s) (bytes_upto 70) in
  if depth <= 0 then leaf
  else oneof_weighted [ (3, leaf); (1, map (fun l -> Rlp.List l) (list_size (int_range 0 4) (rlp_gen (depth - 1)))) ]

let rec rlp_print = function
  | Rlp.Str s -> Printf.sprintf "Str %S" s
  | Rlp.List l -> "List [" ^ String.concat "; " (List.map rlp_print l) ^ "]"

let arb_rlp = QCheck.make ~print:rlp_print (rlp_gen 3)

let rlp_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"rlp: decode (encode x) = x" arb_rlp (fun v ->
      match Rlp.decode (Rlp.encode v) with Ok v' -> v' = v | Error _ -> false)

(* If two byte strings decoded to the same value, an RLP hash would not
   pin down the payload. *)
let rlp_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"rlp: decode s = Ok x => encode x = s" arb_bytes
    (fun s -> match Rlp.decode s with Ok v -> String.equal (Rlp.encode v) s | Error _ -> true)

(* ---------------- SCALE ---------------- *)

let arb_nat =
  QCheck.make ~print:Z.to_string
    QCheck.Gen.(
      oneof_weighted
        [ (3, map Z.of_int (int_range 0 1_000_000));
          (2, map z_of_be (bytes_upto 8));
          (1, map z_of_be (bytes_upto 40)) ])

let scale_compact_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"scale: compact_of_octets (encode_compact z) = z" arb_nat
    (fun z -> Scale.compact_of_octets (Scale.encode_compact z) = Ok z)

let scale_compact_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"scale: compact decode/encode is a bijection" arb_bytes
    (fun s ->
      match Scale.compact_of_octets s with
      | Ok z -> String.equal (Scale.encode_compact z) s
      | Error _ -> true)

let scale_bytes_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"scale: bytes round-trip"
    (QCheck.make ~print:hexenc (bytes_upto 200))
    (fun s -> Scale.bytes_of_octets (Scale.encode_bytes s) = Ok s)

(* ---------------- Borsh ---------------- *)

let borsh_u64_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"borsh: u64 round-trip"
    (QCheck.make ~print:Z.to_string QCheck.Gen.(map z_of_be (bytes_len 8)))
    (fun z -> Borsh.of_octets Borsh.read_u64 (Borsh.encode_u64 z) = Ok z)

let borsh_i64_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"borsh: i64 round-trip"
    (QCheck.make ~print:Z.to_string
       QCheck.Gen.(map (fun s ->
           let z = z_of_be s and half = Z.shift_left Z.one 63 in
           if Z.geq z half then Z.sub z (Z.shift_left Z.one 64) else z) (bytes_len 8)))
    (fun z -> Borsh.of_octets Borsh.read_i64 (Borsh.encode_i64 z) = Ok z)

let borsh_vec_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"borsh: vec u8 round-trip"
    (QCheck.make QCheck.Gen.(list_size (int_range 0 50) (int_range 0 255)))
    (fun xs ->
      Borsh.of_octets (Borsh.read_vec Borsh.read_u8) (Borsh.encode_vec Borsh.encode_u8 xs) = Ok xs)

let borsh_bytes_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"borsh: bytes decode/encode is a bijection" arb_bytes
    (fun s ->
      match Borsh.of_octets Borsh.read_bytes s with
      | Ok v -> String.equal (Borsh.encode_bytes v) s
      | Error _ -> true)

(* ---------------- Base58 / SS58 ---------------- *)

let base58_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"base58: decode (encode s) = s"
    (QCheck.make ~print:hexenc (bytes_upto 120))
    (fun s -> Base58.decode (Base58.encode s) = Ok s)

let base58check_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"base58check: decode_check (encode_check s) = s"
    (QCheck.make ~print:hexenc (bytes_upto 120))
    (fun s -> Base58.decode_check (Base58.encode_check s) = Ok s)

(* A single corrupted character must never pass the checksum. *)
let base58check_detects_corruption =
  QCheck.Test.make ~count:3000 ~name:"base58check: single-character corruption is caught"
    (QCheck.make
       ~print:(fun (s, i, c) -> Printf.sprintf "%s/%d/%c" (hexenc s) i c)
       QCheck.Gen.(triple (bytes_upto 40) (int_range 0 200) (oneof_list (List.init 58 (fun i -> "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".[i])))))
    (fun (payload, i, c) ->
      let enc = Base58.encode_check payload in
      let i = i mod String.length enc in
      if enc.[i] = c then true
      else
        let corrupted = String.mapi (fun j ch -> if j = i then c else ch) enc in
        (* it must be rejected outright, or -- if the 32-bit checksum
           happens to survive -- still yield the original payload. What it
           must never do is quietly hand back a *different* payload. *)
        match Base58.decode_check corrupted with
        | Ok p -> String.equal p payload
        | Error _ -> true)

let ss58_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"ss58: decode (encode ~network k) = (network, k)"
    (QCheck.make QCheck.Gen.(pair (int_range 0 63) (bytes_len 32)))
    (fun (network, k) -> Ss58.decode (Ss58.encode ~network k) = Ok (network, k))

(* ---------------- Bech32 ---------------- *)

let arb_segwit =
  QCheck.make
    ~print:(fun (v, p) -> Printf.sprintf "v%d/%s" v (hexenc p))
    QCheck.Gen.(
      int_range 0 16 >>= fun version ->
      (if version = 0 then oneof_list [ 20; 32 ] else int_range 2 40) >>= fun len ->
      bytes_len len >|= fun program -> (version, program))

let bech32_segwit_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"bech32: segwit address round-trip" arb_segwit
    (fun (version, program) ->
      match Bech32.encode_segwit ~hrp:"bc" ~version ~program with
      | Error _ -> false
      | Ok addr -> Bech32.decode_segwit ~hrp:"bc" addr = Ok (version, program))

(* Uppercasing an address must not change what it means. *)
let bech32_case_insensitive =
  QCheck.Test.make ~count:1000 ~name:"bech32: uppercase decodes identically" arb_segwit
    (fun (version, program) ->
      match Bech32.encode_segwit ~hrp:"bc" ~version ~program with
      | Error _ -> false
      | Ok addr ->
        Bech32.decode_segwit ~hrp:"BC" (String.uppercase_ascii addr)
        = Ok (version, program))

(* ---------------- ABI ---------------- *)

let gen_uint nbits = QCheck.Gen.(map z_of_be (bytes_len (nbits / 8)))

let gen_sint nbits =
  QCheck.Gen.(
    map
      (fun s ->
        let z = z_of_be s and half = Z.shift_left Z.one (nbits - 1) in
        if Z.geq z half then Z.sub z (Z.shift_left Z.one nbits) else z)
      (bytes_len (nbits / 8)))

let rec gen_value ty =
  let open QCheck.Gen in
  match ty with
  | Abi.TUint n -> map (fun z -> Abi.Uint z) (gen_uint n)
  | Abi.TInt n -> map (fun z -> Abi.Int z) (gen_sint n)
  | Abi.TBool -> map (fun b -> Abi.Bool b) bool
  | Abi.TAddress -> map (fun s -> Abi.Address s) (bytes_len 20)
  | Abi.TFixedBytes n -> map (fun s -> Abi.FixedBytes s) (bytes_len n)
  | Abi.TBytes -> map (fun s -> Abi.Bytes s) (bytes_upto 80)
  | Abi.TString -> map (fun s -> Abi.String s) (bytes_upto 80)
  | Abi.TArray t -> map (fun l -> Abi.Array l) (list_size (int_range 0 4) (gen_value t))
  | Abi.TFixedArray (t, k) -> map (fun l -> Abi.FixedArray l) (list_size (return k) (gen_value t))
  | Abi.TTuple ts -> map (fun l -> Abi.Tuple l) (gen_all (List.map gen_value ts))

let abi_tys =
  Abi.[
    [ TUint 256 ]; [ TInt 8 ]; [ TInt 256 ]; [ TUint 32; TBool ]; [ TAddress; TUint 256 ];
    [ TBytes ]; [ TString ]; [ TFixedBytes 4 ]; [ TFixedBytes 32 ];
    [ TArray (TUint 256) ]; [ TArray TBytes ]; [ TBytes; TBool; TArray (TUint 256) ];
    [ TFixedArray (TUint 256, 3) ]; [ TTuple [ TUint 64; TAddress ] ];
    [ TArray (TTuple [ TUint 8; TBool ]) ]; [ TTuple [ TBytes; TArray (TUint 16) ] ];
  ]

let abi_roundtrip =
  let arb =
    QCheck.make
      QCheck.Gen.(
        oneof_list abi_tys >>= fun tys -> gen_all (List.map gen_value tys) >|= fun vs -> (tys, vs))
  in
  QCheck.Test.make ~count:3000 ~name:"abi: decode (encode v) = v" arb (fun (tys, vs) ->
      match Abi.encode vs with
      | Error _ -> false
      | Ok enc -> ( match Abi.decode tys enc with Ok vs' -> vs' = vs | Error _ -> false))

(* ---------------- robustness: decoders never raise ---------------- *)

let no_raise name f =
  QCheck.Test.make ~count:4000 ~name:("never raises: " ^ name) arb_bytes (fun s ->
      match f s with
      | () -> true
      | exception e ->
        Printf.eprintf "\n%s raised %s on %s\n" name (Printexc.to_string e) (hexenc s);
        false)

let robustness =
  [ no_raise "Rlp.decode" (fun s -> ignore (Rlp.decode s));
    no_raise "Base58.decode" (fun s -> ignore (Base58.decode s));
    no_raise "Base58.decode_check" (fun s -> ignore (Base58.decode_check s));
    no_raise "Bech32.decode" (fun s -> ignore (Bech32.decode s));
    no_raise "Bech32.decode_segwit" (fun s -> ignore (Bech32.decode_segwit ~hrp:"bc" s));
    no_raise "Ss58.decode" (fun s -> ignore (Ss58.decode s));
    no_raise "Scale.compact_of_octets" (fun s -> ignore (Scale.compact_of_octets s));
    no_raise "Scale.bytes_of_octets" (fun s -> ignore (Scale.bytes_of_octets s));
    no_raise "Borsh.of_octets read_bytes" (fun s -> ignore (Borsh.of_octets Borsh.read_bytes s));
    no_raise "Borsh.of_octets read_string" (fun s -> ignore (Borsh.of_octets Borsh.read_string s));
    no_raise "Borsh.of_octets read_vec u8"
      (fun s -> ignore (Borsh.of_octets (Borsh.read_vec Borsh.read_u8) s));
    no_raise "Borsh.of_octets read_option u32"
      (fun s -> ignore (Borsh.of_octets (Borsh.read_option Borsh.read_u32) s)) ]
  @ List.map
      (fun tys ->
        no_raise "Abi.decode" (fun s -> ignore (Abi.decode tys s)))
      abi_tys
  @ [ no_raise "Abi.decode_call"
        (fun s -> ignore (Abi.decode_call Abi.[ TAddress; TUint 256 ] s)) ]


(* ---------------- multiformats ---------------- *)

(* Varint minimality is the substrate property: every format below is
   content-addressed, so a value with two spellings is a malleability
   vector. *)
let varint_roundtrip =
  QCheck.Test.make ~count:5000 ~name:"varint: of_octets (write n) = n"
    (QCheck.make ~print:string_of_int QCheck.Gen.(int_range 0 max_int))
    (fun n -> Varint.of_octets (Varint.write n) = Ok n)

let varint_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"varint: decode s = Ok n => write n = s" arb_bytes
    (fun s ->
      match Varint.of_octets s with
      | Ok n -> String.equal (Varint.write n) s
      | Error _ -> true)

let arb_base = QCheck.make ~print:Multibase.name (QCheck.Gen.oneof_list Multibase.all)

let multibase_roundtrip =
  QCheck.Test.make ~count:4000 ~name:"multibase: decode (encode b s) = (b, s)"
    (QCheck.make
       ~print:(fun (b, s) -> Multibase.name b ^ "/" ^ hexenc s)
       QCheck.Gen.(pair (oneof_list Multibase.all) (bytes_upto 120)))
    (fun (b, s) -> Multibase.decode (Multibase.encode b s) = Ok (b, s))

(* Text CIDs are compared as strings, so one payload must have exactly one
   spelling per base. *)
let multibase_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"multibase: decode s = Ok (b,v) => encode b v = s"
    (QCheck.make ~print:(fun s -> s)
       QCheck.Gen.(
         string_size ~gen:(oneof_list (List.init 96 (fun i -> Char.chr (i + 31)))) (int_range 0 40)))
    (fun s ->
      match Multibase.decode s with
      | Ok (b, v) -> String.equal (Multibase.encode b v) s
      | Error _ -> true)

let arb_multihash =
  QCheck.make
    ~print:Multihash.to_string
    QCheck.Gen.(
      pair (oneof_list [ 0x00; 0x11; 0x12; 0x13; 0x16; 0x1b; 0x1e; 0xb220; 0x9999 ]) (bytes_upto 64)
      >|= fun (c, d) -> Multihash.make ~code:(Multicodec.of_code c) ~digest:d)

let multihash_roundtrip =
  QCheck.Test.make ~count:4000 ~name:"multihash: of_octets (to_octets h) = h" arb_multihash
    (fun h ->
      match Multihash.of_octets (Multihash.to_octets h) with
      | Ok h' ->
        Multihash.code h' = Multihash.code h
        && String.equal (Multihash.digest_bytes h') (Multihash.digest_bytes h)
      | Error _ -> false)

let multihash_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"multihash: decode s = Ok h => encode h = s" arb_bytes
    (fun s ->
      match Multihash.of_octets s with
      | Ok h -> String.equal (Multihash.to_octets h) s
      | Error _ -> true)

let arb_cid =
  QCheck.make ~print:Cid.to_string
    QCheck.Gen.(
      pair (oneof_list [ 0x55; 0x70; 0x71; 0x72; 0x0129 ]) (bytes_upto 200)
      >|= fun (codec, payload) ->
      let h = Result.get_ok (Multihash.digest (Multicodec.of_code 0x12) payload) in
      Cid.v1 ~codec:(Multicodec.of_code codec) h)

let cid_roundtrip =
  QCheck.Test.make ~count:3000 ~name:"cid: of_octets (to_octets c) = c" arb_cid
    (fun c -> match Cid.of_octets (Cid.to_octets c) with Ok c' -> Cid.equal c' c | Error _ -> false)

(* A CID rendered in any base must read back as the same CID. *)
let cid_base_agnostic =
  QCheck.Test.make ~count:2000 ~name:"cid: every base names the same CID"
    (QCheck.make
       ~print:(fun (c, b) -> Cid.to_string ~base:b c)
       QCheck.Gen.(pair (QCheck.gen arb_cid) (oneof_list Multibase.all)))
    (fun (c, b) ->
      match Cid.of_string (Cid.to_string ~base:b c) with
      | Ok c' -> Cid.equal c' c
      | Error _ -> false)

let cid_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"cid: decode s = Ok c => encode c = s" arb_bytes
    (fun s ->
      match Cid.of_octets s with
      | Ok c -> String.equal (Cid.to_octets c) s
      | Error _ -> true)

let multiaddr_strings =
  [ "/ip4/127.0.0.1/udp/1234"; "/ip4/1.2.3.4/tcp/80/http"; "/ip6/::1/tcp/8080";
    "/dns4/example.com/tcp/443/tls/ws"; "/ip4/1.2.3.4/udp/4001/quic-v1";
    "/unix/tmp/p2p.sock"; "/memory/4242"; "/ip6/2001:db8::1/tcp/443/wss";
    "/ip4/127.0.0.1/tcp/1234/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC" ]

let multiaddr_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"multiaddr: text and binary both round-trip"
    (QCheck.make ~print:(fun s -> s) (QCheck.Gen.oneof_list multiaddr_strings))
    (fun a ->
      match Multiaddr.of_string a with
      | Error _ -> false
      | Ok m ->
        String.equal (Multiaddr.to_string m) a
        &&
        (match Multiaddr.of_octets (Multiaddr.to_octets m) with
         | Ok m2 -> Multiaddr.equal m2 m
         | Error _ -> false))

let multiaddr_nonmalleable =
  QCheck.Test.make ~count:5000 ~name:"multiaddr: decode s = Ok m => encode m = s" arb_bytes
    (fun s ->
      match Multiaddr.of_octets s with
      | Ok m -> String.equal (Multiaddr.to_octets m) s
      | Error _ -> true)

let multistream_roundtrip =
  QCheck.Test.make ~count:3000 ~name:"multistream: framing round-trips"
    (QCheck.make ~print:(fun s -> s)
       QCheck.Gen.(
         string_size ~gen:(oneof_list (List.init 95 (fun i -> Char.chr (i + 32)))) (int_range 0 120)))
    (fun p -> Multistream.decode_message (Multistream.encode_message p) = Ok p)

let multistream_nonmalleable =
  QCheck.Test.make ~count:4000 ~name:"multistream: decode s = Ok p => encode p = s" arb_bytes
    (fun s ->
      match Multistream.decode_message s with
      | Ok p -> String.equal (Multistream.encode_message p) s
      | Error _ -> true)

let multiformats_props =
  [ varint_roundtrip; varint_nonmalleable;
    multibase_roundtrip; multibase_nonmalleable;
    multihash_roundtrip; multihash_nonmalleable;
    cid_roundtrip; cid_base_agnostic; cid_nonmalleable;
    multiaddr_roundtrip; multiaddr_nonmalleable;
    multistream_roundtrip; multistream_nonmalleable ]

let multiformats_robustness =
  [ no_raise "Varint.of_octets" (fun s -> ignore (Varint.of_octets s));
    no_raise "Base16.decode" (fun s -> ignore (Base16.decode s));
    no_raise "Base32.decode" (fun s -> ignore (Base32.decode s));
    no_raise "Base32.decode ~pad" (fun s -> ignore (Base32.decode ~pad:true s));
    no_raise "Base64.decode" (fun s -> ignore (Base64.decode s));
    no_raise "Base64.decode ~pad" (fun s -> ignore (Base64.decode ~pad:true s));
    no_raise "Multibase.decode" (fun s -> ignore (Multibase.decode s));
    no_raise "Multihash.of_octets" (fun s -> ignore (Multihash.of_octets s));
    no_raise "Cid.of_octets" (fun s -> ignore (Cid.of_octets s));
    no_raise "Cid.of_string" (fun s -> ignore (Cid.of_string s));
    no_raise "Multiaddr.of_octets" (fun s -> ignore (Multiaddr.of_octets s));
    no_raise "Multiaddr.of_string" (fun s -> ignore (Multiaddr.of_string s));
    no_raise "Multikey.of_octets" (fun s -> ignore (Multikey.of_octets s));
    no_raise "Multikey.of_did_key" (fun s -> ignore (Multikey.of_did_key s));
    no_raise "Multistream.decode_message" (fun s -> ignore (Multistream.decode_message s)) ]

let suite =
  [ ("properties",
     List.map QCheck_alcotest.to_alcotest
       ([ rlp_roundtrip; rlp_nonmalleable;
          scale_compact_roundtrip; scale_compact_nonmalleable; scale_bytes_roundtrip;
          borsh_u64_roundtrip; borsh_i64_roundtrip; borsh_vec_roundtrip; borsh_bytes_nonmalleable;
          base58_roundtrip; base58check_roundtrip; base58check_detects_corruption;
          ss58_roundtrip;
          bech32_segwit_roundtrip; bech32_case_insensitive;
          abi_roundtrip ]
        @ robustness
        @ multiformats_props
        @ multiformats_robustness)) ]
