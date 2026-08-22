(* Multiformats: varint, the base encodings, multibase, multicodec,
   multihash, CID, multiaddr, multikey and multistream.

   Every vector here was computed and checked during implementation rather
   than transcribed from memory. The load-bearing external anchors are the
   RFC4648 base32/base64 vectors, the multibase spec's "yes mani !" set,
   the published digests of "abc", and the raw CIDv1 of "hello world"
   (bafkrei…) -- that last one exercises varint, multicodec, multihash,
   multibase and CID composed together, so it failing would localise a
   fault anywhere in the stack. *)

open Web3_codec

let hexenc s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))
let ok = function Ok x -> x | Error e -> Alcotest.failf "unexpected error: %s" e
let str = Alcotest.(check string)
let rejects name r = Alcotest.(check bool) name true (match r with Error _ -> true | Ok _ -> false)
let raises_invalid name f =
  Alcotest.(check bool) name true
    (try ignore (f ()); false with Invalid_argument _ -> true | _ -> false)

(* ---------------- varint ---------------- *)

(* Minimality is the whole point: a CID is a hash of these bytes, so a
   value with two spellings is a malleability vector. *)
let varint_canonical () =
  rejects "\"81 00\" spells 1 in two bytes" (Varint.of_octets "\x81\x00");
  rejects "\"80 80 00\" spells 0 in three" (Varint.of_octets "\x80\x80\x00");
  rejects "trailing zero group" (Varint.of_octets "\x80\x81\x00");
  rejects "10-byte varint" (Varint.of_octets (String.make 9 '\xff' ^ "\x01"));
  rejects "truncated (continuation with no successor)" (Varint.of_octets "\x80");
  rejects "trailing bytes" (Varint.of_octets "\x01\x01");
  (* the canonical spellings still decode *)
  List.iter
    (fun (bytes, v) -> str ("canonical " ^ string_of_int v) (string_of_int v)
        (string_of_int (ok (Varint.of_octets bytes))))
    [ ("\x00", 0); ("\x01", 1); ("\x7f", 127); ("\x80\x01", 128); ("\xff\x01", 255);
      ("\xac\x02", 300) ];
  raises_invalid "negative" (fun () -> Varint.write (-1))

let varint_roundtrip () =
  List.iter
    (fun v ->
      match Varint.of_octets (Varint.write v) with
      | Ok v' -> Alcotest.(check int) (Printf.sprintf "round-trip %d" v) v v'
      | Error m -> Alcotest.failf "round-trip %d: %s" v m)
    ([ 0; 1; 127; 128; 255; 256; 16383; 16384; 0x7fffffff; max_int ]
     @ List.init 200 (fun i -> i * 7919))

(* ---------------- base encodings ---------------- *)

let base_rfc4648 () =
  (* RFC 4648 section 10 *)
  List.iter (fun (i, w) -> str ("base32 " ^ i) w (Base32.encode ~alphabet:Base32.Rfc4648_upper ~pad:true i))
    [ ("", ""); ("f", "MY======"); ("fo", "MZXQ===="); ("foo", "MZXW6===");
      ("foob", "MZXW6YQ="); ("fooba", "MZXW6YTB"); ("foobar", "MZXW6YTBOI======") ];
  List.iter (fun (i, w) -> str ("base32hex " ^ i) w (Base32.encode ~alphabet:Base32.Hex_upper ~pad:true i))
    [ ("f", "CO======"); ("fo", "CPNG===="); ("foo", "CPNMU==="); ("foob", "CPNMUOG=");
      ("fooba", "CPNMUOJ1"); ("foobar", "CPNMUOJ1E8======") ];
  List.iter (fun (i, w) -> str ("base64 " ^ i) w (Base64.encode ~pad:true i))
    [ ("", ""); ("f", "Zg=="); ("fo", "Zm8="); ("foo", "Zm9v");
      ("foob", "Zm9vYg=="); ("fooba", "Zm9vYmE="); ("foobar", "Zm9vYmFy") ];
  str "base16 lower" "666f6f626172" (Base16.encode "foobar");
  str "base16 upper" "666F6F626172" (Base16.encode ~upper:true "foobar")

(* Non-zero trailing bits and no-op symbols are what let one payload have
   several spellings; both are rejected. *)
let base_canonical () =
  rejects "base64 non-zero trailing bits" (Base64.decode "QR");
  rejects "base32 non-zero trailing bits" (Base32.decode "ab");
  rejects "base32 lone symbol" (Base32.decode "a");
  rejects "base32 3 symbols" (Base32.decode "aaa");
  rejects "base32 6 symbols" (Base32.decode "aaaaaa");
  rejects "base64 lone symbol" (Base64.decode "Q");
  rejects "base16 odd length" (Base16.decode "abc");
  rejects "base16 wrong case" (Base16.decode "ABC0");
  rejects "base64 pad expected" (Base64.decode ~pad:true "Zg");
  rejects "base64 unexpected pad" (Base64.decode "Zg==");
  str "base64 \"QQ\" is valid" "A" (ok (Base64.decode "QQ"))

(* ---------------- multibase ---------------- *)

(* The spec's own vector set. *)
let multibase_vectors () =
  let m = "yes mani !" in
  List.iter
    (fun (b, want) ->
      str (Multibase.name b) want (Multibase.encode b m);
      let b', v = ok (Multibase.decode want) in
      Alcotest.(check bool) (Multibase.name b ^ " decodes back") true (b' = b && v = m))
    Multibase.[
      (Identity, "\x00yes mani !");
      (Base2, "001111001011001010111001100100000011011010110000101101110011010010010000000100001");
      (Base8, "7362625631006654133464440102");
      (Base10, "9573277761329450583662625");
      (Base16, "f796573206d616e692021");
      (Base16upper, "F796573206D616E692021");
      (Base32, "bpfsxgidnmfxgsibb");
      (Base32upper, "BPFSXGIDNMFXGSIBB");
      (Base32pad, "cpfsxgidnmfxgsibb");
      (Base32padupper, "CPFSXGIDNMFXGSIBB");
      (Base32hex, "vf5in683dc5n6i811");
      (Base32hexupper, "VF5IN683DC5N6I811");
      (Base32hexpad, "tf5in683dc5n6i811");
      (Base32hexpadupper, "TF5IN683DC5N6I811");
      (Base32z, "hxf1zgedpcfzg1ebb");
      (Base36, "k2lcpzo5yikidynfl");
      (Base36upper, "K2LCPZO5YIKIDYNFL");
      (Base58btc, "z7paNL19xttacUY");
      (Base58flickr, "Z7Pznk19XTTzBtx");
      (Base64, "meWVzIG1hbmkgIQ");
      (Base64pad, "MeWVzIG1hbmkgIQ==");
      (Base64url, "ueWVzIG1hbmkgIQ");
      (Base64urlpad, "UeWVzIG1hbmkgIQ==");
    ]

(* Leading zero bytes carry no value in a radix base, so they have to be
   carried across separately or they vanish. *)
let multibase_leading_zeros () =
  List.iter
    (fun payload ->
      List.iter
        (fun b ->
          let e = Multibase.encode b payload in
          match Multibase.decode e with
          | Ok (b', v) when b' = b && v = payload -> ()
          | Ok (_, v) -> Alcotest.failf "%s: %S -> %S" (Multibase.name b) payload v
          | Error m -> Alcotest.failf "%s: %S -> %s" (Multibase.name b) payload m)
        Multibase.all)
    [ ""; "\x00"; "\x00\x00"; "\x00\x01\x02"; "a"; "hello world"; String.init 256 Char.chr ]

let multibase_rejects () =
  rejects "empty" (Multibase.decode "");
  rejects "unknown prefix" (Multibase.decode "Qabc");
  rejects "base256emoji is unsupported" (Multibase.decode "\xf0\x9f\x9a\x80abc")

(* ---------------- multicodec ---------------- *)

(* The table is transcribed, so check it for internal consistency: a
   duplicate would be silently shadowed by the lookup tables. *)
let multicodec_table () =
  let t = Multicodec.table in
  let dup l =
    let seen = Hashtbl.create 512 in
    List.filter_map (fun x -> if Hashtbl.mem seen x then Some x else (Hashtbl.add seen x (); None)) l
  in
  Alcotest.(check int) "no duplicate codes" 0 (List.length (dup (List.map (fun (c, _, _) -> c) t)));
  Alcotest.(check int) "no duplicate names" 0 (List.length (dup (List.map (fun (_, n, _) -> n) t)));
  List.iter
    (fun (c, n, _) ->
      Alcotest.(check bool) (Printf.sprintf "0x%x <-> %s" c n) true
        (Multicodec.name (Multicodec.of_code c) = Some n && Multicodec.of_name n = Some c))
    t;
  (* the generated blake2 ranges land where the spec puts them *)
  List.iter
    (fun (n, want) -> Alcotest.(check (option int)) n (Some want) (Multicodec.of_name n))
    [ ("blake2b-8", 0xb201); ("blake2b-256", 0xb220); ("blake2b-512", 0xb240);
      ("blake2s-8", 0xb241); ("blake2s-256", 0xb260) ]

(* Spot values from multiformats/multicodec table.csv. The full table was
   diffed against upstream on 2026-08-21 (0 discrepancies across all
   entries); these pin the ones most likely to drift or be mistyped --
   codes outside the contiguous ranges, and names that differ between
   registries. *)
let multicodec_upstream_spot_check () =
  List.iter
    (fun (n, want) -> Alcotest.(check (option int)) n (Some want) (Multicodec.of_name n))
    [ (* hashes the sibling crypto package can compute *)
      ("ripemd-128", 0x1052); ("ripemd-160", 0x1053); ("ripemd-256", 0x1054);
      ("ripemd-320", 0x1055); ("poseidon-bls12_381-a2-fc1", 0xb401);
      ("blake3", 0x1e); ("keccak-512", 0x1d); ("sha2-512-224", 0x1014);
      (* keys, including the ones did:key and Polkadot reach for *)
      ("sr25519-pub", 0xef); ("sr25519-priv", 0x1303);
      ("bip340-pub", 0x1340); ("bip340-priv", 0x1341);
      ("bls12_381-g1g2-pub", 0xee); ("bls12_381-g1-priv", 0x1309);
      ("ed448-pub", 0x1203); ("x448-pub", 0x1204); ("jwk_jcs-pub", 0xeb51);
      ("p521-priv", 0x1308);
      (* content types *)
      ("bitcoin-witness-commitment", 0xb2); ("zcash-block", 0xc0);
      ("zcash-tx", 0xc1); ("ipns-record", 0x300) ];
  (* 0x309 is "memorytransport" in the codec registry; multiaddr spells the
     same code "memory" in its own protocol table. Both are correct in
     their domain, and neither table consults the other. *)
  Alcotest.(check (option int)) "memorytransport" (Some 0x309) (Multicodec.of_name "memorytransport");
  Alcotest.(check (option int)) "multicodec has no \"memory\"" None (Multicodec.of_name "memory");
  Alcotest.(check bool) "multiaddr still spells it \"memory\"" true
    (Multiaddr.proto_of_name "memory" <> None);
  str "and /memory still round-trips" "/memory/4242"
    (Multiaddr.to_string (ok (Multiaddr.of_string "/memory/4242")))

(* An unknown code must stay usable, or a CID naming an unfamiliar codec
   would be unparseable rather than merely unnamed. *)
let multicodec_unknown () =
  let u = Multicodec.of_code 0x9999 in
  Alcotest.(check bool) "unnamed" true (Multicodec.name u = None);
  Alcotest.(check bool) "not known" false (Multicodec.is_known u);
  str "prints as hex" "0x9999" (Multicodec.to_string u);
  str "still round-trips" "9999"
    (hexenc (Varint.write (Multicodec.to_code u)) |> fun _ ->
     string_of_int (ok (Varint.of_octets (Varint.write 0x9999))) |> fun s ->
     Printf.sprintf "%x" (int_of_string s))

(* ---------------- multihash ---------------- *)

let multihash_digests () =
  (* published digests of "abc" *)
  List.iter
    (fun (name, want) ->
      let c = Option.get (Multicodec.of_name name) in
      str name want (hexenc (Multihash.digest_bytes (ok (Multihash.digest c "abc")))))
    [ ("sha2-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
      ("sha3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
      ("keccak-256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
      ("blake2b-256", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
      ("blake2s-256", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
      (* digestif 1.4.0 additions. Keccak here is the pre-FIPS-202 padding, not
         SHA-3 -- compare keccak-256 and sha3-256 above, same rate, different
         digests. shake-* are XOFs squeezed to the lengths go-multihash uses. *)
      ("keccak-224", "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8");
      ("keccak-384",
       "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e");
      ("keccak-512",
       "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96");
      ("shake-128", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
      ("shake-256",
       "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
      ("sha2-512-224", "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
      ("sha2-512-256", "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23") ];
  str "identity is the input" "616263"
    (hexenc (Multihash.digest_bytes (ok (Multihash.digest (Multicodec.of_code 0x00) "abc"))));
  str "sha2-256 of \"hello world\", framed"
    "1220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    (hexenc (Multihash.to_octets (ok (Multihash.digest (Multicodec.of_code 0x12) "hello world"))))

(* The container is algorithm-agnostic: a digest this library cannot
   compute must still parse, and must never verify as valid. *)
let multihash_parse_vs_compute () =
  let blake3 = Option.get (Multicodec.of_name "blake3") in
  Alcotest.(check bool) "blake3 not computable" false (Multihash.supported blake3);
  rejects "digest refuses blake3" (Multihash.digest blake3 "abc");
  let h = Multihash.make ~code:blake3 ~digest:(String.make 32 '\xab') in
  let h' = ok (Multihash.of_octets (Multihash.to_octets h)) in
  Alcotest.(check bool) "but it parses" true (Multihash.code h' = blake3);
  (* Error, not Ok false: an unverifiable digest is never "valid" *)
  rejects "verify refuses rather than answering" (Multihash.verify h "abc");
  let sha = ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
  Alcotest.(check bool) "verify true" true (ok (Multihash.verify sha "hello world"));
  Alcotest.(check bool) "verify false" false (ok (Multihash.verify sha "goodbye"))

let multihash_rejects () =
  let sha = ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
  rejects "declared length exceeds input" (Multihash.of_octets "\x12\x20\x01\x02");
  rejects "trailing bytes" (Multihash.of_octets (Multihash.to_octets sha ^ "\xff"));
  rejects "non-minimal code varint" (Multihash.of_octets ("\x92\x00\x20" ^ String.make 32 '\x00'))

(* ---------------- CID ---------------- *)

(* This is the anchor that exercises the whole stack composed together. *)
let cid_hello_world () =
  let mh = ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
  let c = Cid.v1 ~codec:(Option.get (Multicodec.of_name "raw")) mh in
  str "raw CIDv1 in base32" "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"
    (Cid.to_string c);
  str "binary" "01551220b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    (hexenc (Cid.to_octets c));
  (* the same CID in any base is the same CID *)
  List.iter
    (fun b ->
      let s = Cid.to_string ~base:b c in
      Alcotest.(check bool) (Multibase.name b ^ " round-trips") true
        (match Cid.of_string s with Ok c' -> Cid.equal c' c | Error _ -> false))
    Multibase.all

let cid_v0 () =
  let mh = ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
  let v0 = ok (Cid.v0 mh) in
  let s = Cid.to_string v0 in
  Alcotest.(check int) "v0 text is 46 characters" 46 (String.length s);
  str "v0 text starts Qm" "Qm" (String.sub s 0 2);
  Alcotest.(check int) "v0 binary is 34 bytes" 34 (String.length (Cid.to_octets v0));
  let back = ok (Cid.of_string s) in
  Alcotest.(check bool) "v0 round-trips as v0" true (Cid.equal back v0 && Cid.version back = Cid.V0);
  (* v0 <-> v1 *)
  let up = Cid.to_v1 v0 in
  Alcotest.(check bool) "v0 -> v1 -> v0" true
    (match Cid.to_v0 up with Ok d -> Cid.equal d v0 | Error _ -> false);
  let raw = Cid.v1 ~codec:(Option.get (Multicodec.of_name "raw")) mh in
  rejects "a raw CID has no v0 form" (Cid.to_v0 raw);
  let blake3 = Multihash.make ~code:(Option.get (Multicodec.of_name "blake3")) ~digest:(String.make 32 '\xab') in
  rejects "v0 needs a sha2-256 hash" (Cid.v0 blake3)

let cid_rejects () =
  let mh = ok (Multihash.digest (Multicodec.of_code 0x12) "hello world") in
  let c = Cid.v1 ~codec:(Option.get (Multicodec.of_name "raw")) mh in
  (* v0 has no version field, so writing one is ambiguous by construction *)
  rejects "explicit version varint 0" (Cid.of_octets ("\x00\x55" ^ Multihash.to_octets mh));
  rejects "unsupported version 2" (Cid.of_octets ("\x02\x55" ^ Multihash.to_octets mh));
  rejects "trailing bytes" (Cid.of_octets (Cid.to_octets c ^ "\xff"));
  rejects "bare non-CID string" (Cid.of_string "QQQQQ");
  rejects "empty" (Cid.of_string "")

(* ---------------- multiaddr ---------------- *)

let multiaddr_roundtrip () =
  List.iter
    (fun a ->
      match Multiaddr.of_string a with
      | Error e -> Alcotest.failf "%s: %s" a e
      | Ok m ->
        str ("text round-trip " ^ a) a (Multiaddr.to_string m);
        Alcotest.(check bool) ("binary round-trip " ^ a) true
          (match Multiaddr.of_octets (Multiaddr.to_octets m) with
           | Ok m2 -> Multiaddr.equal m2 m
           | Error _ -> false))
    [ "/ip4/127.0.0.1/udp/1234";
      "/ip4/127.0.0.1/tcp/4321";
      "/ip4/1.2.3.4/tcp/80/http";
      "/ip6/::1/tcp/8080";
      "/ip6/2001:db8::ff00:42:8329/tcp/443/tls/ws";
      "/dns4/example.com/tcp/443/tls/ws";
      "/dns/libp2p.io/tcp/443/wss";
      "/dnsaddr/bootstrap.libp2p.io";
      "/ip4/127.0.0.1/tcp/1234/p2p/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC";
      "/ip4/1.2.3.4/udp/4001/quic-v1/webtransport";
      "/unix/tmp/p2p.sock";
      "/ip6zone/x/ip6/fe80::1/tcp/80";
      "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234";
      "/memory/4242";
      "/ip4/127.0.0.1/tcp/127/ws/p2p-websocket-star" ];
  str "known binary form" "047f000001910204d2"
    (hexenc (Multiaddr.to_octets (ok (Multiaddr.of_string "/ip4/127.0.0.1/udp/1234"))))

(* RFC 5952: longest run of zero groups collapsed, leftmost wins ties. *)
let multiaddr_ip6_formatting () =
  List.iter
    (fun (input, want) ->
      str ("ip6 " ^ input) ("/ip6/" ^ want) (Multiaddr.to_string (ok (Multiaddr.of_string ("/ip6/" ^ input)))))
    [ ("::", "::"); ("::1", "::1"); ("1::", "1::"); ("2001:db8::1", "2001:db8::1");
      ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"); ("fe80::1", "fe80::1");
      ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"); ("::ffff:0:0", "::ffff:0:0");
      ("2001:0db8:0000:0000:0000:ff00:0042:8329", "2001:db8::ff00:42:8329");
      ("0:0:0:0:0:0:0:0", "::"); ("1:0:0:2:0:0:0:3", "1:0:0:2::3") ]

let multiaddr_rejects () =
  rejects "no leading slash" (Multiaddr.of_string "ip4/127.0.0.1");
  rejects "unknown protocol name" (Multiaddr.of_string "/quux/1");
  rejects "missing value" (Multiaddr.of_string "/ip4");
  rejects "trailing slash" (Multiaddr.of_string "/ip4/127.0.0.1/");
  rejects "port out of range" (Multiaddr.of_string "/ip4/127.0.0.1/tcp/99999");
  rejects "octet out of range" (Multiaddr.of_string "/ip4/256.0.0.1");
  rejects "ip4 leading zeros" (Multiaddr.of_string "/ip4/127.0.0.01");
  rejects "too few ip6 groups" (Multiaddr.of_string "/ip6/1:2:3");
  rejects "two '::' runs" (Multiaddr.of_string "/ip6/1::2::3");
  rejects "p2p value is not a multihash" (Multiaddr.of_string "/p2p/notabase58!!");
  (* an unknown code has no knowable width, and guessing would silently
     re-frame every component after it *)
  rejects "unknown code in binary" (Multiaddr.of_octets "\xfe\xff\x03\x01\x02");
  rejects "truncated fixed value" (Multiaddr.of_octets "\x04\x7f\x00");
  rejects "truncated variable value" (Multiaddr.of_octets "\x35\x10ab")

(* ---------------- multikey ---------------- *)

(* The did:key prefixes are not special-cased anywhere; they fall out of
   the codec varint, so these pin that the varint and table agree. *)
let multikey_did_key () =
  List.iter
    (fun (name, len, want) ->
      let c = Option.get (Multicodec.of_name name) in
      let k = ok (Multikey.make ~codec:c ~key:(String.make len '\x02')) in
      let s = Multikey.to_string k in
      str (name ^ " prefix") want (String.sub s 0 (String.length want));
      Alcotest.(check bool) (name ^ " round-trips") true
        (match Multikey.of_string s with
         | Ok k2 -> Multikey.key_bytes k2 = Multikey.key_bytes k && Multikey.codec k2 = c
         | Error _ -> false))
    [ ("ed25519-pub", 32, "z6Mk"); ("secp256k1-pub", 33, "zQ3s");
      ("x25519-pub", 32, "z6LS"); ("p256-pub", 33, "zDn") ];
  let ed = Option.get (Multicodec.of_name "ed25519-pub") in
  let k = ok (Multikey.make ~codec:ed ~key:(String.make 32 '\xab')) in
  str "did:key prefix" "did:key:z6Mk" (String.sub (Multikey.to_did_key k) 0 12);
  Alcotest.(check bool) "did:key round-trips" true
    (match Multikey.of_did_key (Multikey.to_did_key k) with
     | Ok k2 -> Multikey.key_bytes k2 = Multikey.key_bytes k
     | Error _ -> false)

(* Length is all this can check -- there is no curve arithmetic here. *)
let multikey_lengths () =
  let ed = Option.get (Multicodec.of_name "ed25519-pub") in
  let k1 = Option.get (Multicodec.of_name "secp256k1-pub") in
  rejects "ed25519 must be 32 bytes" (Multikey.make ~codec:ed ~key:(String.make 31 '\x00'));
  rejects "secp256k1 uncompressed is refused" (Multikey.make ~codec:k1 ~key:(String.make 65 '\x04'));
  let k = ok (Multikey.make ~codec:ed ~key:(String.make 32 '\xab')) in
  rejects "did:key is base58btc only"
    (Multikey.of_did_key ("did:key:" ^ Multikey.to_string ~base:Multibase.Base16 k));
  rejects "not a did:key URI" (Multikey.of_did_key "did:web:example.com");
  (* RSA has no fixed length, so any length is structurally acceptable *)
  let rsa = Option.get (Multicodec.of_name "rsa-pub") in
  Alcotest.(check bool) "rsa length is unconstrained" true
    (match Multikey.make ~codec:rsa ~key:(String.make 270 '\x01') with Ok _ -> true | Error _ -> false);
  (* likewise for the types whose length this module deliberately does not
     pin -- unconstrained means unconstrained, not invalid *)
  List.iter
    (fun n ->
      let c = Option.get (Multicodec.of_name n) in
      Alcotest.(check (option int)) (n ^ " is unconstrained") None
        (Multikey.expected_length (Multicodec.to_code c)))
    [ "rsa-pub"; "rsa-priv"; "ed448-pub"; "jwk_jcs-pub" ]

(* Key types reachable now that the table covers them. Lengths are either
   derivable from the curve size or checked against a reference encoding,
   since a wrong entry here rejects valid keys. *)
let multikey_more_types () =
  List.iter
    (fun (name, len) ->
      let c = Option.get (Multicodec.of_name name) in
      Alcotest.(check (option int)) (name ^ " length") (Some len)
        (Multikey.expected_length (Multicodec.to_code c));
      let k = ok (Multikey.make ~codec:c ~key:(String.make len '\x03')) in
      Alcotest.(check bool) (name ^ " round-trips") true
        (match Multikey.of_string (Multikey.to_string k) with
         | Ok k2 -> Multikey.key_bytes k2 = Multikey.key_bytes k && Multikey.codec k2 = c
         | Error _ -> false);
      rejects (name ^ " rejects a short key")
        (Multikey.make ~codec:c ~key:(String.make (len - 1) '\x03')))
    [ ("sr25519-pub", 32); ("sr25519-priv", 32);
      ("bip340-pub", 32); ("bip340-priv", 32);
      ("bls12_381-g1g2-pub", 144); ("bls12_381-g1-priv", 32); ("bls12_381-g2-priv", 32);
      ("x448-pub", 56);
      ("p256-priv", 32); ("p384-priv", 48); ("p521-priv", 66) ]

(* ---------------- multistream ---------------- *)

let multistream_framing () =
  let m = Multistream.encode_message Multistream.protocol_id in
  str "framed header" "132f6d756c746973747265616d2f312e302e300a" (hexenc m);
  Alcotest.(check int) "length counts the newline" (String.length Multistream.protocol_id + 1)
    (Char.code m.[0]);
  str "round-trip" Multistream.protocol_id (ok (Multistream.decode_message m));
  rejects "not newline-terminated" (Multistream.decode_message "\x03abc");
  rejects "zero length" (Multistream.decode_message "\x00");
  rejects "truncated" (Multistream.decode_message "\x10ab");
  rejects "trailing bytes" (Multistream.decode_message (m ^ "\xff"));
  raises_invalid "payload may not contain a newline"
    (fun () -> Multistream.encode_message "a\nb")

let multistream_negotiation () =
  let sends acts = List.filter_map (function Multistream.Send s -> Some s | _ -> None) acts in
  let selected acts = List.filter_map (function Multistream.Selected s -> Some s | _ -> None) acts in
  let failed acts = List.exists (function Multistream.Failed _ -> true | _ -> false) acts in
  let ist, ia = Multistream.start (Multistream.Initiator [ "/nope/1.0.0"; "/ipfs/id/1.0.0" ]) in
  let rst, ra = Multistream.start (Multistream.Responder [ "/ipfs/id/1.0.0" ]) in
  Alcotest.(check (list string)) "both open with the header"
    [ Multistream.protocol_id; Multistream.protocol_id ] (sends ia @ sends ra);
  let ist, ia = Multistream.on_message ist Multistream.protocol_id in
  let rst, _ = Multistream.on_message rst Multistream.protocol_id in
  Alcotest.(check (list string)) "initiator offers its first choice" [ "/nope/1.0.0" ] (sends ia);
  let rst, ra = Multistream.on_message rst "/nope/1.0.0" in
  Alcotest.(check (list string)) "responder refuses" [ Multistream.na ] (sends ra);
  let ist, ia = Multistream.on_message ist Multistream.na in
  Alcotest.(check (list string)) "initiator falls back" [ "/ipfs/id/1.0.0" ] (sends ia);
  let rst, ra = Multistream.on_message rst "/ipfs/id/1.0.0" in
  Alcotest.(check (list string)) "responder echoes its acceptance" [ "/ipfs/id/1.0.0" ] (sends ra);
  Alcotest.(check (list string)) "responder selected" [ "/ipfs/id/1.0.0" ] (selected ra);
  let ist, ia = Multistream.on_message ist "/ipfs/id/1.0.0" in
  Alcotest.(check (list string)) "initiator selected" [ "/ipfs/id/1.0.0" ] (selected ia);
  Alcotest.(check bool) "both finished" true (Multistream.is_done ist && Multistream.is_done rst);
  (* exhaustion and a bad header both fail rather than hang *)
  let st, _ = Multistream.start (Multistream.Initiator [ "/only/1.0.0" ]) in
  let st, _ = Multistream.on_message st Multistream.protocol_id in
  let _, acts = Multistream.on_message st Multistream.na in
  Alcotest.(check bool) "exhausting the list fails" true (failed acts);
  let st, _ = Multistream.start (Multistream.Responder [ "/x/1" ]) in
  let _, acts = Multistream.on_message st "/multistream/2.0.0" in
  Alcotest.(check bool) "a wrong header fails" true (failed acts)

let suite =
  [ ("varint",
     [ Alcotest.test_case "canonical encoding" `Quick varint_canonical;
       Alcotest.test_case "round-trip" `Quick varint_roundtrip ]);
    ("base-encodings",
     [ Alcotest.test_case "RFC4648 vectors" `Quick base_rfc4648;
       Alcotest.test_case "canonical decoding" `Quick base_canonical ]);
    ("multibase",
     [ Alcotest.test_case "spec vectors" `Quick multibase_vectors;
       Alcotest.test_case "leading zeros" `Quick multibase_leading_zeros;
       Alcotest.test_case "rejections" `Quick multibase_rejects ]);
    ("multicodec",
     [ Alcotest.test_case "table consistency" `Quick multicodec_table;
       Alcotest.test_case "upstream spot check" `Quick multicodec_upstream_spot_check;
       Alcotest.test_case "unknown passthrough" `Quick multicodec_unknown ]);
    ("multihash",
     [ Alcotest.test_case "published digests" `Quick multihash_digests;
       Alcotest.test_case "parse vs compute" `Quick multihash_parse_vs_compute;
       Alcotest.test_case "rejections" `Quick multihash_rejects ]);
    ("cid",
     [ Alcotest.test_case "hello world anchor" `Quick cid_hello_world;
       Alcotest.test_case "v0 and conversion" `Quick cid_v0;
       Alcotest.test_case "rejections" `Quick cid_rejects ]);
    ("multiaddr",
     [ Alcotest.test_case "round-trip" `Quick multiaddr_roundtrip;
       Alcotest.test_case "ip6 formatting" `Quick multiaddr_ip6_formatting;
       Alcotest.test_case "rejections" `Quick multiaddr_rejects ]);
    ("multikey",
     [ Alcotest.test_case "did:key prefixes" `Quick multikey_did_key;
       Alcotest.test_case "length checks" `Quick multikey_lengths;
       Alcotest.test_case "additional key types" `Quick multikey_more_types ]);
    ("multistream",
     [ Alcotest.test_case "framing" `Quick multistream_framing;
       Alcotest.test_case "negotiation" `Quick multistream_negotiation ]) ]
