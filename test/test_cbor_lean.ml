(* RFC 8949 Appendix A vectors, plus the properties that matter for a codec
   whose output gets signed: canonical output is a fixed point, decoding is
   total on arbitrary bytes, and the ambiguities are refused. *)

module C = Web3_codec_cbor

let hex s =
  let n = String.length s / 2 in
  String.init n (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

let unhex s =
  String.concat "" (List.map (fun c -> Printf.sprintf "%02x" (Char.code c))
                      (List.init (String.length s) (String.get s)))

let check_enc name v expect =
  Alcotest.(check string) (name ^ ": encode") expect (unhex (C.encode v))

let check_dec name bytes expect =
  match C.of_octets (hex bytes) with
  | Ok got -> Alcotest.(check bool) (name ^ ": decode") true (got = expect)
  | Error m -> Alcotest.failf "%s: decode failed: %s" name m

(* A vector that is already in canonical form must survive both directions. *)
let roundtrip name bytes v =
  check_enc name v bytes;
  check_dec name bytes v

(* Appendix A, integers. The unsigned edges are the point: 2^64-1 is a valid
   CBOR integer and is not representable as a positive OCaml int64. *)
let integers () =
  roundtrip "0" "00" (C.Uint 0L);
  roundtrip "23" "17" (C.Uint 23L);
  roundtrip "24" "1818" (C.Uint 24L);
  roundtrip "1000" "1903e8" (C.Uint 1000L);
  roundtrip "1000000" "1a000f4240" (C.Uint 1_000_000L);
  roundtrip "1000000000000" "1b000000e8d4a51000" (C.Uint 1_000_000_000_000L);
  roundtrip "2^64-1" "1bffffffffffffffff" (C.Uint (-1L));
  roundtrip "-1" "20" (C.Nint 0L);
  roundtrip "-100" "3863" (C.Nint 99L);
  roundtrip "-1000" "3903e7" (C.Nint 999L);
  roundtrip "-2^64" "3bffffffffffffffff" (C.Nint (-1L));
  Alcotest.(check string) "2^64-1 prints unsigned" "18446744073709551615"
    (C.uint_to_string (-1L))

let bignums () =
  roundtrip "2^64" "c249010000000000000000"
    (C.Big { negative = false; magnitude = hex "010000000000000000" });
  roundtrip "-2^64-1" "c349010000000000000000"
    (C.Big { negative = true; magnitude = hex "010000000000000000" });
  (* A magnitude with a leading zero is a second spelling of the same integer.
     Refused in both directions rather than normalised, so that a caller cannot
     produce bytes it did not intend. *)
  Alcotest.check_raises "leading zero rejected on encode"
    (Invalid_argument
       "Web3_codec_cbor.encode: bignum magnitude has a leading zero byte, \
        which would give one integer two spellings")
    (fun () -> ignore (C.encode (C.Big { negative = false; magnitude = "\000\001" })));
  match C.of_octets (hex "c2420001") with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "leading zero accepted on decode"

let strings_and_containers () =
  roundtrip "empty bytes" "40" (C.Bytes "");
  roundtrip "bytes" "4401020304" (C.Bytes (hex "01020304"));
  roundtrip "empty text" "60" (C.Text "");
  roundtrip "IETF" "6449455446" (C.Text "IETF");
  roundtrip "[]" "80" (C.Array []);
  roundtrip "[1,2,3]" "83010203" (C.Array [ C.Uint 1L; C.Uint 2L; C.Uint 3L ]);
  roundtrip "nested" "8301820203820405"
    (C.Array [ C.Uint 1L; C.Array [ C.Uint 2L; C.Uint 3L ];
               C.Array [ C.Uint 4L; C.Uint 5L ] ]);
  roundtrip "{}" "a0" (C.Map []);
  roundtrip "{1:2,3:4}" "a201020304"
    (C.Map [ (C.Uint 1L, C.Uint 2L); (C.Uint 3L, C.Uint 4L) ]);
  roundtrip "{a:1,b:[2,3]}" "a26161016162820203"
    (C.Map [ (C.Text "a", C.Uint 1L);
             (C.Text "b", C.Array [ C.Uint 2L; C.Uint 3L ]) ]);
  roundtrip "tagged" "c074323031332d30332d32315432303a30343a30305a"
    (C.Tag (0, C.Text "2013-03-21T20:04:00Z"))

let simple_and_float () =
  roundtrip "false" "f4" (C.Bool false);
  roundtrip "true" "f5" (C.Bool true);
  roundtrip "null" "f6" C.Null;
  roundtrip "undefined" "f7" C.Undefined;
  roundtrip "simple(16)" "f0" (C.Simple 16);
  roundtrip "simple(255)" "f8ff" (C.Simple 255);
  roundtrip "1.5 half" "f93e00" (C.Float (C.Half, 1.5));
  roundtrip "100000.0 single" "fa47c35000" (C.Float (C.Single, 100000.0));
  roundtrip "1.1 double" "fb3ff199999999999a" (C.Float (C.Double, 1.1));
  (* Reserved simple values are ill-formed, not merely unusual. *)
  Alcotest.(check bool) "simple(24) rejected" true
    (match C.of_octets (hex "f818") with Error _ -> true | Ok _ -> false)

(* The decoder must read what a chain sends; the encoder must not produce it. *)
let permissive_decode () =
  check_dec "indefinite bytes" "5f42010243030405ff" (C.Bytes (hex "0102030405"));
  check_dec "indefinite text" "7f657374726561646d696e67ff" (C.Text "streaming");
  check_dec "indefinite array" "9f018202039f0405ffff"
    (C.Array [ C.Uint 1L; C.Array [ C.Uint 2L; C.Uint 3L ];
               C.Array [ C.Uint 4L; C.Uint 5L ] ]);
  check_dec "indefinite map" "bf61610161629f0203ffff"
    (C.Map [ (C.Text "a", C.Uint 1L);
             (C.Text "b", C.Array [ C.Uint 2L; C.Uint 3L ]) ]);
  (* Non-minimal integer heads: legal CBOR, not canonical. Read, never written. *)
  check_dec "non-minimal 0" "1800" (C.Uint 0L);
  Alcotest.(check bool) "non-minimal is not canonical" false
    (C.is_canonical (hex "1800"));
  Alcotest.(check bool) "minimal is canonical" true (C.is_canonical (hex "00"));
  Alcotest.(check bool) "indefinite is not canonical" false
    (C.is_canonical (hex "9f01ff"))

(* Map order is preserved on decode -- a caller comparing a re-encode against
   the original bytes has to see what the sender actually sent. *)
let map_order () =
  (* Deliberately the reverse of canonical order on the wire, so that a decoder
     which quietly sorted would be caught. *)
  (match C.of_octets (hex "a261616162036161") with
   | Ok (C.Map [ (C.Text "a", _); (C.Uint 3L, _) ]) -> ()
   | Ok v -> Alcotest.failf "decode reordered: %s" (unhex (C.encode v))
   | Error m -> Alcotest.fail m);
  (* Canonical: bytewise on the encoded key, so 3 (0x03) precedes "a" (0x6161). *)
  Alcotest.(check string) "canonical sorts bytewise" "a203616161616162"
    (unhex (C.encode ~profile:C.Canonical
              (C.Map [ (C.Text "a", C.Text "b"); (C.Uint 3L, C.Text "a") ])));
  (* RFC 7049: length first. "aa" (3 bytes encoded) sorts after 3 (1 byte),
     and a longer key sorts after a shorter one even when it is bytewise
     smaller -- which is the whole difference between the two orderings. *)
  let m = C.Map [ (C.Text "aa", C.Uint 1L); (C.Uint 3L, C.Uint 2L) ] in
  Alcotest.(check string) "rfc7049 sorts by length first" "a2030262616101"
    (unhex (C.encode ~profile:C.Rfc7049 m))

let duplicate_keys () =
  Alcotest.(check bool) "duplicate key rejected" true
    (match C.of_octets (hex "a2016101016102") with Error _ -> true | Ok _ -> false);
  (* Two spellings of the same integer are the same key. Comparing raw bytes
     rather than decoded values would miss this. *)
  Alcotest.(check bool) "duplicate across spellings rejected" true
    (match C.of_octets (hex "a201611018000161") with
     | Error _ -> true | Ok _ -> false)

let spans () =
  (* The reason this module exists: a caller that hashes a decoded structure
     must hash the bytes it arrived in, not a re-encode. *)
  let s = hex "83010203" in
  let _, sp, next = C.read_span s 1 in
  Alcotest.(check int) "span offset" 1 sp.C.off;
  Alcotest.(check int) "span length" 1 sp.C.len;
  Alcotest.(check int) "next position" 2 next;
  let outer = hex "82" ^ hex "1800" ^ hex "01" in
  let _, sp, _ = C.read_span outer 1 in
  Alcotest.(check string) "span captures the non-canonical spelling" "1800"
    (unhex (String.sub outer sp.C.off sp.C.len))

let limits () =
  let tiny = { C.default_limits with max_nesting = 3 } in
  Alcotest.(check bool) "nesting bounded" true
    (match C.read ~limits:tiny (hex "81818181810100") 0 with
     | exception C.Error _ -> true | _ -> false);
  (* A length header is a claim, not a fact. It must be checked before it is
     believed, or a hostile eight-byte length exhausts memory first. *)
  Alcotest.(check bool) "oversized length refused before allocating" true
    (match C.read (hex "5bffffffffffffffff") 0 with
     | exception C.Error _ -> true | _ -> false);
  let few = { C.default_limits with max_items = 2 } in
  Alcotest.(check bool) "item count bounded" true
    (match C.read ~limits:few (hex "8401020304") 0 with
     | exception C.Error _ -> true | _ -> false)

let trailing () =
  Alcotest.(check bool) "trailing bytes rejected" true
    (match C.of_octets (hex "0001") with Error _ -> true | Ok _ -> false)

(* ---- properties ---- *)

let gen_value =
  let open QCheck.Gen in
  sized_size (int_bound 4) @@ fix (fun self n ->
    let leaf =
      oneof
        [ map (fun i -> C.Uint (Int64.of_int (abs i))) nat;
          map (fun i -> C.Nint (Int64.of_int (abs i))) nat;
          map (fun s -> C.Bytes s) (string_size (int_bound 8));
          map (fun s -> C.Text s) (string_size (int_bound 8));
          return (C.Bool true); return C.Null; return C.Undefined;
          map (fun i -> C.Simple (i mod 20)) nat ]
    in
    if n = 0 then leaf
    else
      oneof_weighted
        [ (3, leaf);
          (1, map (fun xs -> C.Array xs) (list_size (int_bound 3) (self (n / 2))));
          (1, map (fun i -> C.Tag (abs i mod 100 + 4, C.Uint 1L)) nat) ])

let arb_value = QCheck.make gen_value

let prop_roundtrip =
  QCheck.Test.make ~count:2000 ~name:"encode then decode is the identity"
    arb_value (fun v ->
      match C.of_octets (C.encode v) with Ok v' -> v' = v | Error _ -> false)

let prop_canonical_fixed_point =
  QCheck.Test.make ~count:2000 ~name:"canonical output is already canonical"
    arb_value (fun v -> C.is_canonical (C.encode v))

let prop_total =
  (* Arbitrary bytes must produce a value or a typed error, never an escaping
     exception and never a hang. *)
  QCheck.Test.make ~count:5000 ~name:"arbitrary input never escapes as an exception"
    QCheck.(string_size (QCheck.Gen.int_bound 24)) (fun s ->
      match C.of_octets s with _ -> true | exception _ -> false)

let () =
  Alcotest.run "web3-codec-cbor"
    [ ( "rfc8949 vectors",
        [ Alcotest.test_case "integers" `Quick integers;
          Alcotest.test_case "bignums" `Quick bignums;
          Alcotest.test_case "strings and containers" `Quick strings_and_containers;
          Alcotest.test_case "simple and float" `Quick simple_and_float ] );
      ( "decoder discipline",
        [ Alcotest.test_case "permissive decode" `Quick permissive_decode;
          Alcotest.test_case "map order" `Quick map_order;
          Alcotest.test_case "duplicate keys" `Quick duplicate_keys;
          Alcotest.test_case "spans" `Quick spans;
          Alcotest.test_case "limits" `Quick limits;
          Alcotest.test_case "trailing bytes" `Quick trailing ] );
      ( "properties",
        List.map QCheck_alcotest.to_alcotest
          [ prop_roundtrip; prop_canonical_fixed_point; prop_total ] ) ]
