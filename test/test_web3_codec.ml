open Web3_codec

let hexdec s =
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let hexenc s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let ok = function Ok x -> x | Error e -> Alcotest.failf "unexpected error: %s" e
let checkh name expected got = Alcotest.(check string) name expected (hexenc got)

(* ---------------- RLP ---------------- *)

let lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit"

let rlp_encode () =
  checkh "string 'dog'" "83646f67" (Rlp.(encode (Str "dog")));
  checkh "list [cat,dog]" "c88363617483646f67"
    (Rlp.(encode (List [ Str "cat"; Str "dog" ])));
  checkh "empty string" "80" (Rlp.(encode (Str "")));
  checkh "empty list" "c0" (Rlp.(encode (List [])));
  checkh "integer 0" "80" (Rlp.(encode (of_int 0)));
  checkh "integer 15" "0f" (Rlp.(encode (of_int 15)));
  checkh "integer 1024" "820400" (Rlp.(encode (of_int 1024)));
  checkh "single null byte" "00" (Rlp.(encode (Str "\x00")));
  checkh "set-theoretic 3-list" "c7c0c1c0c3c0c1c0"
    (Rlp.(encode (List [ List []; List [ List [] ];
                         List [ List []; List [ List [] ] ] ])));
  checkh "56-byte string long form" ("b838" ^ hexenc lorem)
    (Rlp.(encode (Str lorem)))

let rlp_decode () =
  let dec h = ok (Rlp.decode (hexdec h)) in
  Alcotest.(check bool) "decode [cat,dog]" true
    (dec "c88363617483646f67" = Rlp.(List [ Str "cat"; Str "dog" ]));
  Alcotest.(check string) "decode uint 1024" "1024"
    (Z.to_string (ok (Rlp.to_z (dec "820400"))));
  (* round-trips *)
  List.iter
    (fun v ->
      Alcotest.(check bool) "round-trip" true (ok (Rlp.decode (Rlp.encode v)) = v))
    Rlp.[ Str "dog"; List [ Str "cat"; Str "dog" ]; of_int 0; of_int 1024;
          Str lorem; List [ List []; Str "x"; List [ Str "y"; of_int 255 ] ] ];
  (* malformed inputs are rejected *)
  Alcotest.(check bool) "trailing bytes rejected" true
    (match Rlp.decode (hexdec "80ff") with Error _ -> true | Ok _ -> false);
  Alcotest.(check bool) "truncated rejected" true
    (match Rlp.decode (hexdec "83646f") with Error _ -> true | Ok _ -> false)

(* ---------------- SCALE ---------------- *)

let scale_compact () =
  let c n = hexenc (Scale.encode_compact (Z.of_string n)) in
  Alcotest.(check string) "compact 0" "00" (c "0");
  Alcotest.(check string) "compact 1" "04" (c "1");
  Alcotest.(check string) "compact 42" "a8" (c "42");
  Alcotest.(check string) "compact 63" "fc" (c "63");
  Alcotest.(check string) "compact 64" "0101" (c "64");
  Alcotest.(check string) "compact 69" "1501" (c "69");
  Alcotest.(check string) "compact 65535" "feff0300" (c "65535");
  Alcotest.(check string) "compact 2^30" "0300000040" (c "1073741824");
  Alcotest.(check string) "compact 1e14" "0b00407a10f35a" (c "100000000000000");
  (* round-trips, including a value well beyond 64 bits *)
  List.iter
    (fun n ->
      let z = Z.of_string n in
      Alcotest.(check string) ("round-trip " ^ n) n
        (Z.to_string (ok (Scale.compact_of_octets (Scale.encode_compact z)))))
    [ "0"; "1"; "63"; "64"; "16383"; "16384"; "1073741823"; "1073741824";
      "100000000000000"; "340282366920938463463374607431768211455" ]

let scale_misc () =
  checkh "u16 42" "2a00" (Scale.encode_u16 42);
  checkh "u32 16777215" "ffffff00" (Scale.encode_u32 16777215);
  checkh "u64 max" "ffffffffffffffff"
    (Scale.encode_u64 (Z.of_string "18446744073709551615"));
  checkh "bool true" "01" (Scale.encode_bool true);
  checkh "option none" "00" (Scale.encode_option Scale.encode_u8 None);
  checkh "option some 5" "0105" (Scale.encode_option Scale.encode_u8 (Some 5));
  checkh "bytes hello" ("14" ^ hexenc "hello") (Scale.encode_bytes "hello");
  Alcotest.(check string) "bytes round-trip" "hello"
    (ok (Scale.bytes_of_octets (Scale.encode_bytes "hello")))

(* ---------------- Base58 / Base58Check ---------------- *)

let base58_ () =
  Alcotest.(check string) "encode single 0x61" "2g" (Base58.encode "a");
  Alcotest.(check string) "encode null byte" "1" (Base58.encode "\x00");
  Alcotest.(check string) "decode 2g" "a" (ok (Base58.decode "2g"));
  checkh "decode leading 1s" "0000" (ok (Base58.decode "11"));
  (* classic Base58Check address vector *)
  let payload = "\x00" ^ hexdec "010966776006953d5567439e5e39f86a0d273bee" in
  Alcotest.(check string) "base58check address" "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    (Base58.encode_check payload);
  checkh "base58check round-trip" (hexenc payload)
    (ok (Base58.decode_check "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"));
  Alcotest.(check bool) "bad checksum rejected" true
    (match Base58.decode_check "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN" with
     | Error _ -> true | Ok _ -> false);
  Alcotest.(check bool) "invalid char rejected" true
    (match Base58.decode "0OIl" with Error _ -> true | Ok _ -> false)

(* ---------------- Bech32 / Bech32m ---------------- *)

let bech32_ () =
  (* Taproot (SegWit v1, Bech32m) from BIP341/BIP350 *)
  let taproot_prog =
    hexdec "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
  in
  let taproot_addr = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5" in
  Alcotest.(check string) "encode taproot v1 address" taproot_addr
    (ok (Bech32.encode_segwit ~hrp:"bc" ~version:1 ~program:taproot_prog));
  let ver, prog = ok (Bech32.decode_segwit ~hrp:"bc" taproot_addr) in
  Alcotest.(check int) "decoded taproot version" 1 ver;
  checkh "decoded taproot program" (hexenc taproot_prog) prog;
  (* SegWit v0 example from BIP173 (upper-case input) *)
  let v0_prog = hexdec "751e76e8199196d454941c45d1b3a323f1433bd6" in
  Alcotest.(check string) "encode v0 address" "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    (ok (Bech32.encode_segwit ~hrp:"bc" ~version:0 ~program:v0_prog));
  let ver0, prog0 =
    ok (Bech32.decode_segwit ~hrp:"bc" "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")
  in
  Alcotest.(check int) "decoded v0 version" 0 ver0;
  checkh "decoded v0 program" (hexenc v0_prog) prog0;
  (* a pure Bech32m string (BIP350 valid list) *)
  let enc, hrp, data = ok (Bech32.decode "A1LQFN3A") in
  Alcotest.(check bool) "A1LQFN3A is bech32m" true (enc = Bech32.Bech32m);
  Alcotest.(check string) "A1LQFN3A hrp" "a" hrp;
  Alcotest.(check int) "A1LQFN3A empty data" 0 (List.length data);
  (* a v0 checksum must not validate as bech32m and vice versa *)
  Alcotest.(check bool) "taproot rejects wrong hrp" true
    (match Bech32.decode_segwit ~hrp:"tb" taproot_addr with Error _ -> true | Ok _ -> false)

(* ---------------- SS58 ---------------- *)

let ss58_ () =
  (* the canonical "Alice" Substrate dev account (generic prefix 42) *)
  let alice = hexdec "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d" in
  let alice_addr = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY" in
  Alcotest.(check string) "encode Alice (prefix 42)" alice_addr (Ss58.encode ~network:42 alice);
  let network, pubkey = ok (Ss58.decode alice_addr) in
  Alcotest.(check int) "decoded network prefix" 42 network;
  checkh "decoded account id" (hexenc alice) pubkey;
  Alcotest.(check bool) "corrupted address rejected" true
    (match Ss58.decode "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQZ" with
     | Error _ -> true | Ok _ -> false)

(* ---------------- Borsh ---------------- *)

let borsh_ () =
  checkh "u32 LE" "78563412" (Borsh.encode_u32 0x12345678);
  checkh "string 'test'" ("04000000" ^ hexenc "test") (Borsh.encode_string "test");
  checkh "vec u8 [1;2;3]" "03000000010203" (Borsh.encode_vec Borsh.encode_u8 [ 1; 2; 3 ]);
  checkh "option some 5" "0105" (Borsh.encode_option Borsh.encode_u8 (Some 5));
  checkh "option none" "00" (Borsh.encode_option Borsh.encode_u8 None);
  checkh "bool true" "01" (Borsh.encode_bool true);
  checkh "i32 -1" "ffffffff" (Borsh.encode_i32 (-1));
  checkh "i64 -2" "feffffffffffffff" (Borsh.encode_i64 (Z.of_int (-2)));
  checkh "u128 one" ("01" ^ String.concat "" (List.init 15 (fun _ -> "00")))
    (Borsh.encode_u128 Z.one);
  Alcotest.(check string) "string round-trip" "hello borsh"
    (ok (Borsh.of_octets Borsh.read_string (Borsh.encode_string "hello borsh")));
  Alcotest.(check bool) "vec round-trip" true
    (ok (Borsh.of_octets (Borsh.read_vec Borsh.read_u8)
           (Borsh.encode_vec Borsh.encode_u8 [ 1; 2; 3; 255 ])) = [ 1; 2; 3; 255 ]);
  Alcotest.(check bool) "option round-trip" true
    (ok (Borsh.of_octets (Borsh.read_option Borsh.read_u32)
           (Borsh.encode_option Borsh.encode_u32 (Some 999))) = Some 999)

(* ---------------- Ethereum ABI ---------------- *)

let abi_ () =
  checkh "selector transfer" "a9059cbb" (Abi.selector "transfer(address,uint256)");
  checkh "selector baz" "cdcd77c0" (Abi.selector "baz(uint32,bool)");
  checkh "selector sam" "a5643bf2" (Abi.selector "sam(bytes,bool,uint256[])");
  (* baz(69, true) -- Solidity ABI spec worked example *)
  let baz =
    Abi.encode_call_exn ~signature:"baz(uint32,bool)" [ Abi.Uint (Z.of_int 69); Abi.Bool true ]
  in
  checkh "baz call data"
    ("cdcd77c0"
    ^ "0000000000000000000000000000000000000000000000000000000000000045"
    ^ "0000000000000000000000000000000000000000000000000000000000000001")
    baz;
  (* sam("dave", true, [1,2,3]) -- spec dynamic head/tail example *)
  let sam =
    Abi.encode_call_exn ~signature:"sam(bytes,bool,uint256[])"
      [ Abi.Bytes "dave"; Abi.Bool true;
        Abi.Array [ Abi.Uint Z.one; Abi.Uint (Z.of_int 2); Abi.Uint (Z.of_int 3) ] ]
  in
  checkh "sam call data"
    ("a5643bf2"
    ^ "0000000000000000000000000000000000000000000000000000000000000060"
    ^ "0000000000000000000000000000000000000000000000000000000000000001"
    ^ "00000000000000000000000000000000000000000000000000000000000000a0"
    ^ "0000000000000000000000000000000000000000000000000000000000000004"
    ^ "6461766500000000000000000000000000000000000000000000000000000000"
    ^ "0000000000000000000000000000000000000000000000000000000000000003"
    ^ "0000000000000000000000000000000000000000000000000000000000000001"
    ^ "0000000000000000000000000000000000000000000000000000000000000002"
    ^ "0000000000000000000000000000000000000000000000000000000000000003")
    sam;
  (* f(0x123, [0x456,0x789], bytes10"1234567890", "Hello, world!") -- spec bytesN example *)
  let f =
    Abi.encode_exn
      [ Abi.Uint (Z.of_int 0x123);
        Abi.Array [ Abi.Uint (Z.of_int 0x456); Abi.Uint (Z.of_int 0x789) ];
        Abi.FixedBytes "1234567890"; Abi.Bytes "Hello, world!" ]
  in
  checkh "f(...) encoding"
    ("0000000000000000000000000000000000000000000000000000000000000123"
    ^ "0000000000000000000000000000000000000000000000000000000000000080"
    ^ "3132333435363738393000000000000000000000000000000000000000000000"
    ^ "00000000000000000000000000000000000000000000000000000000000000e0"
    ^ "0000000000000000000000000000000000000000000000000000000000000002"
    ^ "0000000000000000000000000000000000000000000000000000000000000456"
    ^ "0000000000000000000000000000000000000000000000000000000000000789"
    ^ "000000000000000000000000000000000000000000000000000000000000000d"
    ^ "48656c6c6f2c20776f726c642100000000000000000000000000000000000000")
    f;
  (* decode round-trip: re-encoding the decoded params reproduces them *)
  let sam_params = String.sub sam 4 (String.length sam - 4) in
  let decoded = ok (Abi.decode [ Abi.TBytes; Abi.TBool; Abi.TArray (Abi.TUint 256) ] sam_params) in
  checkh "sam decode round-trips" (hexenc sam_params) (Abi.encode_exn decoded);
  (* confirm real decoding, not just re-encoding *)
  (match Abi.decode_call [ Abi.TUint 32; Abi.TBool ] baz with
  | Ok [ u; b ] ->
    Alcotest.(check string) "baz decoded uint" "69" (Z.to_string (Option.get (Abi.to_z u)));
    Alcotest.(check bool) "baz decoded bool" true (b = Abi.Bool true)
  | _ -> Alcotest.fail "baz decode failed");
  (* transfer(address,uint256): address left-padding to a 32-byte word *)
  let addr = hexdec "5b38da6a701c568545dcfcb03fcb875f56beddc4" in
  let call =
    Abi.encode_call_exn ~signature:"transfer(address,uint256)"
      [ Abi.Address addr; Abi.Uint (Z.of_int 1000000) ]
  in
  checkh "transfer call data"
    ("a9059cbb"
    ^ "0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4"
    ^ "00000000000000000000000000000000000000000000000000000000000f4240")
    call

let () =
  Alcotest.run "web3_codec"
    ([
      ("rlp", [ Alcotest.test_case "encode" `Quick rlp_encode;
                Alcotest.test_case "decode" `Quick rlp_decode ]);
      ("scale", [ Alcotest.test_case "compact" `Quick scale_compact;
                  Alcotest.test_case "misc" `Quick scale_misc ]);
      ("base58", [ Alcotest.test_case "encode/decode/check" `Quick base58_ ]);
      ("bech32", [ Alcotest.test_case "segwit + bech32m" `Quick bech32_ ]);
      ("ss58", [ Alcotest.test_case "encode/decode" `Quick ss58_ ]);
      ("borsh", [ Alcotest.test_case "encode/decode" `Quick borsh_ ]);
      ("abi", [ Alcotest.test_case "encode/selector/decode" `Quick abi_ ]);
    ]
    @ Regressions.suite
    @ Multiformats.suite
    @ Properties.suite)
