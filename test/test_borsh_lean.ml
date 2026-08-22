let ok = function Ok value -> value | Error message -> Alcotest.fail message

let integers () =
  let encoded = Web3_codec_borsh.encode_u64 (Z.of_string "18446744073709551615") in
  Alcotest.(check int) "width" 8 (String.length encoded);
  Alcotest.(check string) "round trip" "18446744073709551615"
    (Z.to_string (ok (Web3_codec_borsh.of_octets Web3_codec_borsh.read_u64 encoded)))

let strict_bool () =
  Alcotest.(check bool) "reject tag" true
    (Result.is_error (Web3_codec_borsh.of_octets Web3_codec_borsh.read_bool "\002"))

let () =
  Alcotest.run "web3-codec-borsh"
    [ ("borsh", [ Alcotest.test_case "integers" `Quick integers; Alcotest.test_case "strict bool" `Quick strict_bool ]) ]
