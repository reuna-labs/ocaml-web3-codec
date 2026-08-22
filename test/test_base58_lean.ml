let ok = function Ok value -> value | Error message -> Alcotest.fail message

let vectors () =
  Alcotest.(check string) "hello" "Cn8eVZg" (Web3_codec_base58.encode "hello");
  Alcotest.(check string) "decode" "hello" (ok (Web3_codec_base58.decode "Cn8eVZg"));
  let payload = "\000\001\002" in
  let checked = Web3_codec_base58.encode_check payload in
  Alcotest.(check string) "check" payload (ok (Web3_codec_base58.decode_check checked))

let () = Alcotest.run "web3-codec-base58" [ ("base58", [ Alcotest.test_case "vectors" `Quick vectors ]) ]
