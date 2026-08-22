let ok = function Ok value -> value | Error message -> Alcotest.fail message

let roundtrip () =
  let raw = "\000\000\001\002\255" in
  let encoded = Web3_codec_basen.encode Web3_codec_basen.btc raw in
  Alcotest.(check string) "round trip" raw (ok (Web3_codec_basen.decode Web3_codec_basen.btc encoded))

let () = Alcotest.run "web3-codec-basen" [ ("basen", [ Alcotest.test_case "round trip" `Quick roundtrip ]) ]
