(* Regression tests: one per defect confirmed against the pre-hardening
   code. Each asserts the input is now *rejected* rather than silently
   mis-decoded, over-allocated, or raised out of a [result]-typed API. *)

open Web3_codec

let hexdec s = String.init (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let hexenc s = String.concat "" (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let is_error = function Ok _ -> false | Error _ -> true
let rejects name r = Alcotest.(check bool) name true (is_error r)
let raises_invalid name f =
  Alcotest.(check bool) name true
    (try ignore (f ()); false with Invalid_argument _ -> true | _ -> false)

(* 32-byte big-endian word holding [n] *)
let w n = String.init 32 (fun i ->
    Char.chr (Z.to_int (Z.logand (Z.shift_right (Z.of_int n) (8*(31-i))) (Z.of_int 0xff))))

(* ---------------- ABI ---------------- *)

(* A length or offset word is a full 256 bits. Converting it with
   [Z.to_int] raised [Z.Overflow] straight through an API whose type says
   [result]. *)
let abi_word_overflow () =
  let maxword = String.make 32 '\xff' in
  rejects "2^256-1 length word"
    (Abi.decode [ Abi.TBytes ] (maxword ^ String.make 32 '\000'));
  rejects "2^256-1 offset word" (Abi.decode [ Abi.TArray (Abi.TUint 256) ] maxword)

(* [TArray] built its element list from the claimed count before checking
   it against the buffer, so 64 bytes of input drove a multi-gigabyte
   allocation. [TBytes] always had the bounds check; [TArray] did not. *)
let abi_array_bomb () =
  List.iter
    (fun claim ->
      rejects (Printf.sprintf "array claiming %d elements in 64 bytes" claim)
        (Abi.decode [ Abi.TArray (Abi.TUint 256) ] (w 32 ^ w claim)))
    [ 1_000_000; 100_000_000; max_int ]

(* The declared width was ignored: every intN/uintN came back as the raw
   256-bit word, so int8 0xff..ff decoded as 255 rather than -1. *)
let abi_int_width () =
  rejects "uint8 holding 511" (Abi.decode [ Abi.TUint 8 ] (w 511));
  rejects "int8 holding 255 (not sign-extended)" (Abi.decode [ Abi.TInt 8 ] (w 255));
  (* the correctly sign-extended value must still decode, and as -1 *)
  (match Abi.decode [ Abi.TInt 8 ] (String.make 32 '\xff') with
   | Ok [ v ] -> Alcotest.(check string) "int8 -1" "-1" (Z.to_string (Option.get (Abi.to_z v)))
   | _ -> Alcotest.fail "sign-extended int8 -1 should decode");
  (match Abi.decode [ Abi.TUint 8 ] (w 255) with
   | Ok [ v ] -> Alcotest.(check string) "uint8 255" "255" (Z.to_string (Option.get (Abi.to_z v)))
   | _ -> Alcotest.fail "uint8 255 should decode");
  rejects "invalid uintN width" (Abi.decode [ Abi.TUint 7 ] (w 1));
  rejects "invalid bytesN width" (Abi.decode [ Abi.TFixedBytes 33 ] (w 1))

(* Non-canonical words were accepted verbatim. *)
let abi_canonical_words () =
  rejects "address with non-zero high bytes" (Abi.decode [ Abi.TAddress ] (String.make 32 '\xaa'));
  rejects "bool that is neither 0 nor 1" (Abi.decode [ Abi.TBool ] (w 2));
  rejects "bytesN with non-zero padding"
    (Abi.decode [ Abi.TFixedBytes 4 ] (hexdec "aabbccdd" ^ String.make 28 '\xff'));
  (* canonical forms still decode *)
  (match Abi.decode [ Abi.TAddress ] (String.make 12 '\000' ^ String.make 20 '\xaa') with
   | Ok [ Abi.Address a ] -> Alcotest.(check int) "address 20 bytes" 20 (String.length a)
   | _ -> Alcotest.fail "canonical address should decode")

(* Encoding validated nothing: a 32-byte Address silently wrapped mod
   2^256 into a well-formed transaction to the wrong recipient, an
   over-long FixedBytes shifted every following head/tail offset, and
   Uint 2^300 encoded as literal zero. *)
let abi_encode_validation () =
  rejects "Address of 32 bytes" (Abi.encode [ Abi.Address (String.make 32 '\xbb') ]);
  rejects "Address of 19 bytes" (Abi.encode [ Abi.Address (String.make 19 '\xbb') ]);
  rejects "FixedBytes of 40 bytes" (Abi.encode [ Abi.FixedBytes (String.make 40 '\xcc') ]);
  rejects "FixedBytes of 0 bytes" (Abi.encode [ Abi.FixedBytes "" ]);
  rejects "Uint 2^300" (Abi.encode [ Abi.Uint (Z.shift_left Z.one 300) ]);
  rejects "negative Uint" (Abi.encode [ Abi.Uint (Z.of_int (-1)) ]);
  rejects "Int at 2^255" (Abi.encode [ Abi.Int (Z.shift_left Z.one 255) ]);
  (* nested values are validated too, not just top-level ones *)
  rejects "bad Address nested in a Tuple"
    (Abi.encode [ Abi.Tuple [ Abi.Bool true; Abi.Address "short" ] ]);
  rejects "bad Address nested in an Array"
    (Abi.encode [ Abi.Array [ Abi.Address (String.make 20 '\x01'); Abi.Address "short" ] ]);
  raises_invalid "encode_exn raises on a bad value"
    (fun () -> Abi.encode_exn [ Abi.Address "short" ])

(* ---------------- RLP ---------------- *)

(* An 8-byte length field was accumulated into a 63-bit int without a
   guard, so 0x8000000000000064 wrapped to 100 and "ff 80 00 00 00 00 00
   00 64" decoded identically to the canonical "f8 64" -- two byte strings,
   one value, in a format whose hashes are consensus-critical. *)
let rlp_length_overflow () =
  let body = String.make 100 '\x01' in
  rejects "8-byte length field wrapping to 100"
    (Rlp.decode ("\xff\x80\x00\x00\x00\x00\x00\x00\x64" ^ body));
  (* the canonical spelling of that same list must still decode *)
  (match Rlp.decode ("\xf8\x64" ^ body) with
   | Ok (Rlp.List items) -> Alcotest.(check int) "canonical 100-item list" 100 (List.length items)
   | _ -> Alcotest.fail "canonical long-form list should decode");
  rejects "length field longer than the input" (Rlp.decode ("\xff" ^ String.make 8 '\xff'));
  rejects "leading zero in a length field" (Rlp.decode ("\xf9\x00\x64" ^ body))

(* RLP has no representation for a negative scalar; encoding one as the
   empty string silently turned -5 into 0. *)
let rlp_negative () =
  raises_invalid "of_z of a negative" (fun () -> Rlp.of_z (Z.of_int (-5)));
  raises_invalid "of_int of a negative" (fun () -> Rlp.of_int (-5));
  Alcotest.(check string) "zero still encodes as 0x80" "80" (hexenc (Rlp.encode (Rlp.of_int 0)))

(* Nesting is bounded so adversarial input cannot drive deep recursion.
   (Not a demonstrated crash on OCaml 5, whose main-fiber stack grows;
   this is defence in depth for fixed-stack runtimes.) *)
let rlp_depth () =
  let rec nest d acc = if d = 0 then acc else nest (d - 1) (Rlp.List [ acc ]) in
  let deep = Rlp.encode (nest (Rlp.max_depth + 10) (Rlp.List [])) in
  rejects "nesting past max_depth" (Rlp.decode deep);
  let shallow = Rlp.encode (nest 10 (Rlp.List [])) in
  Alcotest.(check bool) "moderate nesting still decodes" true
    (match Rlp.decode shallow with Ok _ -> true | Error _ -> false)

(* Known non-canonical RLP spellings. Each is a second encoding of a value
   that already has a valid one, which is exactly what an RLP hash must not
   admit. *)
let rlp_noncanonical_vectors () =
  List.iter
    (fun (hex, why) -> rejects (why ^ ": " ^ hex) (Rlp.decode (hexdec hex)))
    [ ("8100", "single byte 0x00 given a length prefix");
      ("8101", "single byte 0x01 given a length prefix");
      ("817f", "single byte 0x7f given a length prefix");
      ("b800", "long form for an empty string");
      ("b801ff", "long form for a 1-byte string");
      ("b90000", "long form with a leading zero length");
      ("f800", "long form for an empty list");
      ("b83a" ^ String.concat "" (List.init 57 (fun _ -> "61")), "long-form length disagrees with payload");
      ("80ff", "trailing bytes after a complete value");
      ("c0c0", "trailing list after a complete value") ];
  (* and the canonical spellings of the same shapes must still decode *)
  List.iter
    (fun (hex, why) ->
      match Rlp.decode (hexdec hex) with
      | Ok _ -> ()
      | Error m -> Alcotest.failf "canonical %s (%s) rejected: %s" hex why m)
    [ ("00", "single byte 0x00"); ("7f", "single byte 0x7f");
      ("80", "empty string"); ("c0", "empty list");
      ("8180", "1-byte string 0x80 does need a prefix");
      ("b838" ^ String.concat "" (List.init 56 (fun _ -> "61")), "56-byte string in long form") ]

(* ---------------- SCALE ---------------- *)

(* Every compact mode accepted values belonging to a shorter mode, so one
   value had many spellings. *)
let scale_compact_canonical () =
  rejects "two-byte spelling of 0" (Scale.compact_of_octets "\x01\x00");
  rejects "two-byte spelling of 1" (Scale.compact_of_octets "\x05\x00");
  rejects "four-byte spelling of 0" (Scale.compact_of_octets "\x02\x00\x00\x00");
  rejects "big-int spelling of 0" (Scale.compact_of_octets "\x03\x00\x00\x00\x00");
  rejects "big-int with a leading zero byte"
    (Scale.compact_of_octets ("\x07" ^ "\x00\x00\x00\x40\x00"));
  (* the canonical spellings still decode *)
  List.iter
    (fun (bytes, expect) ->
      match Scale.compact_of_octets bytes with
      | Ok v -> Alcotest.(check string) ("canonical " ^ expect) expect (Z.to_string v)
      | Error m -> Alcotest.failf "canonical %s rejected: %s" expect m)
    [ ("\x00", "0"); ("\x04", "1"); ("\xfc", "63"); ("\x01\x01", "64");
      ("\xfe\xff\x03\x00", "65535") ]

(* A big-integer compact can spell a length far past [max_int]; converting
   it raised [Z.Overflow] out of a [result]-typed API. *)
let scale_length_overflow () =
  let hdr = Char.chr (((67 - 4) lsl 2) lor 3) in
  rejects "67-byte compact length" (Scale.bytes_of_octets (String.make 1 hdr ^ String.make 67 '\xff'))

(* Fixed-width encoders masked per byte, so an out-of-range balance was
   silently reduced mod 2^n. *)
let scale_encode_range () =
  raises_invalid "u16 of 70000" (fun () -> Scale.encode_u16 70000);
  raises_invalid "u8 of 300" (fun () -> Scale.encode_u8 300);
  raises_invalid "u64 of 2^64+5"
    (fun () -> Scale.encode_u64 (Z.add (Z.shift_left Z.one 64) (Z.of_int 5)));
  raises_invalid "u64 of a negative" (fun () -> Scale.encode_u64 (Z.of_int (-1)));
  Alcotest.(check string) "u64 max still encodes" "ffffffffffffffff"
    (hexenc (Scale.encode_u64 (Z.of_string "18446744073709551615")))

(* ---------------- Borsh ---------------- *)

let borsh_encode_range () =
  raises_invalid "u8 of 300" (fun () -> Borsh.encode_u8 300);
  raises_invalid "i8 of 200" (fun () -> Borsh.encode_i8 200);
  raises_invalid "u64 of 2^64+5"
    (fun () -> Borsh.encode_u64 (Z.add (Z.shift_left Z.one 64) (Z.of_int 5)));
  raises_invalid "i64 of 2^63" (fun () -> Borsh.encode_i64 (Z.shift_left Z.one 63));
  Alcotest.(check string) "i8 -128 still encodes" "80" (hexenc (Borsh.encode_i8 (-128)));
  Alcotest.(check string) "i8 127 still encodes" "7f" (hexenc (Borsh.encode_i8 127))

(* Borsh strings are UTF-8 by definition; arbitrary bytes were accepted in
   both directions. *)
let borsh_utf8 () =
  raises_invalid "encoding invalid UTF-8 as a string"
    (fun () -> Borsh.encode_string "\xff\xfe");
  rejects "decoding invalid UTF-8 as a string"
    (Borsh.of_octets Borsh.read_string (Borsh.encode_bytes "\xff\xfe"));
  Alcotest.(check bool) "opaque bytes still round-trip via encode_bytes" true
    (Borsh.of_octets Borsh.read_bytes (Borsh.encode_bytes "\xff\xfe") = Ok "\xff\xfe");
  Alcotest.(check bool) "multi-byte UTF-8 round-trips" true
    (Borsh.of_octets Borsh.read_string (Borsh.encode_string "héllo ☃") = Ok "héllo ☃")

let borsh_signed_readers () =
  List.iter
    (fun n ->
      let enc = Borsh.encode_i32 n in
      match Borsh.of_octets Borsh.read_i32 enc with
      | Ok v -> Alcotest.(check int) (Printf.sprintf "i32 %d round-trip" n) n v
      | Error m -> Alcotest.failf "i32 %d: %s" n m)
    [ 0; 1; -1; 2147483647; -2147483648 ]

(* ---------------- Bech32 ---------------- *)

(* BIP173 caps an address at 90 characters because the BCH code only
   guarantees detecting 4 errors within that length, and constrains the
   human-readable part to ASCII 33..126. Neither was enforced. *)
let bech32_limits () =
  rejects "91-character string" (Bech32.decode ("bc1" ^ String.make 88 'q'));
  rejects "hrp holding byte 0x80" (Bech32.decode "a\x80b1qqqqqqq");
  rejects "hrp holding a space" (Bech32.decode "a b1qqqqqqq");
  raises_invalid "encoding past 90 characters"
    (fun () -> Bech32.encode Bech32.Bech32 ~hrp:(String.make 100 'a') ~data:[ 0; 1; 2 ]);
  raises_invalid "encoding a bad hrp"
    (fun () -> Bech32.encode Bech32.Bech32 ~hrp:"a\x80b" ~data:[ 0 ]);
  raises_invalid "encoding an out-of-range data group"
    (fun () -> Bech32.encode Bech32.Bech32 ~hrp:"bc" ~data:[ 32 ])

(* The invalid-address lists published with BIP173 and BIP350 -- the
   vectors that exist precisely to catch the gaps above. *)
let bech32_official_invalid () =
  List.iter
    (fun (v, why) -> rejects (why ^ ": " ^ String.escaped v) (Bech32.decode v))
    [ ("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
       "overall max length exceeded");
      ("pzry9x0s0muk", "no separator");
      ("1pzry9x0s0muk", "empty hrp");
      ("x1b4n0q5v", "invalid data character");
      ("li1dgmt3", "too short checksum");
      ("de1lg7wt\xff", "invalid character in data part");
      ("A1G7SGD8", "checksum computed over the uppercase hrp");
      ("10a06t8", "empty hrp");
      ("1qzzfhee", "empty hrp");
      ("\x201nwldj5", "hrp character out of range");
      ("\x7f1axkwrx", "hrp character out of range") ]

let bech32_official_valid () =
  List.iter
    (fun v ->
      match Bech32.decode v with
      | Ok _ -> ()
      | Error m -> Alcotest.failf "valid vector %s rejected: %s" v m)
    [ "A1LQFN3A"; "a1lqfn3a";
      "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx";
      "?1v759aa";
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
      "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5" ]

(* A v0 program must carry a Bech32 checksum and v1+ a Bech32m one; mixing
   them is how a Taproot address could be read as a v0 one. *)
let bech32_variant_binding () =
  let taproot = "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5" in
  rejects "taproot address under the wrong hrp" (Bech32.decode_segwit ~hrp:"tb" taproot);
  (* BIP350 invalid: v0 witness with a bech32m checksum, and vice versa *)
  rejects "v0 with a bech32m checksum"
    (Bech32.decode_segwit ~hrp:"bc" "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemcr6x");
  rejects "v1 with a bech32 checksum"
    (Bech32.decode_segwit ~hrp:"bc"
       "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4")

(* ---------------- Base58 ---------------- *)

(* Base conversion is quadratic; unbounded input turned a pasted megabyte
   into a minute of CPU. *)
let base58_length_cap () =
  rejects "20k-character input" (Base58.decode (String.make 20_000 'z'));
  raises_invalid "encoding past the cap"
    (fun () -> Base58.encode (String.make (Base58.max_length + 1) '\x01'));
  (* everything of a realistic size still works *)
  Alcotest.(check string) "a real address still decodes"
    "00010966776006953d5567439e5e39f86a0d273bee"
    (hexenc (Result.get_ok (Base58.decode_check "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")))

(* ---------------- CRC ---------------- *)

(* [crc.ml] arrived with no test coverage. These are the standard check
   values -- the CRC of the ASCII string "123456789" -- published with each
   algorithm, plus the byte orders the .mli promises.

   Worth being explicit about what these are for: a CRC detects accidental
   corruption, not tampering. TON's address checksum stops a mistyped
   address, and nothing more; it is not a security boundary. *)
let crc_check_values () =
  let s = "123456789" in
  Alcotest.(check int) "CRC-16/XMODEM" 0x31C3 (Crc.crc16_xmodem s);
  Alcotest.(check int) "CRC-32/ISO-HDLC" 0xCBF43926 (Crc.crc32 s);
  Alcotest.(check int) "CRC-32C (Castagnoli)" 0xE3069283 (Crc.crc32c s);
  Alcotest.(check int) "CRC-16/XMODEM of empty" 0x0000 (Crc.crc16_xmodem "");
  Alcotest.(check int) "CRC-32 of empty" 0x00000000 (Crc.crc32 "");
  Alcotest.(check int) "CRC-32C of empty" 0x00000000 (Crc.crc32c "")

let crc_byte_order () =
  let s = "123456789" in
  Alcotest.(check string) "crc16_xmodem_be is big-endian" "31c3" (hexenc (Crc.crc16_xmodem_be s));
  Alcotest.(check string) "crc32_le is little-endian" "2639f4cb" (hexenc (Crc.crc32_le s));
  Alcotest.(check string) "crc32c_le is little-endian" "839206e3" (hexenc (Crc.crc32c_le s));
  (* every output is exactly its declared width *)
  Alcotest.(check int) "crc16 is 2 bytes" 2 (String.length (Crc.crc16_xmodem_be s));
  Alcotest.(check int) "crc32 is 4 bytes" 4 (String.length (Crc.crc32_le s));
  Alcotest.(check int) "crc32c is 4 bytes" 4 (String.length (Crc.crc32c_le s))

(* A CRC must stay inside its declared width for every input, including
   ones with the high bit set throughout. *)
let crc_width_invariant () =
  List.iter
    (fun s ->
      Alcotest.(check bool) "crc16 fits 16 bits" true (Crc.crc16_xmodem s land lnot 0xffff = 0);
      Alcotest.(check bool) "crc32 fits 32 bits" true (Crc.crc32 s land lnot 0xffffffff = 0);
      Alcotest.(check bool) "crc32c fits 32 bits" true (Crc.crc32c s land lnot 0xffffffff = 0))
    [ ""; "\x00"; "\xff"; String.make 100 '\xff'; String.make 1000 '\x00';
      String.init 256 Char.chr ]

let suite =
  [ ("crc-coverage",
     [ Alcotest.test_case "standard check values" `Quick crc_check_values;
       Alcotest.test_case "byte order and width" `Quick crc_byte_order;
       Alcotest.test_case "width invariant" `Quick crc_width_invariant ]);
    ("abi-regressions",
     [ Alcotest.test_case "256-bit word overflow" `Quick abi_word_overflow;
       Alcotest.test_case "array length bomb" `Quick abi_array_bomb;
       Alcotest.test_case "declared integer width" `Quick abi_int_width;
       Alcotest.test_case "non-canonical words" `Quick abi_canonical_words;
       Alcotest.test_case "encode-side validation" `Quick abi_encode_validation ]);
    ("rlp-regressions",
     [ Alcotest.test_case "length-field overflow" `Quick rlp_length_overflow;
       Alcotest.test_case "negative scalars" `Quick rlp_negative;
       Alcotest.test_case "nesting depth" `Quick rlp_depth;
       Alcotest.test_case "non-canonical vectors" `Quick rlp_noncanonical_vectors ]);
    ("scale-regressions",
     [ Alcotest.test_case "compact canonicity" `Quick scale_compact_canonical;
       Alcotest.test_case "compact length overflow" `Quick scale_length_overflow;
       Alcotest.test_case "encoder range checks" `Quick scale_encode_range ]);
    ("borsh-regressions",
     [ Alcotest.test_case "encoder range checks" `Quick borsh_encode_range;
       Alcotest.test_case "utf-8 strings" `Quick borsh_utf8;
       Alcotest.test_case "signed readers" `Quick borsh_signed_readers ]);
    ("bech32-regressions",
     [ Alcotest.test_case "length and hrp limits" `Quick bech32_limits;
       Alcotest.test_case "BIP173/350 invalid vectors" `Quick bech32_official_invalid;
       Alcotest.test_case "BIP173/350 valid vectors" `Quick bech32_official_valid;
       Alcotest.test_case "version/variant binding" `Quick bech32_variant_binding ]);
    ("base58-regressions",
     [ Alcotest.test_case "input length cap" `Quick base58_length_cap ]) ]
