(* Base58 and Base58Check, as used by Bitcoin (legacy addresses, WIF),
   TRON, and Solana (plain Base58 for keys). Base58Check appends a
   4-byte SHA256d checksum.

   The radix conversion itself lives in {!Basen}, shared with the other
   non-power-of-two bases multibase needs. This module is the Bitcoin
   alphabet plus the checksum, and keeps its own tight length cap: it is
   the entry point that parses pasted addresses, where the quadratic cost
   is worth bounding hard. Multibase asks Basen for a larger bound
   directly. *)

let max_length = 1024

let encode s = Basen.encode ~max_length ~name:"Base58" Basen.btc s
let decode s = Basen.decode ~max_length ~name:"base58" Basen.btc s

let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let checksum s = String.sub (sha256 (sha256 s)) 0 4

let encode_check payload = encode (payload ^ checksum payload)

let decode_check s =
  match decode s with
  | Error _ as e -> e
  | Ok raw ->
    let n = String.length raw in
    if n < 4 then Error "base58check: too short for a checksum"
    else
      let payload = String.sub raw 0 (n - 4) and cs = String.sub raw (n - 4) 4 in
      if String.equal cs (checksum payload) then Ok payload
      else Error "base58check: bad checksum"
