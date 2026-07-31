(* SS58, Substrate/Polkadot's address format: a network prefix and an
   account id, Base58-encoded with a Blake2b checksum. This covers the
   common case of a 32-byte account id and a single-byte network prefix
   (< 64), which includes Polkadot (0), Kusama (2), and the generic
   Substrate prefix (42). *)

let blake2b512 s = Digestif.BLAKE2B.(to_raw_string (digest_string s))

let context = "SS58PRE"

let encode ~network pubkey =
  if network < 0 || network >= 64 then invalid_arg "Ss58.encode: network prefix must be < 64"
  else if String.length pubkey <> 32 then invalid_arg "Ss58.encode: account id must be 32 bytes"
  else begin
    let body = String.make 1 (Char.chr network) ^ pubkey in
    let checksum = String.sub (blake2b512 (context ^ body)) 0 2 in
    Base58.encode (body ^ checksum)
  end

let decode s =
  match Base58.decode s with
  | Error _ as e -> e
  | Ok raw ->
    (* 1 prefix byte + 32 account bytes + 2 checksum bytes *)
    if String.length raw <> 35 then Error "ss58: unexpected length"
    else
      let network = Char.code raw.[0] in
      let body = String.sub raw 0 33 and cs = String.sub raw 33 2 in
      if String.equal cs (String.sub (blake2b512 (context ^ body)) 0 2) then
        Ok (network, String.sub raw 1 32)
      else Error "ss58: bad checksum"
