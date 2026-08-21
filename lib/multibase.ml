(* Multibase: a self-describing base encoding. One leading character says
   which base the rest is in.
   https://github.com/multiformats/multibase

   Every base here decodes canonically -- the underlying {!Bitbase} rejects
   non-zero trailing bits, and {!Basen} preserves leading zeros -- so a
   payload has exactly one spelling per base. That matters because a CID is
   commonly compared as text. *)

type base =
  | Identity
  | Base2
  | Base8
  | Base10
  | Base16
  | Base16upper
  | Base32
  | Base32upper
  | Base32pad
  | Base32padupper
  | Base32hex
  | Base32hexupper
  | Base32hexpad
  | Base32hexpadupper
  | Base32z
  | Base36
  | Base36upper
  | Base58btc
  | Base58flickr
  | Base64
  | Base64pad
  | Base64url
  | Base64urlpad

let all =
  [ Identity; Base2; Base8; Base10; Base16; Base16upper; Base32; Base32upper;
    Base32pad; Base32padupper; Base32hex; Base32hexupper; Base32hexpad;
    Base32hexpadupper; Base32z; Base36; Base36upper; Base58btc; Base58flickr;
    Base64; Base64pad; Base64url; Base64urlpad ]

let prefix = function
  | Identity -> '\x00'
  | Base2 -> '0'
  | Base8 -> '7'
  | Base10 -> '9'
  | Base16 -> 'f'
  | Base16upper -> 'F'
  | Base32 -> 'b'
  | Base32upper -> 'B'
  | Base32pad -> 'c'
  | Base32padupper -> 'C'
  | Base32hex -> 'v'
  | Base32hexupper -> 'V'
  | Base32hexpad -> 't'
  | Base32hexpadupper -> 'T'
  | Base32z -> 'h'
  | Base36 -> 'k'
  | Base36upper -> 'K'
  | Base58btc -> 'z'
  | Base58flickr -> 'Z'
  | Base64 -> 'm'
  | Base64pad -> 'M'
  | Base64url -> 'u'
  | Base64urlpad -> 'U'

let name = function
  | Identity -> "identity"
  | Base2 -> "base2"
  | Base8 -> "base8"
  | Base10 -> "base10"
  | Base16 -> "base16"
  | Base16upper -> "base16upper"
  | Base32 -> "base32"
  | Base32upper -> "base32upper"
  | Base32pad -> "base32pad"
  | Base32padupper -> "base32padupper"
  | Base32hex -> "base32hex"
  | Base32hexupper -> "base32hexupper"
  | Base32hexpad -> "base32hexpad"
  | Base32hexpadupper -> "base32hexpadupper"
  | Base32z -> "base32z"
  | Base36 -> "base36"
  | Base36upper -> "base36upper"
  | Base58btc -> "base58btc"
  | Base58flickr -> "base58flickr"
  | Base64 -> "base64"
  | Base64pad -> "base64pad"
  | Base64url -> "base64url"
  | Base64urlpad -> "base64urlpad"

let of_prefix c = List.find_opt (fun b -> prefix b = c) all
let of_name n = List.find_opt (fun b -> name b = n) all

let t_base2 = Bitbase.make ~bits:1 ~alphabet:"01"
let t_base8 = Bitbase.make ~bits:3 ~alphabet:"01234567"

(* The radix bases are quadratic, so they carry a bound; see {!Basen}. *)
let max_radix_length = Basen.default_max_length

(* [body] encodes without the prefix character. *)
let body b s =
  match b with
  | Identity -> s
  | Base2 -> Bitbase.encode t_base2 s
  | Base8 -> Bitbase.encode t_base8 s
  | Base10 -> Basen.encode ~max_length:max_radix_length ~name:"base10" Basen.base10 s
  | Base16 -> Base16.encode s
  | Base16upper -> Base16.encode ~upper:true s
  | Base32 -> Base32.encode s
  | Base32upper -> Base32.encode ~alphabet:Base32.Rfc4648_upper s
  | Base32pad -> Base32.encode ~pad:true s
  | Base32padupper -> Base32.encode ~alphabet:Base32.Rfc4648_upper ~pad:true s
  | Base32hex -> Base32.encode ~alphabet:Base32.Hex s
  | Base32hexupper -> Base32.encode ~alphabet:Base32.Hex_upper s
  | Base32hexpad -> Base32.encode ~alphabet:Base32.Hex ~pad:true s
  | Base32hexpadupper -> Base32.encode ~alphabet:Base32.Hex_upper ~pad:true s
  | Base32z -> Base32.encode ~alphabet:Base32.Z_base_32 s
  | Base36 -> Basen.encode ~max_length:max_radix_length ~name:"base36" Basen.base36 s
  | Base36upper -> Basen.encode ~max_length:max_radix_length ~name:"base36upper" Basen.base36_upper s
  | Base58btc -> Basen.encode ~max_length:max_radix_length ~name:"base58btc" Basen.btc s
  | Base58flickr -> Basen.encode ~max_length:max_radix_length ~name:"base58flickr" Basen.flickr s
  | Base64 -> Base64.encode s
  | Base64pad -> Base64.encode ~pad:true s
  | Base64url -> Base64.encode ~alphabet:Base64.Url s
  | Base64urlpad -> Base64.encode ~alphabet:Base64.Url ~pad:true s

let decode_body b s =
  match b with
  | Identity -> Ok s
  | Base2 -> Bitbase.decode t_base2 s
  | Base8 -> Bitbase.decode t_base8 s
  | Base10 -> Basen.decode ~max_length:max_radix_length ~name:"base10" Basen.base10 s
  | Base16 -> Base16.decode s
  | Base16upper -> Base16.decode ~upper:true s
  | Base32 -> Base32.decode s
  | Base32upper -> Base32.decode ~alphabet:Base32.Rfc4648_upper s
  | Base32pad -> Base32.decode ~pad:true s
  | Base32padupper -> Base32.decode ~alphabet:Base32.Rfc4648_upper ~pad:true s
  | Base32hex -> Base32.decode ~alphabet:Base32.Hex s
  | Base32hexupper -> Base32.decode ~alphabet:Base32.Hex_upper s
  | Base32hexpad -> Base32.decode ~alphabet:Base32.Hex ~pad:true s
  | Base32hexpadupper -> Base32.decode ~alphabet:Base32.Hex_upper ~pad:true s
  | Base32z -> Base32.decode ~alphabet:Base32.Z_base_32 s
  | Base36 -> Basen.decode ~max_length:max_radix_length ~name:"base36" Basen.base36 s
  | Base36upper -> Basen.decode ~max_length:max_radix_length ~name:"base36upper" Basen.base36_upper s
  | Base58btc -> Basen.decode ~max_length:max_radix_length ~name:"base58btc" Basen.btc s
  | Base58flickr -> Basen.decode ~max_length:max_radix_length ~name:"base58flickr" Basen.flickr s
  | Base64 -> Base64.decode s
  | Base64pad -> Base64.decode ~pad:true s
  | Base64url -> Base64.decode ~alphabet:Base64.Url s
  | Base64urlpad -> Base64.decode ~alphabet:Base64.Url ~pad:true s

let encode b s = String.make 1 (prefix b) ^ body b s

let decode s =
  if String.length s = 0 then Error "multibase: empty input"
  else
    match of_prefix s.[0] with
    | None -> Error (Printf.sprintf "multibase: unknown prefix %C" s.[0])
    | Some b -> (
      match decode_body b (String.sub s 1 (String.length s - 1)) with
      | Ok v -> Ok (b, v)
      | Error m -> Error m)
