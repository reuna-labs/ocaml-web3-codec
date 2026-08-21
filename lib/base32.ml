(* RFC4648 base32 in its standard and extended-hex alphabets, plus
   z-base-32 (Zooko's human-oriented variant, used by multibase as
   base32z). *)

type alphabet = Rfc4648 | Rfc4648_upper | Hex | Hex_upper | Z_base_32

let t_rfc = Bitbase.make ~bits:5 ~alphabet:"abcdefghijklmnopqrstuvwxyz234567"
let t_rfc_upper = Bitbase.make ~bits:5 ~alphabet:"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
let t_hex = Bitbase.make ~bits:5 ~alphabet:"0123456789abcdefghijklmnopqrstuv"
let t_hex_upper = Bitbase.make ~bits:5 ~alphabet:"0123456789ABCDEFGHIJKLMNOPQRSTUV"
let t_zbase32 = Bitbase.make ~bits:5 ~alphabet:"ybndrfg8ejkmcpqxot1uwisza345h769"

let table = function
  | Rfc4648 -> t_rfc
  | Rfc4648_upper -> t_rfc_upper
  | Hex -> t_hex
  | Hex_upper -> t_hex_upper
  | Z_base_32 -> t_zbase32

let encode ?(alphabet = Rfc4648) ?(pad = false) s = Bitbase.encode ~pad (table alphabet) s
let decode ?(alphabet = Rfc4648) ?(pad = false) s = Bitbase.decode ~pad (table alphabet) s
