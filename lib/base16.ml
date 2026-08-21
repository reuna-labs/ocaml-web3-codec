(* Hexadecimal. Byte-aligned (two symbols per byte), so it never pads and
   never has trailing bits to worry about. *)

let t_lower = Bitbase.make ~bits:4 ~alphabet:"0123456789abcdef"
let t_upper = Bitbase.make ~bits:4 ~alphabet:"0123456789ABCDEF"
let table upper = if upper then t_upper else t_lower

let encode ?(upper = false) s = Bitbase.encode (table upper) s

(* Case is not folded: multibase gives base16 and base16upper separate
   prefixes, so accepting either here would let one payload have two
   spellings under a single prefix. *)
let decode ?(upper = false) s = Bitbase.decode (table upper) s
