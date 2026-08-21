(* RFC4648 base64, standard and URL-safe alphabets. *)

type alphabet = Standard | Url

let t_standard =
  Bitbase.make ~bits:6
    ~alphabet:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

let t_url =
  Bitbase.make ~bits:6
    ~alphabet:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

let table = function Standard -> t_standard | Url -> t_url

let encode ?(alphabet = Standard) ?(pad = false) s = Bitbase.encode ~pad (table alphabet) s
let decode ?(alphabet = Standard) ?(pad = false) s = Bitbase.decode ~pad (table alphabet) s
