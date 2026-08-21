(* Bitwise for CRC-16 (short inputs, not worth a table) and table-driven for
   the CRC-32 variants (used over whole Bags of Cells, which can be megabytes).

   All arithmetic stays below 2^32, so it is exact in a 63-bit OCaml int. *)

let crc16_xmodem s =
  let reg = ref 0 in
  let feed byte =
    let mask = ref 0x80 in
    while !mask > 0 do
      reg := !reg lsl 1;
      if byte land !mask <> 0 then incr reg;
      mask := !mask lsr 1;
      if !reg > 0xffff then reg := (!reg land 0xffff) lxor 0x1021
    done
  in
  String.iter (fun c -> feed (Char.code c)) s;
  (* Two zero bytes flush the register, which is what makes this XMODEM
     rather than CCITT-FALSE. *)
  feed 0;
  feed 0;
  !reg

let crc16_xmodem_be s =
  let r = crc16_xmodem s in
  String.init 2 (fun i -> Char.chr (if i = 0 then r lsr 8 else r land 0xff))

let make_table poly =
  Array.init 256 (fun n ->
      let c = ref n in
      for _ = 0 to 7 do
        c := if !c land 1 = 1 then (!c lsr 1) lxor poly else !c lsr 1
      done;
      !c)

let table_ieee = lazy (make_table 0xedb88320)
let table_castagnoli = lazy (make_table 0x82f63b78)

let reflected table s =
  let t = Lazy.force table in
  let crc = ref 0xffffffff in
  String.iter
    (fun ch -> crc := t.((!crc lxor Char.code ch) land 0xff) lxor (!crc lsr 8))
    s;
  !crc lxor 0xffffffff

let le32 v = String.init 4 (fun i -> Char.chr ((v lsr (8 * i)) land 0xff))
let crc32 s = reflected table_ieee s
let crc32_le s = le32 (crc32 s)
let crc32c s = reflected table_castagnoli s
let crc32c_le s = le32 (crc32c s)
