(* Bech32 (BIP173) and Bech32m (BIP350), the base-32 checksummed encoding
   behind SegWit addresses. SegWit v0 uses Bech32; v1+ (Taproot) uses
   Bech32m. *)

type encoding = Bech32 | Bech32m

let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

let inverse =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) charset;
  t

let const = function Bech32 -> 1 | Bech32m -> 0x2bc830a3

let polymod values =
  let gen = [| 0x3b6a57b2; 0x26508e6d; 0x1ea119fa; 0x3d4233dd; 0x2a1462b3 |] in
  let chk = ref 1 in
  List.iter
    (fun v ->
      let top = !chk lsr 25 in
      chk := ((!chk land 0x1ffffff) lsl 5) lxor v;
      for i = 0 to 4 do
        if (top lsr i) land 1 <> 0 then chk := !chk lxor gen.(i)
      done)
    values;
  !chk

let hrp_expand hrp =
  let n = String.length hrp in
  List.init n (fun i -> Char.code hrp.[i] lsr 5)
  @ [ 0 ]
  @ List.init n (fun i -> Char.code hrp.[i] land 31)

let create_checksum enc hrp data =
  let values = hrp_expand hrp @ data @ [ 0; 0; 0; 0; 0; 0 ] in
  let m = polymod values lxor const enc in
  List.init 6 (fun i -> (m lsr (5 * (5 - i))) land 31)

let verify_checksum hrp data =
  match polymod (hrp_expand hrp @ data) with
  | 1 -> Some Bech32
  | 0x2bc830a3 -> Some Bech32m
  | _ -> None

(* [convertbits data from to pad] regroups a list of [from]-bit values
   into [to]-bit values (MSB first). *)
let convertbits ?(pad = true) data ~from ~into =
  let acc = ref 0 and bits = ref 0 and out = ref [] in
  let maxv = (1 lsl into) - 1 in
  let ok = ref true in
  List.iter
    (fun v ->
      if v < 0 || v lsr from <> 0 then ok := false;
      acc := (!acc lsl from) lor v;
      bits := !bits + from;
      while !bits >= into do
        bits := !bits - into;
        out := ((!acc lsr !bits) land maxv) :: !out
      done)
    data;
  if pad then begin
    if !bits > 0 then out := ((!acc lsl (into - !bits)) land maxv) :: !out
  end
  else if !bits >= from || (!acc lsl (into - !bits)) land maxv <> 0 then ok := false;
  if !ok then Some (List.rev !out) else None

(* [encode enc ~hrp ~data]: [data] are 5-bit groups (0..31). *)
let encode enc ~hrp ~data =
  let combined = data @ create_checksum enc hrp data in
  hrp ^ "1" ^ String.concat "" (List.map (fun d -> String.make 1 charset.[d]) combined)

let decode s =
  let n = String.length s in
  let has_lower = ref false and has_upper = ref false in
  String.iter
    (fun c ->
      if c >= 'a' && c <= 'z' then has_lower := true;
      if c >= 'A' && c <= 'Z' then has_upper := true)
    s;
  if !has_lower && !has_upper then Error "bech32: mixed case"
  else begin
    let s = String.lowercase_ascii s in
    match String.rindex_opt s '1' with
    | None -> Error "bech32: missing separator"
    | Some sep ->
      if sep < 1 || sep + 7 > n then Error "bech32: misplaced separator"
      else begin
        let hrp = String.sub s 0 sep in
        let data_part = String.sub s (sep + 1) (n - sep - 1) in
        let exception Bad in
        match
          List.init (String.length data_part) (fun i ->
              let d = inverse.(Char.code data_part.[i]) in
              if d < 0 then raise Bad;
              d)
        with
        | values -> (
          match verify_checksum hrp values with
          | None -> Error "bech32: bad checksum"
          | Some enc ->
            let data = List.filteri (fun i _ -> i < List.length values - 6) values in
            Ok (enc, hrp, data))
        | exception Bad -> Error "bech32: invalid character"
      end
  end

(* ---- SegWit addresses (BIP173/BIP350) ---- *)

let encode_segwit ~hrp ~version ~program =
  if version < 0 || version > 16 then Error "segwit: version out of range"
  else if String.length program < 2 || String.length program > 40 then
    Error "segwit: program length out of range"
  else if version = 0 && String.length program <> 20 && String.length program <> 32 then
    Error "segwit: v0 program must be 20 or 32 bytes"
  else
    let enc = if version = 0 then Bech32 else Bech32m in
    match
      convertbits (List.init (String.length program) (fun i -> Char.code program.[i])) ~from:8 ~into:5
    with
    | None -> Error "segwit: bit conversion failed"
    | Some prog5 -> Ok (encode enc ~hrp ~data:(version :: prog5))

let decode_segwit ~hrp s =
  match decode s with
  | Error _ as e -> e
  | Ok (enc, hrp', data) ->
    if not (String.equal hrp hrp') then Error "segwit: wrong human-readable part"
    else
      match data with
      | [] -> Error "segwit: empty data"
      | version :: rest ->
        if version < 0 || version > 16 then Error "segwit: version out of range"
        else if (version = 0 && enc <> Bech32) || (version <> 0 && enc <> Bech32m) then
          Error "segwit: wrong bech32 variant for version"
        else (
          match convertbits ~pad:false rest ~from:5 ~into:8 with
          | None -> Error "segwit: bit conversion failed"
          | Some prog ->
            let len = List.length prog in
            if len < 2 || len > 40 then Error "segwit: program length out of range"
            else if version = 0 && len <> 20 && len <> 32 then
              Error "segwit: v0 program must be 20 or 32 bytes"
            else Ok (version, String.init len (fun i -> Char.chr (List.nth prog i))))
