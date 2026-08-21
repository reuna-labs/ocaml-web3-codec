(* Generic power-of-two base encoding: regroup bytes into fixed-width
   symbols, most significant bit first. One implementation covers base2,
   base8, base16, base32 and base64 -- they differ only in how many bits a
   symbol carries and which characters spell them.

   Decoding is canonical. Two rules do that work:

     - the trailing bits left over after the last whole byte must be zero.
       A decoder that ignores them accepts many spellings of one payload,
       which is the classic base64 malleability.
     - a symbol count that leaves a whole symbol's worth of bits unused is
       rejected, because that symbol carried nothing. For base32 this is
       what makes counts of 1, 3 and 6 within a group invalid.

   Unlike the radix bases in {!Basen} this is linear, so it needs no input
   length cap. *)

type t = {
  alphabet : string;
  bits : int;
  mask : int;
  accmask : int;
  inverse : int array;
  group : int; (* symbols per whole-byte group, i.e. the padding period *)
}

let rec gcd a b = if b = 0 then a else gcd b (a mod b)

let make ~bits ~alphabet =
  if bits < 1 || bits > 6 then invalid_arg "Bitbase.make: bits must be 1..6";
  if String.length alphabet <> 1 lsl bits then
    invalid_arg (Printf.sprintf "Bitbase.make: alphabet must hold %d symbols" (1 lsl bits));
  let inverse = Array.make 256 (-1) in
  String.iteri
    (fun i c ->
      if c = '=' then invalid_arg "Bitbase.make: '=' is reserved for padding";
      if inverse.(Char.code c) >= 0 then invalid_arg "Bitbase.make: duplicate symbol";
      inverse.(Char.code c) <- i)
    alphabet;
  { alphabet; bits; mask = (1 lsl bits) - 1;
    (* only [bits + 8] bits of the accumulator are ever read back *)
    accmask = (1 lsl (bits + 8)) - 1;
    inverse; group = 8 / gcd 8 bits }

let group t = t.group

let encode ?(pad = false) t s =
  let buf = Buffer.create (((String.length s * 8) / t.bits) + 8) in
  let acc = ref 0 and nbits = ref 0 in
  String.iter
    (fun c ->
      acc := ((!acc lsl 8) lor Char.code c) land t.accmask;
      nbits := !nbits + 8;
      while !nbits >= t.bits do
        nbits := !nbits - t.bits;
        Buffer.add_char buf t.alphabet.[(!acc lsr !nbits) land t.mask]
      done)
    s;
  if !nbits > 0 then
    Buffer.add_char buf t.alphabet.[(!acc lsl (t.bits - !nbits)) land t.mask];
  if pad then begin
    let r = Buffer.length buf mod t.group in
    if r <> 0 then
      for _ = 1 to t.group - r do
        Buffer.add_char buf '='
      done
  end;
  Buffer.contents buf

let decode ?(pad = false) t s =
  let n = String.length s in
  let npad =
    let i = ref n in
    while !i > 0 && s.[!i - 1] = '=' do decr i done;
    n - !i
  in
  let body_len = n - npad in
  let bad_padding =
    if pad then
      (* a padded encoding is a whole number of groups, the padding never
         fills a whole group, and it is exactly the amount the encoder
         would have added *)
      n mod t.group <> 0 || npad >= t.group
      || (t.group - (body_len mod t.group)) mod t.group <> npad
    else npad > 0
  in
  if bad_padding then Error "base: bad padding"
  else begin
    let body = String.sub s 0 body_len in
    let out = Buffer.create ((body_len * t.bits / 8) + 1) in
    let acc = ref 0 and nbits = ref 0 in
    let exception Bad in
    match
      String.iter
        (fun c ->
          let v = t.inverse.(Char.code c) in
          if v < 0 then raise Bad;
          acc := ((!acc lsl t.bits) lor v) land t.accmask;
          nbits := !nbits + t.bits;
          while !nbits >= 8 do
            nbits := !nbits - 8;
            Buffer.add_char out (Char.chr ((!acc lsr !nbits) land 0xff))
          done)
        body
    with
    | () ->
      if !nbits >= t.bits then Error "base: trailing symbol carries no data"
      else if !nbits > 0 && !acc land ((1 lsl !nbits) - 1) <> 0 then
        Error "base: non-zero trailing bits"
      else Ok (Buffer.contents out)
    | exception Bad -> Error "base: invalid character"
  end
