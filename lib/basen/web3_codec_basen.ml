(* Radix conversion for the bases whose radix is not a power of two --
   base10, base36, base58 -- where regrouping bits does not work and the
   whole input has to be treated as one big integer.

   That makes it quadratic: one bignum multiply-add per character over a
   number that grows with the input. Hence [~max_length]; the linear
   power-of-two bases in {!Bitbase} need no such bound.

   Leading zero bytes are carried across separately. They contribute
   nothing to the integer, so without this a leading 0x00 would vanish and
   encoding would not round-trip. *)

type t = { alphabet : string; base : Z.t; inverse : int array; zero : char }

let default_max_length = 16384

let make ~alphabet =
  let n = String.length alphabet in
  if n < 2 then invalid_arg "Basen.make: alphabet needs at least two symbols";
  let inverse = Array.make 256 (-1) in
  String.iteri
    (fun i c ->
      if inverse.(Char.code c) >= 0 then invalid_arg "Basen.make: duplicate symbol";
      inverse.(Char.code c) <- i)
    alphabet;
  { alphabet; base = Z.of_int n; inverse; zero = alphabet.[0] }

let encode ?(max_length = default_max_length) ?(name = "basen") t s =
  if String.length s > max_length then
    invalid_arg (Printf.sprintf "%s.encode: input longer than %d bytes" name max_length);
  let n = String.length s in
  let zeros = ref 0 in
  while !zeros < n && s.[!zeros] = '\000' do
    incr zeros
  done;
  let z = ref Z.zero in
  String.iter (fun c -> z := Z.add (Z.mul !z (Z.of_int 256)) (Z.of_int (Char.code c))) s;
  let buf = Buffer.create (n * 2) in
  while Z.sign !z > 0 do
    let q, r = Z.div_rem !z t.base in
    Buffer.add_char buf t.alphabet.[Z.to_int r];
    z := q
  done;
  for _ = 1 to !zeros do
    Buffer.add_char buf t.zero
  done;
  let b = Buffer.contents buf in
  (* digits were produced least-significant first: reverse *)
  String.init (String.length b) (fun i -> b.[String.length b - 1 - i])

let decode ?(max_length = default_max_length) ?(name = "basen") t s =
  let n = String.length s in
  if n > max_length then Error (name ^ ": input too long")
  else begin
    let zeros = ref 0 in
    while !zeros < n && s.[!zeros] = t.zero do
      incr zeros
    done;
    let exception Bad in
    match
      let z = ref Z.zero in
      String.iter
        (fun c ->
          let d = t.inverse.(Char.code c) in
          if d < 0 then raise Bad;
          z := Z.add (Z.mul !z t.base) (Z.of_int d))
        s;
      let body =
        if Z.sign !z = 0 then ""
        else begin
          let nb = (Z.numbits !z + 7) / 8 in
          String.init nb (fun i ->
              Char.chr (Z.to_int (Z.logand (Z.shift_right !z (8 * (nb - 1 - i))) (Z.of_int 0xff))))
        end
      in
      String.make !zeros '\000' ^ body
    with
    | v -> Ok v
    | exception Bad -> Error (name ^ ": invalid character")
  end

(* the alphabets this library needs *)
let btc = make ~alphabet:"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
let flickr = make ~alphabet:"123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
let base36 = make ~alphabet:"0123456789abcdefghijklmnopqrstuvwxyz"
let base36_upper = make ~alphabet:"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
let base10 = make ~alphabet:"0123456789"
