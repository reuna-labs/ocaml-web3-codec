(* Base58 and Base58Check, as used by Bitcoin (legacy addresses, WIF),
   TRON, and Solana (plain Base58 for keys). Base58Check appends a
   4-byte SHA256d checksum. *)

let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

let inverse =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) alphabet;
  t

let encode s =
  let n = String.length s in
  let zeros = ref 0 in
  while !zeros < n && s.[!zeros] = '\000' do
    incr zeros
  done;
  let z = ref Z.zero in
  String.iter (fun c -> z := Z.add (Z.mul !z (Z.of_int 256)) (Z.of_int (Char.code c))) s;
  let buf = Buffer.create (n * 2) in
  let fifty8 = Z.of_int 58 in
  while Z.sign !z > 0 do
    let q, r = Z.div_rem !z fifty8 in
    Buffer.add_char buf alphabet.[Z.to_int r];
    z := q
  done;
  for _ = 1 to !zeros do
    Buffer.add_char buf '1'
  done;
  let b = Buffer.contents buf in
  (* digits were produced least-significant first: reverse *)
  String.init (String.length b) (fun i -> b.[String.length b - 1 - i])

let decode s =
  let n = String.length s in
  let ones = ref 0 in
  while !ones < n && s.[!ones] = '1' do
    incr ones
  done;
  let exception Bad in
  match
    let z = ref Z.zero in
    let fifty8 = Z.of_int 58 in
    String.iter
      (fun c ->
        let d = inverse.(Char.code c) in
        if d < 0 then raise Bad;
        z := Z.add (Z.mul !z fifty8) (Z.of_int d))
      s;
    (* big-endian bytes of z, then restore leading zero bytes as '1's *)
    let body =
      if Z.sign !z = 0 then ""
      else begin
        let nb = (Z.numbits !z + 7) / 8 in
        String.init nb (fun i ->
            Char.chr (Z.to_int (Z.logand (Z.shift_right !z (8 * (nb - 1 - i))) (Z.of_int 0xff))))
      end
    in
    String.make !ones '\000' ^ body
  with
  | v -> Ok v
  | exception Bad -> Error "base58: invalid character"

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
