(* Bech32 now lives in the lean web3-codec-bech32 package (lib/bech32/).

   This re-export keeps [Web3_codec.Bech32] working for consumers that already
   take the umbrella, so slicing the package out is not a breaking change. *)
include Web3_codec_bech32
