(** Bech32 (BIP173) and Bech32m (BIP350).

    The implementation lives in the lean {!Web3_codec_bech32} package; this is
    a re-export so that [Web3_codec.Bech32] keeps working. New code that needs
    only an address encoding should depend on [web3-codec-bech32] directly
    rather than on this umbrella. *)

include module type of struct
  include Web3_codec_bech32
end
