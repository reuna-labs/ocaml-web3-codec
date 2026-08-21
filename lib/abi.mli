(** @deprecated Ethereum ABI support moved to the [evm-abi] package. Use
    {!Evm_abi} for new code. This forwarding module remains for one release. *)
include module type of Evm_abi
