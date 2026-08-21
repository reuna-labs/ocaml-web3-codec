(** Cyclic redundancy checks used by blockchain wire formats.

    These are small, self-contained and dependency-free on purpose: they are
    needed by codecs that must link into freestanding/unikernel targets, where
    pulling in a C-backed checksum library is unwelcome. *)

val crc16_xmodem : string -> int
(** CRC-16/XMODEM: polynomial [0x1021], initial value [0], no input or output
    reflection, no final XOR. Used by TON for user-friendly address checksums
    and for deriving get-method identifiers. *)

val crc16_xmodem_be : string -> string
(** {!crc16_xmodem} as 2 bytes, most significant first — the order TON
    appends it in. *)

val crc32 : string -> int
(** CRC-32/ISO-HDLC, the ubiquitous "IEEE" CRC-32: reflected polynomial
    [0xedb88320], initial value and final XOR [0xffffffff]. Used by TL to
    derive constructor identifiers from schema lines. *)

val crc32_le : string -> string
(** {!crc32} as 4 bytes, least significant first. *)

val crc32c : string -> int
(** CRC-32C (Castagnoli): reflected polynomial [0x82f63b78], initial value and
    final XOR [0xffffffff]. Used by TON as the Bag-of-Cells checksum. *)

val crc32c_le : string -> string
(** {!crc32c} as 4 bytes, least significant first — the order a Bag of Cells
    stores it in. *)
