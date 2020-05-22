#!/usr/bin/env python3
import hashlib
from enum import Enum, auto
from typing import Optional, List

import base58
import bech32

OP_0 = 0x00
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xa9
OP_CHECKSIG = 0xac

P2PKH_ADDRESS_HEADER = 0x00
P2SH_ADDRESS_HEADER = 0x05
BECH32_HRP = 'bc'

sha256 = lambda bytes: hashlib.sha256(bytes).digest()
ripemd160 = lambda bytes: hashlib.new('ripemd160', bytes).digest()
hash160 = lambda bytes: ripemd160(sha256(bytes))


class ScriptType(Enum):
    """
    Single-key output script type.
    """
    LEGACY = auto()  # P2PKH
    COMPAT = auto()  # P2SH of P2WPKH
    SEGWIT = auto()  # P2WPKH

    def build_output_script(self, pubkey: bytes) -> bytes:
        """
        Compute the output script for a given public key.
        """
        if self is ScriptType.LEGACY:
            return _build_p2pkh_output_script(hash160(pubkey))

        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(hash160(pubkey))
            return _build_p2sh_output_script(hash160(script))

        if self is ScriptType.SEGWIT:
            return _build_segwit_output_script(hash160(pubkey))

        raise ValueError('Unrecognized address type')

    def build_input_script(self, pubkey: bytes, signature: bytes) -> bytes:
        """
        Compute the input script for a given public key and signature.
        """
        if self is ScriptType.LEGACY:
            return _build_p2pkh_input_script(pubkey, signature)

        if self is ScriptType.COMPAT:
            script = _build_segwit_output_script(hash160(pubkey))
            return _build_p2sh_input_script(script)

        if self is ScriptType.SEGWIT:
            return bytes()

        raise ValueError('Unrecognized address type')

    def build_witness(self, pubkey: bytes, signature: bytes) -> List[bytes]:
        """
        Compute the witness for a given public key and signature.
        """
        if self is ScriptType.LEGACY:
            return []

        if self in [ScriptType.COMPAT, ScriptType.SEGWIT]:
            return [signature, pubkey]

        raise ValueError('Unrecognized address type')


def build_output_script_from_address(address: str) -> Optional[bytes]:
    """
    Compute the output script for a given address.
    """
    # Try to decode a base58 address
    try:
        decoded = base58.b58decode_check(address)
        version = decoded[0]
        hash = decoded[1:]

        if version == P2PKH_ADDRESS_HEADER:
            return _build_p2pkh_output_script(hash)

        if version == P2SH_ADDRESS_HEADER:
            return _build_p2sh_output_script(hash)

    except ValueError:
        pass

    # Try to decode a bech32 address
    try:
        version, hash = bech32.decode(BECH32_HRP, address)

        if version == 0:
            return _build_segwit_output_script(hash)

    except ValueError:
        pass

    return None


def _build_p2pkh_output_script(pubkey_hash: bytes) -> bytes:
    script = bytearray()

    script.append(OP_DUP)
    script.append(OP_HASH160)
    script.append(len(pubkey_hash))
    script.extend(pubkey_hash)
    script.append(OP_EQUALVERIFY)
    script.append(OP_CHECKSIG)

    return bytes(script)


def _build_p2sh_output_script(script_hash: bytes) -> bytes:
    script = bytearray()

    script.append(OP_HASH160)
    script.append(len(script_hash))
    script.extend(script_hash)
    script.append(OP_EQUAL)

    return bytes(script)


def _build_segwit_output_script(hash: bytes) -> bytes:
    script = bytearray()

    script.append(OP_0)
    script.append(len(hash))
    script.extend(hash)

    return bytes(script)


def _build_p2pkh_input_script(pubkey: bytes, signature: bytes) -> bytes:
    script = bytearray()

    script.append(len(signature))
    script.extend(signature)
    script.append(len(pubkey))
    script.extend(pubkey)

    return bytes(script)


def _build_p2sh_input_script(*args: bytes) -> bytes:
    script = bytearray()

    for arg in args:
        script.append(len(arg))
        script.extend(arg)

    return bytes(script)
