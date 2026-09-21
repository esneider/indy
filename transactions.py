#!/usr/bin/env python3
from typing import List, Tuple

import coincurve
from bip32 import BIP32

import scanner
import scripts

VERSION = 2
SEGWIT_MARKER = 0
SEGWIT_FLAG = 1
SEQUENCE = 0xffff_ffff
LOCKTIME = 0x0000_0000
SIGHASH_ALL = 0x01

NON_SEGWIT_DUST = 546


class Transaction:
    """
    Sweep transaction.
    """

    def __init__(self, master_key: BIP32, utxos: List[scanner.Utxo], address: str, amount_in_sat: int):
        """
        Craft and sign a transaction that spends all the UTXOs and sends the requested funds to a specific address.
        """
        output_script = scripts.build_output_script_from_address(address)
        if output_script is None:
            raise ValueError('The address is invalid or the format isn\'t recognized.')

        if amount_in_sat < NON_SEGWIT_DUST:
            raise ValueError('Not enough funds to create a sweep transaction.')

        self.outputs = [(amount_in_sat, output_script)]
        self.inputs = []

        if not utxos:
            raise ValueError('No inputs')
        if len({(u.txid,u.output_index) for u in utxos}) != len(utxos):
            raise ValueError('Duplicate outpoints')
        self.prevouts = []
        for u in utxos:
            pub = master_key.get_pubkey_from_path(u.path.to_list())
            self.prevouts.append(u.script_type.build_output_script(pub))
        for index, utxo in enumerate(utxos):
            pubkey = master_key.get_pubkey_from_path(utxo.path.to_list())
            privkey = master_key.get_privkey_from_path(utxo.path.to_list())
            if utxo.script_type == scripts.ScriptType.TAPROOT:
                digest = _taproot_sighash(utxos, self.prevouts, self.outputs, index)
                # BIP86: coincurve's tweak_add handles the internal-key parity.
                internal = coincurve.PrivateKey(privkey)
                secret = int.from_bytes(privkey, 'big')
                if internal.public_key.format(compressed=True)[0] == 3:
                    secret = scripts.SECP256K1_ORDER - secret
                tweak = int.from_bytes(scripts.tagged_hash('TapTweak', pubkey[1:]), 'big')
                if tweak >= scripts.SECP256K1_ORDER:
                    raise ValueError('Invalid tap tweak')
                tweaked = (secret + tweak) % scripts.SECP256K1_ORDER
                if not tweaked:
                    raise ValueError('Invalid tweaked secret')
                key = coincurve.PrivateKey(tweaked.to_bytes(32, 'big'))
                if key.public_key.format(compressed=True)[1:] != self.prevouts[index][2:]:
                    raise ValueError('Taproot output key mismatch')
                signature = key.sign_schnorr(digest, aux_randomness=b'\x00'*32)
                self.inputs.append((utxo, b'', [signature]))
                continue
            scriptcode = scripts.ScriptType.LEGACY.build_output_script(pubkey)
            unsigned = [(u, scriptcode if j == index else b'', []) for j,u in enumerate(utxos)]
            if utxo.script_type == scripts.ScriptType.LEGACY:
                preimage = _serialize_tx(unsigned, self.outputs, include_witness=False)
            else:
                preimage = _serialize_tx_for_segwit_signing(index, unsigned, self.outputs)
            digest = scripts.sha256(scripts.sha256(bytes(preimage) + SIGHASH_ALL.to_bytes(4,'little')))
            signature = coincurve.PrivateKey(privkey).sign(digest, hasher=None) + bytes([SIGHASH_ALL])
            self.inputs.append((utxo, utxo.script_type.build_input_script(pubkey, signature),
                                utxo.script_type.build_witness(pubkey, signature)))

    def virtual_size(self) -> int:
        """
        Compute the size of the transaction in virtual bytes.
        """
        witness_tx = _serialize_tx(self.inputs, self.outputs)
        non_witness_tx = _serialize_tx(self.inputs, self.outputs, include_witness=False)

        return (3 * len(non_witness_tx) + len(witness_tx) + 3) // 4

    def to_bytes(self) -> bytes:
        """
        Serialize the transaction according to BIP144 for witness transactions, and according to the old serialization
        format for non-witness transactions.
        """
        return _serialize_tx(self.inputs, self.outputs)


def _serialize_tx(
        inputs: List[Tuple[scanner.Utxo, bytes, List[bytes]]],
        outputs: List[Tuple[int, bytes]],
        include_witness: bool = True
) -> bytearray:
    """
    Serialize a transaction in wire format.
    """
    segwit = include_witness and any(len(witness) > 0 for _, _, witness in inputs)

    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, 'little'))

    if segwit:
        tx.append(SEGWIT_MARKER)
        tx.append(SEGWIT_FLAG)

    tx.extend(_varint(len(inputs)))

    for utxo, script, _ in inputs:
        tx.extend(_reversed(bytes.fromhex(utxo.txid)))
        tx.extend(utxo.output_index.to_bytes(4, 'little'))
        tx.extend(_varint(len(script)))
        tx.extend(script)
        tx.extend(SEQUENCE.to_bytes(4, 'little'))

    tx.extend(_varint(len(outputs)))

    for amount, script in outputs:
        tx.extend(amount.to_bytes(8, 'little'))
        tx.extend(_varint(len(script)))
        tx.extend(script)

    if segwit:
        for _, _, witness in inputs:
            tx.extend(_varint(len(witness)))
            for item in witness:
                tx.extend(_varint(len(item)))
                tx.extend(item)

    tx.extend(LOCKTIME.to_bytes(4, 'little'))
    return tx


def _serialize_tx_for_segwit_signing(
        input_index: int,
        inputs: List[Tuple[scanner.Utxo, bytes, List[bytes]]],
        outputs: List[Tuple[int, bytes]]
) -> bytearray:
    """
    Serialize a transaction in order to produce the BIP143 digest needed to sign segwit inputs.
    """
    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, 'little'))

    outpoints = bytearray()
    sequences = bytearray()

    for utxo, _, _ in inputs:
        outpoints.extend(_reversed(bytes.fromhex(utxo.txid)))
        outpoints.extend(utxo.output_index.to_bytes(4, 'little'))
        sequences.extend(SEQUENCE.to_bytes(4, 'little'))

    tx.extend(scripts.sha256(scripts.sha256(bytes(outpoints))))
    tx.extend(scripts.sha256(scripts.sha256(bytes(sequences))))

    utxo, script, _ = inputs[input_index]

    tx.extend(_reversed(bytes.fromhex(utxo.txid)))
    tx.extend(utxo.output_index.to_bytes(4, 'little'))
    tx.extend(_varint(len(script)))
    tx.extend(script)
    tx.extend(utxo.amount_in_sat.to_bytes(8, 'little'))
    tx.extend(SEQUENCE.to_bytes(4, 'little'))

    outs = bytearray()
    for amount, script in outputs:
        outs.extend(amount.to_bytes(8, 'little'))
        outs.extend(_varint(len(script)))
        outs.extend(script)

    tx.extend(scripts.sha256(scripts.sha256(bytes(outs))))
    tx.extend(LOCKTIME.to_bytes(4, 'little'))
    return tx


def _varint(number: int) -> bytes:
    """
    Create a script that pushes an integer to the script stack.
    """
    if number <= 0xfc:
        return bytes([number])

    if number <= 0xffff:
        return bytes([0xfd, *number.to_bytes(2, 'little')])

    if number <= 0xffff_ffff:
        return bytes([0xfe, *number.to_bytes(4, 'little')])

    if number <= 0xffff_ffff_ffff_ffff:
        return bytes([0xff, *number.to_bytes(8, 'little')])

    raise ValueError()


def _reversed(array: bytes) -> bytes:
    array = bytearray(array)
    array.reverse()
    return bytes(array)


def _taproot_sighash(utxos, prevouts, outputs, index):
    # BIP341 key-path, SIGHASH_DEFAULT, no annex, no ANYONECANPAY.
    def h(data): return scripts.sha256(bytes(data))
    outpoints = b''.join(_reversed(bytes.fromhex(u.txid)) + u.output_index.to_bytes(4,'little') for u in utxos)
    amounts = b''.join(u.amount_in_sat.to_bytes(8,'little') for u in utxos)
    spks = b''.join(_varint(len(s)) + s for s in prevouts)
    sequences = SEQUENCE.to_bytes(4,'little') * len(utxos)
    outs = b''.join(a.to_bytes(8,'little') + _varint(len(s)) + s for a,s in outputs)
    msg = (b'\x00' + b'\x00' + VERSION.to_bytes(4,'little') + LOCKTIME.to_bytes(4,'little')
           + h(outpoints) + h(amounts) + h(spks) + h(sequences) + h(outs)
           + b'\x00' + index.to_bytes(4,'little'))
    return scripts.tagged_hash('TapSighash', msg)
