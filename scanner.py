#!/usr/bin/env python3
from typing import List

from bip32 import BIP32
from connectrum.client import StratumClient
from tqdm import tqdm

import scripts
from descriptors import ScriptIterator, Path
from scripts import ScriptType


class Utxo:
    """
    Data needed to spend a currently unspent transaction output.
    """

    def __init__(self, txid: str, output_index: int, amount_in_sat: int, path: Path, script_type: ScriptType):
        self.txid = txid
        self.output_index = output_index
        self.amount_in_sat = amount_in_sat
        self.path = path
        self.script_type = script_type


async def scan_master_key(client: StratumClient, master_key: BIP32, max_gap: int, max_account: int) -> List[Utxo]:
    """
    Iterate through all the possible addresses of a master key, in order to find its UTXOs.
    """
    script_iter = ScriptIterator(master_key, max_gap, max_account)
    descriptors = set()
    utxos = []

    with tqdm(total=script_iter.total_scripts, desc='🏃‍♀️  Searching possible addresses') as progress_bar:
        while True:
            iter = script_iter.next_script()
            if iter is None:
                break

            progress_bar.update(1)

            script, path, address_type = iter
            if (path, address_type) in descriptors:
                continue

            # TODO: use an electrum client that supports batching
            # TODO: parallelize fetching

            hash = _electrum_script_hash(script)
            response = await client.RPC('blockchain.scripthash.get_history', hash)

            if len(response) > 0:
                message = f'🕵️‍♂️   Found used addresses at path={path.path} address_type={address_type.name}'
                print(f'\r{message}'.ljust(progress_bar.ncols + 2))  # print the message replacing the current line

                descriptors.add((path, address_type))
                utxos.extend(await _scan_descriptor(client, master_key, path, address_type, max_gap))

    return utxos


async def _scan_descriptor(
        client: StratumClient,
        master_key: BIP32,
        path: Path,
        script_type: ScriptType,
        max_gap: int
) -> List[Utxo]:
    """
    Iterate sequentially the address from an output descriptor, looking for UTXOs. We'll stop looking once we hit a
    big-enough gap of unused addresses.
    """
    utxos = []
    index = 0
    gap = 0

    while gap <= max_gap:
        child_path = path.with_index(index)
        child_pubkey = master_key.get_pubkey_from_path(child_path.to_list())
        child_script = script_type.build_output_script(child_pubkey)

        index += 1
        gap += 1

        hash = _electrum_script_hash(child_script)
        response = await client.RPC('blockchain.scripthash.get_history', hash)

        if len(response) > 0:
            gap = 0
            response = await client.RPC('blockchain.scripthash.listunspent', hash)
            for entry in response:
                utxo = Utxo(entry['tx_hash'], entry['tx_pos'], entry['value'], child_path, script_type)
                utxos.append(utxo)
                print(f'💰  Found unspent output at ({utxo.txid}, {utxo.output_index}) with {utxo.amount_in_sat} sats')

    if len(utxos) == 0:
        print('😔  This derivation path doesn\'t have any unspent outputs')

    return utxos


def _electrum_script_hash(script: bytes) -> str:
    """
    Compute the hex-encoded big-endian sha256 hash of a script.
    """
    bytes = bytearray(scripts.sha256(script))
    bytes.reverse()
    return bytes.hex()
