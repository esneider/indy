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


async def scan_master_key(client: StratumClient, master_key: BIP32, address_gap: int, account_gap: int) -> List[Utxo]:
    """
    Iterate through all the possible addresses of a master key, in order to find its UTXOs.
    """
    script_iter = ScriptIterator(master_key, address_gap, account_gap)
    descriptors = set()
    utxos = []

    with tqdm(total=script_iter.total_scripts(), desc='🏃‍♀️  Searching possible addresses') as progress_bar:
        while True:
            script = script_iter.next_script()
            if not script:
                break

            progress_bar.update(1)

            # TODO: use an electrum client that supports batching
            # TODO: parallelize fetching

            hash = _electrum_script_hash(script.program)
            response = await client.RPC('blockchain.scripthash.get_history', hash)

            if len(response) > 0:

                if (script.path, script.type) not in descriptors:
                    descriptors.add((script.path, script.type))
                    message = f'🕵️‍♂️   Found used addresses at path={script.path.path} address_type={script.type.name}'
                    print(f'\r{message}'.ljust(progress_bar.ncols + 2))  # print the message replacing the current line

                response = await client.RPC('blockchain.scripthash.listunspent', hash)
                for entry in response:
                    txid, output_index, amount = entry['tx_hash'], entry['tx_pos'], entry['value']

                    utxo = Utxo(txid, output_index, amount, script.path.with_index(script.index), script.type)
                    utxos.append(utxo)

                    message = f'💰  Found unspent output at ({txid}, {output_index}) with {amount} sats'
                    print(f'\r{message}'.ljust(progress_bar.ncols + 2))  # print the message replacing the current line

                script_iter.found_used_script()
                progress_bar.total = script_iter.total_scripts()
                progress_bar.refresh()

    return utxos


def _electrum_script_hash(script: bytes) -> str:
    """
    Compute the hex-encoded big-endian sha256 hash of a script.
    """
    bytes = bytearray(scripts.sha256(script))
    bytes.reverse()
    return bytes.hex()
