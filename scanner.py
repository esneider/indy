#!/usr/bin/env python3
from typing import List, Tuple

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
            response = await _electrum_rpc(client, [('blockchain.scripthash.get_history', [hash])])

            if len(response[0]) > 0:

                path, type = script.path_with_account().path, script.type().name

                if (path, type) not in descriptors:
                    descriptors.add((path, type))
                    message = f'🕵   Found used addresses at path={path} address_type={type}'
                    print(f'\r{message}'.ljust(progress_bar.ncols))  # print the message replacing the current line

                response = await _electrum_rpc(client, [('blockchain.scripthash.listunspent', [hash])])

                for entry in response[0]:
                    txid, output_index, amount = entry['tx_hash'], entry['tx_pos'], entry['value']

                    utxo = Utxo(txid, output_index, amount, script.full_path(), script.type())
                    utxos.append(utxo)

                    message = f'💰  Found unspent output at ({txid}, {output_index}) with {amount} sats'
                    print(f'\r{message}'.ljust(progress_bar.ncols))  # print the message replacing the current line

                script.set_as_used()
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


async def _electrum_rpc(client: StratumClient, requests: List[Tuple[str, List[str]]]) -> List:
    """
    Perform an electrum RPC call, using batching if multiple requests are required.
    """
    if len(requests) == 0:
        return []

    if len(requests) == 1:
        method, params = requests[0]
        response = await client.RPC(method, *params)
        return [response]

    response = await client.batch_rpc(requests)
    return response
