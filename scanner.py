#!/usr/bin/env python3
from typing import List, Tuple

from bip32 import BIP32
from connectrum.client import StratumClient
from tqdm import tqdm

import scripts
from descriptors import ScriptIterator, Path
from scripts import ScriptType

MAX_BATCH_SIZE = 100


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


async def scan_master_key(
        client: StratumClient,
        master_key: BIP32,
        address_gap: int,
        account_gap: int,
        should_batch: bool
) -> List[Utxo]:
    """
    Iterate through all the possible addresses of a master key, in order to find its UTXOs.
    """
    batch_size = MAX_BATCH_SIZE if should_batch else 1
    script_iter = ScriptIterator(master_key, address_gap, account_gap)
    descriptors = set()
    utxos = []

    # TODO: parallelize fetching

    with tqdm(total=script_iter.total_scripts(), desc='🏃‍♀️  Searching possible addresses') as progress_bar:
        while True:

            # Compute the next batch of scripts
            scripts = []
            for index in range(batch_size):
                script = script_iter.next_script()
                if not script:
                    break
                scripts.append(script)

            if len(scripts) == 0:
                # We are done!
                break

            progress_bar.update(len(scripts))

            # Build the next batched request
            batch_request = []
            for script in scripts:
                hash = _electrum_script_hash(script.program)
                batch_request.append(('blockchain.scripthash.get_history', hash))

            responses = await _electrum_rpc(client, batch_request)

            # Using the responses, compute the next batch of *used* scripts
            used_scripts = []
            for script, response in zip(scripts, responses):
                if len(response) == 0:
                    continue

                path, type = script.path_with_account().path, script.type().name

                if (path, type) not in descriptors:
                    descriptors.add((path, type))
                    message = f'🕵   Found used addresses at path={path} address_type={type}'
                    print(f'\r{message}'.ljust(progress_bar.ncols))  # print the message replacing the current line

                script.set_as_used()
                used_scripts.append(script)

            # Build the next batched request
            batch_request = []
            for script in used_scripts:
                hash = _electrum_script_hash(script.program)
                batch_request.append(('blockchain.scripthash.listunspent', hash))

            responses = await _electrum_rpc(client, batch_request)

            for script, response in zip(used_scripts, responses):
                for entry in response:
                    txid, output_index, amount = entry['tx_hash'], entry['tx_pos'], entry['value']

                    utxo = Utxo(txid, output_index, amount, script.full_path(), script.type())
                    utxos.append(utxo)

                    message = f'💰  Found unspent output at ({txid}, {output_index}) with {amount} sats'
                    print(f'\r{message}'.ljust(progress_bar.ncols))  # print the message replacing the current line

            # Update the progress bar length, in case we now need to explore more scripts
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


async def _electrum_rpc(client: StratumClient, requests: List[Tuple[str, ...]]) -> List:
    """
    Perform an electrum RPC call, using batching if multiple requests are required.
    """
    if len(requests) == 0:
        return []

    if len(requests) == 1:
        request = requests[0]
        response = await client.RPC(*request)
        return [response]

    response = await client.batch_rpc(requests)
    return response
