#!/usr/bin/env python3
import argparse
import asyncio
import json
import random
from typing import Optional

import connectrum
from bip32 import BIP32
from connectrum.client import StratumClient
from connectrum.svr_info import ServerInfo
from mnemonic import Mnemonic

import scanner
import transactions


def main():
    parser = argparse.ArgumentParser(
        description='Find and sweep all the funds from a mnemonic or bitcoin key, regardless of the derivation path or '
                    'address format used.'
    )

    parser.add_argument('key', help='master key to sweep, formats: mnemonic, xpriv or xpub')

    sweep_tx = parser.add_argument_group('sweep transaction')

    sweep_tx.add_argument('--address', metavar='<address>',
                          help='craft a transaction sending all funds to this address')
    sweep_tx.add_argument('--broadcast', default=False, action='store_true',
                          help='if present broadcast the transaction to the network')
    sweep_tx.add_argument('--fee-rate', metavar='<rate>', type=int,
                          help='fee rate to use in sat/vbyte (default: next block fee)')

    scanning = parser.add_argument_group('scanning parameters')

    scanning.add_argument('--address-gap', metavar='<num>', default=20, type=int,
                          help='max empty addresses gap to explore (default: 20)')
    scanning.add_argument('--account-gap', metavar='<num>', default=0, type=int,
                          help='max empty account levels gap to explore (default: 0)')

    electrum = parser.add_argument_group('electrum server')

    electrum.add_argument('--host', metavar='<host>',
                          help='hostname of the electrum server to use')
    electrum.add_argument('--port', metavar='<port>', type=int,
                          help='port number of the electrum server to use')
    electrum.add_argument('--protocol', choices='ts', default='s',
                          help='electrum connection protocol: t=TCP, s=SSL (default: s)')
    electrum.add_argument('--no-batching', default=False, action='store_true',
                          help='disable request batching')

    args = parser.parse_args()

    master_key = parse_key(args.key)

    if args.host is not None:
        port = (args.protocol + str(args.port)) if args.port else args.protocol
        server = ServerInfo(args.host, hostname=args.host, ports=port)
    else:
        with open('servers.json', 'r') as f:
            servers = json.load(f)
        server = random.choice(servers)
        server = ServerInfo(server['host'], hostname=server['host'], ports=server['port'])

    loop = asyncio.get_event_loop()
    loop.run_until_complete(find_utxos(
        server,
        master_key,
        args.address_gap,
        args.account_gap,
        args.address,
        args.fee_rate,
        args.broadcast,
        not args.no_batching
    ))
    loop.close()


def parse_key(key: str) -> BIP32:
    """
    Try to parse an extended key, whether it is in xpub, xpriv or mnemonic format.
    """
    try:
        private_key = BIP32.from_xpriv(key)
        print('🔑  Read master private key successfully')
        return private_key
    except Exception:
        pass

    try:
        public_key = BIP32.from_xpub(key)
        print('🔑  Read master public key successfully')
        return public_key
    except Exception:
        pass

    try:
        language = Mnemonic.detect_language(key)
        seed = Mnemonic(language).to_seed(key)
        private_key = BIP32.from_seed(seed)
        print('🔑  Read mnemonic successfully')
        return private_key
    except Exception:
        pass

    raise ValueError('The key is invalid or the format isn\'t recognized. Make sure it\'s a mnemonic, xpriv or xpub.')


async def find_utxos(
        server: ServerInfo,
        master_key: BIP32,
        address_gap: int,
        account_gap: int,
        address: Optional[str],
        fee_rate: Optional[int],
        should_broadcast: bool,
        should_batch: bool
):
    """
    Connect to an electrum server and find all the UTXOs spendable by a master key.
    """
    print('⏳  Connecting to electrum server, this might take a while')

    client = StratumClient()
    await client.connect(server, disable_cert_verify=True)

    print('🌍  Connected to electrum server successfully')

    utxos = await scanner.scan_master_key(client, master_key, address_gap, account_gap, should_batch)

    if len(utxos) == 0:
        print('😔  Didn\'t find any unspent outputs')
        client.close()
        return

    balance = sum([utxo.amount_in_sat for utxo in utxos])
    print(f'💸  Total spendable balance found: {balance} sats')

    if master_key.master_privkey is None:
        print('✍️  Re-run with a private key to create a sweep transaction')
        client.close()
        return

    if address is None:
        print('ℹ️   Re-run with `--address` to create a sweep transaction')
        client.close()
        return

    if fee_rate is None:
        fee_rate_in_btc_per_kb = await client.RPC('blockchain.estimatefee', 1)

        if fee_rate_in_btc_per_kb == -1:
            print('🔁  Couldn\'t fetch fee rates, try again with manual fee rates using `--fee-rate`')
            client.close()
            return

        fee_rate = int(fee_rate_in_btc_per_kb * 10 ** 8 / 1024)

        print(f'🚌  Fetched next-block fee rate of {fee_rate} sat/vbyte')

    tx_without_fee = transactions.Transaction(master_key, utxos, address, balance)
    fee = tx_without_fee.virtual_size() * fee_rate
    tx = transactions.Transaction(master_key, utxos, address, balance - fee)
    bin_tx = tx.to_bytes()

    print('👇  This transaction sweeps all funds to the address provided')
    print()
    print(bin_tx.hex())
    print()

    if not should_broadcast:
        print('📋  Copy this transaction and broadcast it manually to the network, or re-run with `--broadcast`')
        client.close()
        return

    try:
        print('📣  Broadcasting transaction to the network')
        txid = await client.RPC('blockchain.transaction.broadcast', bin_tx.hex())
        print(f'✅  Transaction {txid} successfully broadcasted')
    except connectrum.exc.ElectrumErrorResponse as err:
        print(f'⛔️  Transaction broadcasting failed: {err}')

    client.close()


if __name__ == '__main__':
    main()
