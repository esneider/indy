![Indy: the ultimate recovery tool](readme/header.png)

## About

Recovering funds from a wallet using just the mnemonic phrase has historically been a difficult problem. The main reason being that different wallets use different derivation paths and script types. Sadly, the mnemonic format doesn't document this and other important metadata needed during the recovery process.

Indy intends to cover the gap left by the standard by making the recovery of funds from a mnemonic trivial. Just input your mnemonic and let the tool guess the derivation path used by the wallet.

You can use Indy to sweep all the funds to a destination address of your choice.

## Features

* Supports sweeping funds from mnemonics, xprivs, and xpubs (for xpubs it will just find the UTXOs)
* Supports mnemonics in English, Chinese, Spanish, French, Italian, Japanese and Korean
* Supports all the derivation paths and address types from the wallets listed in [walletsrecovery.org](https://walletsrecovery.org/)
* Supports customizing the address gap limit and the account gap limit
* Supports using a custom electrum server

## Demo

![](readme/demo.gif)

## How it works

Indy uses electrum servers to try [every possible combination](https://github.com/esneider/indy/blob/master/descriptors.py#L10) of known derivation paths and script types. Once the relevant path and script type combinations are detected, the tool will proceed to find all the UTXOs for those combinations. After all funds are found, if you desire so, Indy can create a transaction that will sweep them to an address of your choosing.

Some wallets use a custom address gap limit (or none at all), or really high account numbers, so you can choose to override these parameters.

Finally, notice that this tool is only useful for single key wallets. If you are using a multisig or lightning wallet, then you cannot recover the funds with just the mnemonic.

## Installation
```
git clone https://github.com/esneider/indy && cd indy
pip3 install -r requirements.txt
python3 indy.py --help
```

## Usage

```
usage: indy.py [-h] [--passphrase <pass>] [--address <address>] [--broadcast]
               [--fee-rate <rate>] [--address-gap <num>] [--account-gap <num>]
               [--host <host>] [--port <port>] [--protocol {t,s}] [--no-batching]
               key

Find and sweep all the funds from a mnemonic or bitcoin key, regardless of the
derivation path or address format used.

positional arguments:
  key                  master key to sweep, formats: mnemonic, xpriv or xpub

optional arguments:
  -h, --help           show this help message and exit
  --passphrase <pass>  optional secret phrase necessary to decode the mnemonic

sweep transaction:
  --address <address>  craft a transaction sending all funds to this address
  --broadcast          if present broadcast the transaction to the network
  --fee-rate <rate>    fee rate to use in sat/vbyte (default: next block fee)

scanning parameters:
  --address-gap <num>  max empty addresses gap to explore (default: 20)
  --account-gap <num>  max empty account levels gap to explore (default: 0)

electrum server:
  --host <host>        hostname of the electrum server to use
  --port <port>        port number of the electrum server to use
  --protocol {t,s}     electrum connection protocol: t=TCP, s=SSL (default: s)
  --no-batching        disable request batching
```

## Credits

This tool was created after reading [this twitter thread](https://twitter.com/aantonop/status/1259478489427775491) by [@aantonop](https://twitter.com/aantonop). Many thanks for the idea and the relentless contributions to the Bitcoin community!

Also, Indy stands on the tremendous effort done by [@NVK](https://twitter.com/NVK) and [@J9Roem](https://twitter.com/J9Roem) documenting the derivation paths for many wallets at [walletsrecovery.org](https://walletsrecovery.org/). It belongs in a museum!
