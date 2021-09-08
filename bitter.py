#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Created by kamoshiren, 2021
import argparse
import hashlib
import os
import time
from binascii import hexlify, unhexlify

import base58
import cryptotools.BTC
import ecdsa
import requests

from _version import __version__, __author__


def makePrivateKey():
    """
    Make a 32 byte (256 bit) Bitcoin-compatible private key.
    In Bitcoin, a private key is a 256-bit number, which can be represented one of several ways.
    Here is a private key in hexadecimal - 256 bits in hexadecimal is 32 bytes,
    or 64 characters in the range 0-9 or A-F
    E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262
    Also, nearly every 256-bit number is a valid ECDSA private key.
    """
    keys = []
    generated_private_key = os.urandom(32)
    private_key = hexlify(generated_private_key).decode('utf-8')
    keys.append(generated_private_key)
    keys.append(private_key)
    return keys


def makeAddressesFromPrivateKey(undecoded_private_key, private_key):
    """
    Convert private Bitcoin key to addresses.
    """

    def ripemd160(data):
        d = hashlib.new('ripemd160')
        d.update(data)
        return d

    secret_key = ecdsa.SigningKey.from_string(undecoded_private_key, curve=ecdsa.SECP256k1)
    vk = secret_key.get_verifying_key()
    address_uncompressed = '04' + hexlify(vk.to_string()).decode()
    hash160 = ripemd160(hashlib.sha256(unhexlify(address_uncompressed)).digest()).digest()
    address_uncompressed = b"\x00" + hash160
    checksum = hashlib.sha256(hashlib.sha256(address_uncompressed).digest()).digest()[:4]
    address_uncompressed = base58.b58encode(address_uncompressed + checksum).decode()

    private = cryptotools.PrivateKey.from_hex(private_key)
    public = private.to_public()
    address_compressed = public.to_address('P2PKH', compressed=True)

    return [address_uncompressed, address_compressed]


def makeWIFFromPrivateKey(private_key):
    """
    Convert Private Key to WIF (Wallet Import Format)
    """
    digest = hashlib.sha256(unhexlify('80' + private_key)).hexdigest()
    hash = hashlib.sha256(unhexlify(digest)).hexdigest()
    hash = unhexlify('80' + private_key + hash[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(hash[::-1]): value += 256 ** i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in hash:
        if c == 0:
            pad += 1
        else:
            break

    private = cryptotools.PrivateKey.from_hex(private_key)
    compressed_wif = private.wif(compressed=True)

    return [(chars[0] * pad + result), compressed_wif]


def makePublicKeyFromPrivateKey(private_key):
    """
    Get uncompressed Public key
    """
    private = cryptotools.PrivateKey.from_hex(private_key)
    public = private.to_public()
    return public.hex()


def generateAllKeys():
    """
    Create Private key, Public key, uncompressed and compressed WIF,
    uncompressed and compressed addresses.
    """
    undecoded_private_key, private_key = makePrivateKey()
    public_key = makePublicKeyFromPrivateKey(private_key)
    uncompressed_address, compressed_address = makeAddressesFromPrivateKey(undecoded_private_key, private_key)
    uncompressed_wif, compressed_wif = makeWIFFromPrivateKey(private_key)

    return {'private_key': private_key,
            'public_key': public_key,
            'uncompressed_address': uncompressed_address,
            'compressed_address': compressed_address,
            'uncompressed_wif': uncompressed_wif,
            'compressed_wif': compressed_wif,
            }


def checkBalance(keys):
    """
    Check balance of the Bitcoin wallet via blockchain.info
    """
    if args.verbosity:
        print(f'\nChecking balance of the wallet with private Key "{keys["private_key"]}".')

    url = f'https://blockchain.info/balance?cors=true&active={keys["compressed_address"]},{keys["uncompressed_address"]}'
    get_balance = requests.get(url)

    trying = 5
    while get_balance.status_code != 200:
        trying -= 1
        if trying == 0:
            print('Exiting.')
            quit()
        print("Can't connect to the server. Reconnecting...")

        t = 5
        while t:  # Timer
            mins, secs = divmod(5, 60)
            timer = '{:02d}:{:02d}'.format(mins, secs)
            print(timer, end="\r")
            time.sleep(1)
            t -= 1

        get_balance = requests.get(url)

    wallets = get_balance.json()
    for wallet in wallets:
        if wallets[wallet]['final_balance'] > 0:
            success_file = open('success_wallets.txt', 'a')
            for key in keys:
                success_file.write(f'{key}: {keys[key]}\n')

            success_file.write('-' * 100 + '\n\n')
            success_file.close()
            print('Success!!! Wallet data has been written to "success_file.txt". Please check it.\n')
            break
        else:
            print(f'{wallet}: [nothing]')
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbosity', action='store_true', help='increase output verbosity')
    parser.add_argument('--version', action='version', version='%(prog)s {version}. Author: {author}'
                        .format(version=__version__, author=__author__))
    args = parser.parse_args()

    while True:
        keys = generateAllKeys()
#        for key in keys:
#            print(f'{key}: {keys[key]}')
        checkBalance(keys)