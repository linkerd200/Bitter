# Bitter

Bitter is a convenient tool for checking Bitcoin wallets balance using blockchain.info API. It generates private key and public key pair along with uncompressed and compressed wallet addresses/WIF, then trying to get most recent data about wallets, if the balance greater than 0, writes data to "success_file.txt". Enjoy it!

## Installation

Insert following lines in Terminal.

```bash
$ git clone https://github.com/kamoshiren.git bitter

$ cd bitter && pip3 install -r requirements.txt

$ chmod +x ./bitter.py
```

## Usage

```bash
# standard launch
$ bitter.py

# verbose output
$ bitter.py -v

# check current version
$ bitter.py --version

# help
$ bitter.py --help
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)