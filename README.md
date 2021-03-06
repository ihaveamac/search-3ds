# search-3ds
Searches contents in files used on the Nintendo 3DS system.

pycryptodomex required for encryption.

## Usage
```bash
python3 search-3ds.py [-h] [--path DIR] {search-terms}
```

* `--path DIR` - path to search, defaults to current directory
* `--verbose` / `-v` - print more information, use multiple times for more verbosity
* `--search-all` - search every file, without basing on extension
* `--no-format` - don't format results like a table
* `--err` - dump traceback when an exception occurs

### Search terms
* `--type TYPE` / `-t` - file types to search, separated by commas
  * Valid types: `cia`, `cci`, `ncch`, `tik`, `tmd`
* `--name NAME` / `-n` - title name (in smdh, displays on HOME Menu) - entire name not required
* `--strict-name NAME` / `-N` - case-sensitive title name (in smdh, displays on HOME Menu) - entire name not required
* `--publisher NAME` / `-N` - publisher name (in smdh, displays on HOME Menu) - entire name not required
* `--title-id TID` / `-i` - title id (e.g. 0004000000046500)
* `--unique-id TID` / `-i` - unique id (e.g. 175e or 0x175e)
* `--product-code CODE` / `-p` - product code (e.g. CTR-P-AQNE)
* `--exh-name CODE` / `-p` - extended header (exheader) application title - entire name not required

## License
`search-3ds.py` is under the MIT license.
