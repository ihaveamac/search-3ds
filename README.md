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
* `--no-format` - don't format results like a table (NYI)

### Search terms
* `--type TYPE` / `-t` - file types to search, separated by commas
  * Valid types: `cia`, `cci`, `ncch`, `tik`, `tmd`
* `--name NAME` / `-n` - title name (in smdh, displays on HOME Menu) - entire name not required (NYI)
* `--strict-name NAME` / `-N` - case-sensitive title name (in smdh, displays on HOME Menu) - entire name not required (NYI)
* `--title-id TID` / `-i` - title id
* `--product-code CODE` / `-p` - product code (e.g. CTR-P-AQNE)

## License
`search-3ds.py` is under the MIT license.
