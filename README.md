# search-3ds
Searches contents in files used on the Nintendo 3DS system.

## Usage
```bash
python3 search-3ds.py [-h] [--path DIR] {search-terms}
```

### Search terms
* `--name NAME` / `-n` - title name (in smdh, displays on HOME Menu)
* `--strict-name NAME` / `-N` - case-sensitive title name (in smdh, displays on HOME Menu)
* `--title-id TID` / `-i` - title id
* `--type TYPE` / `-t` - file types to search, separated by commas
  * Valid types: `cia`, `cci`, `ncch`, `tik`, `tmd`, `exefs`

## License
`search-3ds.py` is under the MIT license.
