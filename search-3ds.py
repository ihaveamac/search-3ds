#!/usr/bin/env python3

import argparse
import struct
import sys
from collections import OrderedDict
from glob import glob
from os.path import join as pjoin  # this feels dirty

encryption_supported = False
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    encryption_supported = True
except ImportError:
    print('Crypto module not found, please install pycryptodomex for encryption support.')

parser = argparse.ArgumentParser(description='Searches contents in files used on the Nintendo 3DS system.')
parser.add_argument('--path', metavar='DIR', help='path to search, defaults to current directory', default='.')
# parser.add_argument('--no-format', metavar='PATH', help='don\'t format results like a table (NYI)', default='.')

terms = parser.add_argument_group('terms')
terms.add_argument('--name', '-n', metavar='NAME', help='title name (in smdh, displays on HOME Menu)')
terms.add_argument('--strict-name', '-N', metavar='NAME', help='case-sensitive title name (in smdh, displays on HOME Menu)')
terms.add_argument('--title-id', '-i', metavar='TID', help='title id')
terms.add_argument('--type', '-t', metavar='NAME', help='file types to search, separated by commas')

a = parser.parse_args()

# if you know of a better way to check if at least one of the terms was used,
#   let me know please
if not (a.name or a.strict_name or a.title_id or a.type):
    parser.print_usage()
    sys.exit(1)

big_list_of_files = []


def addtolist(*ext):
    for e in ext:
        # to avoid duplicates, which are possible when looking for *.*
        for f in glob(pjoin(a.path, '**/*.' + e), recursive=True):
            if f not in big_list_of_files:
                big_list_of_files.append(f)


if a.type:
    types = a.type.lower().split(',')

    # .bin is a common extension that may contain different formats
    addtolist('bin')

    # assuming file extensions for file types. saves time searching files that
    #   likely don't contain the file type (cci wouldn't be a cia, etc)
    if 'cia' in types:
        addtolist('cia')
    if 'cci' in types or '3ds' in types:
        addtolist('cci', '3ds')
    if 'ncch' in types:
        addtolist('ncch', 'cxi', 'cfa', 'app', '*.*')
        # last option is to follow the format <name>.<index>.<id> that ctrtool
        #   saves cia contents as
    if 'tik' in types or 'ticket' in types:
        addtolist('tik')
    if 'tmd' in types:
        addtolist('tmd')
    # if 'exefs' in types:
    #     # exefs is also commonly with a .bin filename; some tools use .exefs
    #     #   like GodMode9
    #     addtolist('exefs')
else:
    # this doesn't feel right
    types = ['cia', 'cci', '3ds', 'ncch', 'app', 'tik', 'tmd']  # , 'exefs']
    # last ones are not separate types, just filename formats/extensions
    addtolist(*types, 'bin', 'app', '*.*')


# based on http://stackoverflow.com/questions/1766535/bit-hack-round-off-to-multiple-of-8/1766566#1766566
def roundup(x):
    return ((x + 63) >> 6) << 6


# types: 'tid', ...
def check_ticket(tik, content, cktype):
    if cktype == 'tid':
        return tik[0x1DC:0x1E4] == bytes.fromhex(content)


# types: 'tid', ...
# checks starting at 0x100 (ignoring signature)
def check_ncch(ncch, content, cktype):
    if cktype == 'tid':
        return ncch[0x8:0x10][::-1] == bytes.fromhex(content)


# types: 'tid', ...
# checks starting at 0x100 (ignoring signature)
def check_ncsd(ncsd, content, cktype):
    if cktype == 'tid':
        return ncsd[0x8:0x10][::-1] == bytes.fromhex(content)


search_results = OrderedDict()
longest_name_len = 8  # for use when displaying a table

for filename in big_list_of_files:
    with open(filename, 'rb') as f:
        matches = False
        result = {}

        # determine the real file type

        # cia header; archive header size, type, version, cert chain size, and
        #   ticket size never change
        cia_header = struct.pack('<IHHII', 0x2020, 0, 0, 0xA00, 0x350)
        if f.read(0x10) == cia_header:
            matches = 'cia' in types
            if not matches:
                break
            result['type'] = 'CIA '

            # since the sizes of everything before the tmd are fixed, we just
            #   need the tmd size to reach the content.
            tmd_size = int.from_bytes(f.read(4), 'little')
            content_offset = 0x2DC0 + roundup(tmd_size)

            if a.title_id:
                # read tid from ticket
                f.seek(0x2A40)
                matches = check_ticket(f.read(0x350), a.title_id, 'tid')
                if matches:
                    result['tid'] = a.title_id.lower()
                else:
                    continue
        else:
            f.seek(0x100)
            magic = f.read(4)
            if magic == b'NCCH':
                matches = 'ncch' in types
                if not matches:
                    break
                result['type'] = 'NCCH'

                if a.title_id:
                    # read tid from ncch header
                    f.seek(0x100)
                    matches = check_ncch(f.read(0x100), a.title_id, 'tid')
                    if matches:
                        result['tid'] = a.title_id.lower()
                    else:
                        continue
            elif magic == b'NCSD':
                matches = 'cci' in types
                if not matches:
                    break
                # special check to make sure it's not a nand backup
                f.seek(0x10C)
                if f.read(4) != b'\0\0\4\0':
                    continue
                result['type'] = 'CCI '

                if a.title_id:
                    # read tid from ncsd header
                    f.seek(0x100)
                    matches = check_ncch(f.read(0x100), a.title_id, 'tid')
                    if matches:
                        result['tid'] = a.title_id.lower()
                    else:
                        continue

        # if still matches (mostly a failsafe), add it to the search results
        if matches:
            search_results[filename] = result
            longest_name_len = max(len(filename), longest_name_len)

if search_results:
    header = ['Filename' + ' ' * (longest_name_len - 8), 'Type']
    if a.title_id:
        header.append('Title ID        ')
    header_print = ' | '.join(header)
    print(header_print)

    for filename, result in search_results.items():
        line = [filename + ' ' * (longest_name_len - len(filename)), result['type']]
        if 'tid' in result:
            line.append(result['tid'])
        print(' | '.join(line))
else:
    print('No files matched the given search terms.')
