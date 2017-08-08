#!/usr/bin/env python3

import argparse
import os
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
# parser.add_argument('--no-format', help='don\'t format results like a table (NYI)', default='.')

terms = parser.add_argument_group('terms')
terms.add_argument('--type', '-t', metavar='NAME', help='file types to search, separated by commas')
terms.add_argument('--name', '-n', metavar='NAME', help='title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--strict-name', '-N', metavar='NAME', help='case-sensitive title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--title-id', '-i', metavar='TID', help='title id (e.g. 0004000000046500)')
terms.add_argument('--product-code', '-p', metavar='CODE', help='product code (e.g. CTR-P-AQNE) - entire product code not required')

a = parser.parse_args()

# if you know of a better way to check if at least one of the terms was used,
#   let me know please
if not (a.type or a.name or a.strict_name or a.title_id or a.product_code):
    parser.print_usage()
    sys.exit(1)

keys_set = False
# 0: retail, 1: dev
orig_ncch_key_x = []
common_key_x = []
if encryption_supported:
    def set_keys(boot9_file):
        global keys_set, orig_ncch_key_x, common_key_x
        if not keys_set and os.path.isfile(boot9_file):
            keys_offset = 0
            if os.path.getsize(boot9_file) == 0x10000:
                keys_offset += 0x8000
            for i in range(2):
                with open(boot9_file, 'rb') as f:
                    f.seek(0x59D0 + (i * 0x400) + keys_offset)
                    orig_ncch_key_x.append(f.read(0x10))
                    f.seek(0x50, 1)
                    common_key_x.append(f.read(0x10))
            keys_set = True

    set_keys(os.path.expanduser('~') + '/.3ds/boot9.bin')
    set_keys(os.path.expanduser('~') + '/.3ds/boot9_prot.bin')

big_list_of_files = []


def addtolist(*ext):
    for e in ext:
        # to avoid duplicates, which are possible when looking for *.*
        for f in glob(pjoin(a.path, '**/*' + e), recursive=True):
            if f not in big_list_of_files:
                big_list_of_files.append(f)


if a.type and a.type != 'all':
    types = a.type.lower().split(',')

    # .bin is a common extension that may contain different formats
    addtolist('.bin')

    # assuming file extensions for file types. saves time searching files that
    #   likely don't contain the file type (cci wouldn't be a cia, etc)
    if 'cia' in types:
        addtolist('.cia')
    if 'cci' in types or '3ds' in types:
        addtolist('.cci', '3ds')
    if 'ncch' in types:
        addtolist('.ncch', '.cxi', '.cfa', '.app', '*.*.*')
        # last option is to follow the format <name>.<index>.<id> that ctrtool
        #   saves cia contents as
    if 'tik' in types or 'ticket' in types:
        addtolist('.tik')
    if 'tmd' in types:
        addtolist('.tmd')
    # if 'exefs' in types:
    #     # exefs is also commonly with a .bin filename; some tools use .exefs
    #     #   like GodMode9
    #     addtolist('.exefs')
else:
    # this doesn't feel right
    types = 'all'
    # last ones are not separate types, just filename formats/extensions
    addtolist('.cia', '.cci', '.3ds', '.ncch', '.cxi', '.cfa', '.tik', '.tmd', '.exefs', '.bin', '.app', '*.*.*')


def check_type(ftype):
    return types == 'all' or ftype in types


# based on http://stackoverflow.com/questions/1766535/bit-hack-round-off-to-multiple-of-8/1766566#1766566
def roundup(x):
    return ((x + 63) >> 6) << 6


# types: 'tid', ...
def check_ticket(tik, content, cktype):
    if cktype == 'tid':
        tid = tik[0x1DC:0x1E4]
        if bytes.fromhex(content) == tid:
            return tid
        return False
    return False


# types: 'tid', ...
# checks starting at 0x100 (ignoring signature)
def check_ncch(ncch, content, cktype):
    if cktype == 'tid':
        tid = ncch[0x8:0x10][::-1]
        if bytes.fromhex(content) == tid:
            return tid.hex()
        return False
    elif cktype == 'pcode':
        pcode = ncch[0x50:0x60].strip().decode('utf-8')
        if content.lower() in pcode.lower():
            return pcode
        return False
    return False


# types: 'tid', ...
# checks starting at 0x100 (ignoring signature)
def check_ncsd(ncsd, content, cktype):
    if cktype == 'tid':
        tid = ncsd[0x8:0x10][::-1]
        if bytes.fromhex(content) == tid:
            return tid.hex()
        return False


search_results = OrderedDict()

for filename in big_list_of_files:
    with open(filename, 'rb') as f:
        matches = False
        result = {}
        dev = 0  # to use proper keys

        # determine the real file type

        # cia header; archive header size, type, version, cert chain size, and
        #   ticket size never change
        cia_header = struct.pack('<IHHII', 0x2020, 0, 0, 0xA00, 0x350)
        if f.read(0x10) == cia_header:
            matches = check_type('cia')
            if not matches:
                break
            result['type'] = 'CIA'

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

            # if encryption_supported:
            #     f.seek()
            #     cipher_content0 = AES.new()

            if a.product_code:
                # TODO: this (product-code in cia)
                continue

        else:
            # check for ncch/ncsd header
            f.seek(0x100)
            file_header = f.read(0x100)
            if file_header[0:4] == b'NCCH':
                matches = check_type('ncch')
                if not matches:
                    break
                result['type'] = 'NCCH'

                if a.title_id:
                    res = check_ncch(file_header, a.title_id, 'tid')
                    if res:
                        result['tid'] = res
                        matches = True
                    else:
                        continue

                if a.product_code:
                    res = check_ncch(file_header, a.product_code, 'pcode')
                    if res:
                        result['pcode'] = res
                        matches = True
                    else:
                        continue

            elif file_header[0:4] == b'NCSD':
                matches = check_type('cci')
                if not matches:
                    break
                # special check to make sure it's not a nand backup
                if file_header[0xC:0x10] != b'\0\0\4\0':
                    continue
                result['type'] = 'CCI'

                # the ncch offset is assumed to be 0x4000 since every cci ever
                #   has it start here. i'm also being lazy. maybe i'll
                #   properly implement offset reading later.
                f.seek(0x4100)
                ncch_header = f.read(0x100)

                if a.title_id:
                    # read tid from ncsd header
                    res = check_ncch(ncch_header, a.title_id, 'tid')
                    if res:
                        result['tid'] = res
                        matches = True
                    else:
                        continue

                if a.product_code:
                    res = check_ncch(ncch_header, a.product_code, 'pcode')
                    if res:
                        result['pcode'] = res
                        matches = True
                    else:
                        continue

        # if still matches (mostly a failsafe), add it to the search results
        if matches:
            search_results[filename] = result

column_lengths = []
lines = []


def add_to_table(line):
    global column_lengths, lines
    for idx, col in enumerate(line):
        column_lengths[idx] = max(len(col), column_lengths[idx])
    lines.append(line)


if search_results:
    header = ['Filename', 'Type']
    if a.title_id:
        header.append('Title ID')
    if a.product_code:
        header.append('Product Code')
    print(len(header))
    column_lengths = [0] * len(header)
    add_to_table(header)

    for filename, result in search_results.items():
        line = [filename, result['type']]
        if 'tid' in result:
            line.append(result['tid'])
        if 'pcode' in result:
            line.append(result['pcode'])
        add_to_table(line)

    for line in lines:
        print(' | '.join(col.ljust(column_lengths[idx]) for idx, col in enumerate(line)))
else:
    print('No files matched the given search terms.')
