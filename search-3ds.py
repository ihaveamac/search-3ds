#!/usr/bin/env python3

import argparse
import os
import struct
import sys
from collections import OrderedDict
from glob import iglob
from os.path import join as pjoin  # this feels dirty

encryption_supported = False
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    encryption_supported = True
except ImportError:
    print('Cryptodome module not found, please install pycryptodomex for encryption support (`pip install pycryptodomex`).')

parser = argparse.ArgumentParser(description='Searches contents in files used on the Nintendo 3DS system.')
parser.add_argument('--path', metavar='DIR', help='path to search, defaults to current directory', default='')
parser.add_argument('--verbose', '-v', help='print more information', action='count', default=0)
parser.add_argument('--search-all', help='search every file, without basing on extension', action='store_true')
# parser.add_argument('--no-format', help='don\'t format results like a table (NYI)', default='.')

terms = parser.add_argument_group('terms')
terms.add_argument('--type', '-t', metavar='NAME', help='file types to search, separated by commas')
terms.add_argument('--name', '-n', metavar='NAME', help='title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--strict-name', '-N', metavar='NAME', help='case-sensitive title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--title-id', '-i', metavar='TID', help='title id (e.g. 0004000000046500)')
terms.add_argument('--product-code', '-p', metavar='CODE', help='product code (e.g. CTR-P-AQNE) - entire product code not required')

a = parser.parse_args()


def print_v(msg, v=1):
    if a.verbose >= v:
        print('DEBUG L{}: {}'.format(v, msg))


# if you know of a better way to check if at least one of the terms was used,
#   let me know please
if not (a.type or a.name or a.strict_name or a.title_id or a.product_code):
    parser.print_usage()
    sys.exit(1)

# 0: retail, 1: dev
# Original NCCH (0x2C) KeyX
orig_ncch_key_x = ('B98E95CECA3E4D171F76A94DE934C053', '510207515507CBB18E243DCB85E23A1D')
# Common Key (0x3D) Normal Key
common_keys = (
    ('64C5FD55DD3AD988325BAAEC5243DB98', '55A3F872BDC80C555A654381139E153B'),
    ('4AAA3D0E27D4D728D0B1B433F0F9CBC8', '4434ED14820CA1EBAB82C16E7BEF0C25'),
    ('FBB0EF8CDBB0D8E453CD99344371697F', '85215E96CB95A9ECA4B4DE601CB562C7'),
    ('25959B7AD0409F72684198BA2ECD7DC6', '0C767230F0998F1C46828202FAACBE4C'),
    ('7ADA22CAFFC476CC8297A0C7CEEEEEBE', 'E02D27441DB9558BAD087FD746DF1057'),
    ('A5051CA1B37DCF3AFBCF8CC1EDD9CE02', '0412959405AA41CC7118B61E75E283AB')
)

big_list_of_files = []


def addtolist(*ext):
    for e in ext:
        # to avoid duplicates, which are possible when looking for *.*
        for f in iglob(pjoin(a.path, '**/*' + e), recursive=True):
            if os.path.isfile(f) and f not in big_list_of_files:
                print_v('Adding {} to list for searching'.format(f), v=2)
                big_list_of_files.append(f)


print_v('Listing files to scan', v=1)

if a.type and a.type != 'all':
    types = a.type.lower().split(',')

    if a.search_all:
        addtolist('')
    else:
        # .bin is a common extension that may contain different formats
        addtolist('.bin')

        # assuming file extensions for file types. saves time searching files that
        #   likely don't contain the file type (cci wouldn't be a cia, etc)
        if 'cia' in types:
            addtolist('.cia')
        if 'cci' in types or '3ds' in types:
            addtolist('.cci', '.3ds')
        if 'ncch' in types:
            addtolist('.ncch', '.cxi', '.cfa', '.app', '*.{}.{}*'.format('[0-9a-f]' * 4, '[0-9a-f]' * 8))  # what the fuck?
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
    if a.search_all:
        addtolist('')
    else:
        # last ones are not separate types, just filename formats/extensions
        addtolist('.cia', '.cci', '.3ds', '.ncch', '.cxi', '.cfa', '.tik', '.tmd', '.exefs', '.bin', '.app', '*.{}.{}*'.format('[0-9a-f]' * 4, '[0-9a-f]' * 8))  # what the fuck?????

print_v('Done listing files', v=1)


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
        print_v('Searching {} for matches'.format(filename), v=2)
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

            f.seek(0x2A40)
            ticket = f.read(0x350)

            if a.title_id:
                # read tid from ticket
                matches = check_ticket(ticket, a.title_id, 'tid')
                if matches:
                    result['tid'] = a.title_id.lower()
                else:
                    continue

            # this is very lazy, but given fixed offsets this should not change
            f.seek(0x38CA)
            content_type = int.from_bytes(f.read(0x2), 'big')
            is_encrypted = content_type & 1

            if is_encrypted:
                if encryption_supported:
                    # get signer (determines retail/dev)
                    ticket_cert_name = ticket[0x150:0x15A]
                    if ticket_cert_name == b'XS0000000c':
                        is_dev = 0
                    elif ticket_cert_name == b'XS00000009':
                        is_dev = 1
                    else:
                        print('Ticket certificate unknown! Found {}. This shouldn\'t be happening. Is this a valid CIA?'.format(ticket_cert_name))
                        continue
                    # get encrypted titlekey
                    enc_titlekey = ticket[0x1BF:0x1CF]
                    # get common key index
                    common_key_index = ticket[0x1F1]
                    # decrypt titlekey
                    cipher_titlekey = AES.new(bytes.fromhex(common_keys[common_key_index][is_dev]), AES.MODE_CBC, ticket[0x1DC:0x1E4] + (b'\0' * 8))
                    dec_titlekey = cipher_titlekey.decrypt(enc_titlekey)
                    f.seek(content_offset)
                    cipher_content0 = AES.new(dec_titlekey, AES.MODE_CBC, b'\0' * 0x10)
                    ncch_header_pre = cipher_content0.decrypt(f.read(0x200))
                    ncch_key_y = ncch_header_pre[0:0x10]
                    ncch_header = ncch_header_pre[0x100:0x200]
                else:
                    print_v('Not searching {} any further due to no encryption support.'.format(filename))
                    continue
            else:
                f.seek(content_offset)
                ncch_key_y = f.read(0x10)
                f.seek(0xF0, 1)
                ncch_header = f.read(0x100)

            if a.product_code:
                res = check_ncch(ncch_header, a.product_code, 'pcode')
                if res:
                    result['pcode'] = res
                    matches = True
                else:
                    continue

        else:
            f.seek(0)
            # read keyY while we're here
            ncch_key_y = f.read(0x10)
            # check for ncch/ncsd header
            f.seek(0xF0, 1)
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

                if encryption_supported and (a.name or a.strict_name):
                    continue  # TODO: this

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
                f.seek(0x4000)
                ncch_key_y = f.read(0x10)
                f.seek(0xF0, 1)
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

                if encryption_supported and (a.name or a.strict_name):
                    continue  # TODO: this

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
    column_lengths = [0] * len(header)
    add_to_table(header)

    for filename, result in search_results.items():
        line = [filename, result['type']]
        if 'tid' in result:
            line.append(result['tid'])
        if 'pcode' in result:
            line.append(result['pcode'])
        add_to_table(line)

    for line_idx, line in enumerate(lines):
        if line_idx == 0 and os.name != 'nt':  # windows cmd doesn't have our fancy terminal formatting
            print('\033[4m', end='')  # fancy underline, if the terminal supports it
        print(' | '.join(col.ljust(column_lengths[idx]) for idx, col in enumerate(line)))
        if line_idx == 0 and os.name != 'nt':
            print('\033[0m', end='')
else:
    print('No files matched the given search terms.')
