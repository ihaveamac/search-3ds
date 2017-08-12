#!/usr/bin/env python3

import argparse
import os
import struct
import sys
from collections import OrderedDict
from pathlib import Path

encryption_supported = False
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    encryption_supported = True
except ImportError:
    print('Cryptodome module not found, please install pycryptodomex for encryption support (`pip install pycryptodomex`).')

parser = argparse.ArgumentParser(description='Searches contents in files used on the Nintendo 3DS system.')
parser.add_argument('--path', metavar='DIR', help='path to search, defaults to current directory', default='')
parser.add_argument('--verbose', '-v', help='print more information, use multiple times for more verbosity', action='count', default=0)
parser.add_argument('--search-all', help='search every file, without basing on extension', action='store_true')
parser.add_argument('--no-format', help='don\'t format results like a table', action='store_true')

terms = parser.add_argument_group('terms')
terms.add_argument('--type', '-t', metavar='TYPE', help='file types to search, separated by commas')
terms.add_argument('--name', '-n', metavar='NAME', help='title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--strict-name', '-N', metavar='NAME', help='more-strict title name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--publisher', '-P', metavar='NAME', help='publisher name (in smdh, displays on HOME Menu) - entire name not required (NYI)')
terms.add_argument('--title-id', '-i', metavar='TID', help='title id (e.g. 0004000000046500)')
terms.add_argument('--unique-id', '-u', metavar='UID', help='unique id in hex (e.g. 175e or 0x175e)')
terms.add_argument('--product-code', '-p', metavar='CODE', help='product code (e.g. CTR-P-AQNE) - entire product code not required')

a = parser.parse_args()


def print_v(msg, v=1):
    if a.verbose >= v:
        print('DEBUG L{}: {}'.format(v, msg))


# if you know of a better way to check if at least one of the terms was used,
#   let me know please
if not (a.type or a.name or a.strict_name or a.publisher or a.title_id or a.unique_id or a.product_code):
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
        try:
            for f in Path(a.path).glob(os.path.join('**/*' + e)):
                f_s = str(f)
                if os.path.isfile(f_s) and f_s not in big_list_of_files:
                    print_v('Adding {} to list for searching'.format(f_s), v=2)
                    big_list_of_files.append(f_s)
        except OSError as err:
            if err.errno == 62:
                print_v('Pathname too long. Ending listing for "{}".'.format(e))
            else:
                raise


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
            addtolist('.ncch', '.cxi', '.cfa', '.app', '.{}.{}*'.format('[0-9a-f]' * 4, '[0-9a-f]' * 8))  # what the fuck?
            # last option is to follow the format <name>.<index>.<id> that ctrtool
            #   saves cia contents as
        if 'tik' in types or 'ticket' in types:
            addtolist('.tik')
        if 'tmd' in types:
            addtolist('.tmd')
else:
    # this doesn't feel right
    types = 'all'
    if a.search_all:
        addtolist('')
    else:
        # last ones are not separate types, just filename formats/extensions
        addtolist('.cia', '.cci', '.3ds', '.ncch', '.cxi', '.cfa', '.tik', '.tmd', '.bin', '.app', '.{}.{}*'.format('[0-9a-f]' * 4, '[0-9a-f]' * 8))  # what the fuck?????

print_v('Done listing files', v=1)


def check_type(ftype):
    return types == 'all' or ftype in types


# based on http://stackoverflow.com/questions/1766535/bit-hack-round-off-to-multiple-of-8/1766566#1766566
def roundup(x):
    return ((x + 63) >> 6) << 6


# used from http://www.falatic.com/index.php/108/python-and-bitwise-rotation
# converted to def because pycodestyle complained to me
def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2 ** max_bits - 1) | ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))


def ncch_keygen(key_y, isdev):
    x = int(orig_ncch_key_x[isdev], 16)
    y = int.from_bytes(key_y, 'big')
    return rol((rol(x, 2, 128) ^ y) + 0x1FF9E9AAC5FE0408024591DC5D52768A, 87, 128).to_bytes(0x10, byteorder='big')


def check_ticket(ticket, content, cktype):
    tid = ticket[0x1DC:0x1E4]
    uid = int.from_bytes(tid[4:7], 'big')
    if content == '.show':
        if cktype == 'tid':
            return tid.hex()
        elif cktype == 'uid':
            return '{:06x}'.format(uid)
        return False

    contents = content.split(',')
    if cktype == 'tid':
        if any(bytes.fromhex(c) == tid for c in contents):
            return tid.hex()
        return False
    elif cktype == 'uid':
        if any(int(c, 16) == uid for c in contents):
            return '{:06x}'.format(uid)
        return False
    return False


def check_tmd(tmd, content, cktype):
    tid = tmd[0x18C:0x194]
    uid = int.from_bytes(tid[4:7], 'big')
    if content == '.show':
        if cktype == 'tid':
            return tid.hex()
        elif cktype == 'uid':
            return '{:06x}'.format(uid)
        return False

    contents = content.split(',')
    if cktype == 'tid':
        if any(bytes.fromhex(c) == tid for c in contents):
            return tid.hex()
        return False
    elif cktype == 'uid':
        if any(int(c, 16) == uid for c in contents):
            return '{:06x}'.format(uid)
        return False
    return False


# checks starting at 0x100 (ignoring signature)
def check_ncch(ncch, content, cktype):
    tid = ncch[0x8:0x10][::-1]
    uid = int.from_bytes(tid[4:7], 'big')
    pcode = ncch[0x50:0x60].rstrip(b'\0').decode('utf-8')
    if content == '.show':
        if cktype == 'tid':
            return tid.hex()
        elif cktype == 'uid':
            return '{:06x}'.format(uid)
        elif cktype == 'pcode':
            return pcode
        return False

    contents = content.split(',')
    if cktype == 'tid':
        if any(bytes.fromhex(c) == tid for c in contents):
            return tid.hex()
        return False
    elif cktype == 'pcode':
        if any(c.lower() in pcode.lower() for c in contents):
            return pcode
        return False
    elif cktype == 'uid':
        if any(int(c, 16) == uid for c in contents):
            return '{:06x}'.format(uid)
        return False
    return False


# checks starting at 0x100 (ignoring signature)
def check_ncsd(ncsd, content, cktype):
    tid = ncsd[0x8:0x10][::-1]
    uid = int.from_bytes(tid[4:7], 'big')
    if content == '.show':
        if cktype == 'tid':
            return tid.hex()
        elif cktype == 'uid':
            return '{:06x}'.format(uid)
        return False

    contents = content.split(',')
    if cktype == 'tid':
        if any(bytes.fromhex(c) == tid for c in contents):
            return tid.hex()
        return False


lang_codes = ('JA', 'EN', 'FR', 'DE', 'IT', 'ES', 'ZH-S', 'KO', 'NL', 'PT', 'RU', 'ZH-T')


def check_smdh(smdh, content, cktype):
    title_structs_raw = smdh[0x8:0x2008]
    title_structs_raw2 = [title_structs_raw[i:i + 0x200] for i in range(0, 0x2000, 0x200)]
    title_structs = OrderedDict()
    for idx, st in enumerate(title_structs_raw2):
        if st != b'\0' * 0x200:
            title_structs[lang_codes[idx]] = {
                'short_name': st[0:0x80].decode('utf-16le').rstrip('\0'),
                'long_name': st[0x80:0x180].decode('utf-16le').rstrip('\0'),
                'publisher': st[0x180:0x200].decode('utf-16le').rstrip('\0')
            }
    print_v(title_structs)
    return False  # TODO: proper smdh searching


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
            # no need to do a tid check here, if it's in a cia it's probably
            #   for 3DS

            # get signer (determines retail/dev)
            ticket_cert_name = ticket[0x150:0x15A]
            if ticket_cert_name == b'XS0000000c':
                is_dev = 0
            elif ticket_cert_name == b'XS00000009':
                is_dev = 1
                result['type'] = 'CIA (dev)'
            else:
                print_v('Ticket certificate unknown! Found {}. This shouldn\'t be happening. Is this a valid CIA?'.format(ticket_cert_name))
                continue

            if a.title_id:
                # read tid from ticket
                res = check_ticket(ticket, a.title_id, 'tid')
                if res:
                    result['tid'] = res
                    matches = True
                else:
                    continue

            if a.unique_id:
                # read uid from ticket
                res = check_ticket(ticket, a.unique_id, 'uid')
                if res:
                    result['uid'] = res
                    matches = True
                else:
                    continue

            # this is very lazy, but given fixed offsets this should not change
            f.seek(0x38CA)
            content_type = int.from_bytes(f.read(0x2), 'big')
            is_encrypted = content_type & 1

            if is_encrypted:
                if encryption_supported:
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

            if ncch_header[0:4] != b'NCCH':
                continue  # either corrupted, or DSi title

            ncch_flag_5 = ncch_header[0x8D]  # content type
            ncch_flag_7 = ncch_header[0x8F]  # bit-masks (for crypto)
            is_ncch_encrypted = not ncch_flag_7 & 4
            is_ncch_zerokey_encrypted = ncch_flag_7 & 1

            if a.product_code:
                res = check_ncch(ncch_header, a.product_code, 'pcode')
                if res:
                    result['pcode'] = res
                    matches = True
                else:
                    continue

            if is_ncch_encrypted or is_ncch_zerokey_encrypted:
                if encryption_supported:
                    print_v('Not searching {} any further due to NCCH crypto not being implemented.'.format(filename))
                    if a.name or a.strict_name or a.publisher:
                        continue
                else:
                    print_v('Not searching {} any further due to no encryption support.'.format(filename))
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
                    continue

                ncch_flag_5 = file_header[0x8D]  # content type
                ncch_flag_7 = file_header[0x8F]  # bit-masks (for crypto)
                is_ncch_encrypted = not ncch_flag_7 & 4
                is_ncch_zerokey_encrypted = ncch_flag_7 & 1

                result['type'] = 'NCCH/' + ('CXI' if ncch_flag_5 & 2 else 'CFA')

                if a.title_id:
                    res = check_ncch(file_header, a.title_id, 'tid')
                    if res:
                        result['tid'] = res
                        matches = True
                    else:
                        continue

                if a.unique_id:
                    res = check_ncch(file_header, a.unique_id, 'uid')
                    if res:
                        result['uid'] = res
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

                if is_ncch_encrypted or is_ncch_zerokey_encrypted:
                    if encryption_supported:
                        print_v('Not searching {} any further due to NCCH crypto not being implemented.'.format(filename))
                        if a.name or a.strict_name or a.publisher:
                            continue
                    else:
                        print_v('Not searching {} any further due to no encryption support.'.format(filename))
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
                f.seek(0x4000)
                ncch_key_y = f.read(0x10)
                f.seek(0xF0, 1)
                ncch_header = f.read(0x100)

                ncch_flag_5 = ncch_header[0x8D]  # content type
                ncch_flag_7 = ncch_header[0x8F]  # bit-masks (for crypto)
                is_ncch_encrypted = not ncch_flag_7 & 4
                is_ncch_zerokey_encrypted = ncch_flag_7 & 1

                if a.title_id:
                    # read tid from ncsd header
                    res = check_ncch(ncch_header, a.title_id, 'tid')
                    if res:
                        result['tid'] = res
                        matches = True
                    else:
                        continue

                if a.unique_id:
                    res = check_ncch(ncch_header, a.unique_id, 'uid')
                    if res:
                        result['uid'] = res
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

                if is_ncch_encrypted or is_ncch_zerokey_encrypted:
                    if encryption_supported:
                        print_v('Not searching {} any further due to NCCH crypto not being implemented.'.format(filename))
                        if a.name or a.strict_name or a.publisher:
                            continue
                    else:
                        print_v('Not searching {} any further due to no encryption support.'.format(filename))
                        continue

            else:
                # not ncch/ncsd
                # check to see if it's a ticket or tmd
                f.seek(0x150)
                cert_name = f.read(0xA)
                if cert_name.startswith(b'XS'):  # ticket
                    matches = check_type('tik')
                    if not matches:
                        continue
                    f.seek(0)
                    ticket = f.read(0x350)
                    # tid check, to make sure it's 3DS and not other systems
                    if ticket[0x1DC:0x1DE] != b'\0\4':
                        continue
                    if cert_name == b'XS0000000c':
                        result['type'] = 'TIK'
                    elif cert_name == b'XS00000009':
                        result['type'] = 'TIK (dev)'
                    else:
                        print_v('Ticket certificate unknown! Found {}. This shouldn\'t be happening. Is this a valid 3DS ticket?'.format(cert_name))
                        continue

                    if a.title_id:
                        # read tid from ticket
                        res = check_ticket(ticket, a.title_id, 'tid')
                        if res:
                            result['tid'] = res
                            matches = True
                        else:
                            continue

                    if a.unique_id:
                        # read uid from ticket
                        res = check_ticket(ticket, a.unique_id, 'uid')
                        if res:
                            result['uid'] = res
                            matches = True
                        else:
                            continue

                    if a.product_code or a.name or a.strict_name or a.publisher:
                        continue  # not relevant to a ticket

                elif cert_name.startswith(b'CP'):  # tmd
                    matches = check_type('tmd')
                    if not matches:
                        continue
                    f.seek(0x1DE)
                    content_count = int.from_bytes(f.read(2), 'big')
                    f.seek(0)
                    tmd = f.read(0xB04 + (0x30 * content_count))
                    # tid check, to make sure it's 3DS and not other systems
                    if tmd[0x18C:0x18E] != b'\0\4':
                        continue
                    if cert_name == b'CP0000000b':
                        result['type'] = 'TMD'
                    elif cert_name == b'CP0000000a':
                        result['type'] = 'TMD (dev)'
                    else:
                        print_v('Ticket certificate unknown! Found {}. This shouldn\'t be happening. Is this a valid 3DS tmd?'.format(cert_name))
                        continue

                    if a.title_id:
                        # read tid from tmd
                        res = check_tmd(tmd, a.title_id, 'tid')
                        if res:
                            result['tid'] = res
                            matches = True
                        else:
                            continue

                    if a.unique_id:
                        # read uid from tmd
                        res = check_tmd(tmd, a.unique_id, 'uid')
                        if res:
                            result['uid'] = res
                            matches = True
                        else:
                            continue

                    if a.product_code or a.name or a.strict_name or a.publisher:
                        continue  # not relevant to a tmd

        # if still matches (mostly a failsafe), add it to the search results
        if matches:
            search_results[filename] = result

column_lengths = []
lines = []


def add_to_table(line):
    global column_lengths, lines
    if not a.no_format:
        for idx, col in enumerate(line):
            column_lengths[idx] = max(len(col), column_lengths[idx])
    lines.append(line)


if search_results:
    header = ['Filename', 'Type']
    if a.title_id:
        header.append('Title ID')
    if a.unique_id:
        header.append('Unique ID')
    if a.product_code:
        header.append('Product Code')
    if not a.no_format:
        column_lengths = [0] * len(header)
        add_to_table(header)

    for filename, result in search_results.items():
        line = [filename, result['type']]
        if 'tid' in result:
            line.append(result['tid'])
        if 'uid' in result:
            line.append(result['uid'])
        if 'pcode' in result:
            line.append(result['pcode'])
        add_to_table(line)

    for line_idx, line in enumerate(lines):
        if a.no_format:
            if line_idx == 0:
                continue
            print('; '.join(header[idx] + ': ' + col for idx, col in enumerate(line)))
        else:
            if line_idx == 0 and os.name != 'nt':  # windows cmd doesn't have our fancy terminal formatting
                print('\033[4m', end='')  # fancy underline, if the terminal supports it
            print(' | '.join(col.ljust(column_lengths[idx]) for idx, col in enumerate(line)))
            if line_idx == 0 and os.name != 'nt':
                print('\033[0m', end='')
else:
    print('No files matched the given search terms.')
