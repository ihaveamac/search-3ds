#!/usr/bin/env python3

import argparse
import hashlib
import os
import struct
import sys
import traceback
import unicodedata
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
parser.add_argument('--err', help='dump traceback when an exception occurs', action='store_true')

terms = parser.add_argument_group('terms')
terms.add_argument('--type', '-t', metavar='TYPE', help='file types to search, separated by commas')
terms.add_argument('--name', '-n', metavar='NAME', help='title name (in smdh, displays on HOME Menu) - entire name not required')
terms.add_argument('--strict-name', '-N', metavar='NAME', help='more-strict title name (in smdh, displays on HOME Menu) - entire name not required')
terms.add_argument('--publisher', '-P', metavar='NAME', help='publisher name (in smdh, displays on HOME Menu) - entire name not required')
terms.add_argument('--title-id', '-i', metavar='TID', help='title id (e.g. 0004000000046500)')
terms.add_argument('--unique-id', '-u', metavar='UID', help='unique id in hex (e.g. 175e or 0x175e)')
terms.add_argument('--product-code', '-p', metavar='CODE', help='product code (e.g. CTR-P-AQNE) - entire product code not required')
terms.add_argument('--exh-name', '-e', metavar='TITLE', help='extended header (exheader) application title - entire name not required')

a = parser.parse_args()


def print_v(msg, v=1):
    if a.verbose >= v:
        print('DEBUG L{}: {}'.format(v, msg))


# if you know of a better way to check if at least one of the terms was used,
#   let me know please
if not (a.type or a.name or a.strict_name or a.publisher or a.title_id or a.unique_id or a.product_code or a.exh_name):
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
zerokey = b'\0' * 16

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


def ncch_keygen(key_y, is_dev):
    x = int(orig_ncch_key_x[is_dev], 16)
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
    return False


def check_exh(exh, content, cktype):
    appname = exh[0:8].decode('utf-8').rstrip('\0')
    if content == '.show':
        if cktype == 'appname':
            return appname
        return False

    contents = content.split(',')
    if cktype == 'appname':
        if any(c.lower() in appname.lower() for c in contents):
            return appname
        return False
    return False


lang_codes = ('JA', 'EN', 'FR', 'DE', 'IT', 'ES', 'ZH-S', 'KO', 'NL', 'PT', 'RU', 'ZH-T', 'unk1', 'unk2', 'unk3', 'unk4')


def normalize_name(name, lang):
    if not any(l in lang for l in ('JA', 'ZH', 'KO', 'RU', 'unk')):
        name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('utf-8')
    return name


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

    contents = content.split(',')
    found_lang = False
    for c in contents:
        if any(c.lower().startswith(l.lower()) for l in lang_codes):
            c_lang, c_name = c.split(':', 1)
            c_lang = c_lang.upper()
            if c_lang in title_structs:
                if c_name == '.show':
                    found_lang = c_lang
                    break
                if cktype == 'name':
                    n_name = normalize_name(title_structs[c_lang]['short_name'], c_lang)
                    n_long_name = normalize_name(title_structs[c_lang]['long_name'], c_lang)
                    c_n_name = normalize_name(c_name, c_lang)
                    if c_n_name.lower() in n_name.lower() or c_n_name.lower() in n_long_name.lower():
                        found_lang = c_lang
                        break
                elif cktype == 'strict_name':
                    if c_name in title_structs[c_lang]['short_name'] or c_name in title_structs[c_lang]['long_name']:
                        found_lang = c_lang
                        break
                elif cktype == 'publisher':
                    n_publisher = normalize_name(title_structs[c_lang]['publisher'], c_lang)
                    c_n_name = normalize_name(c_name, c_lang)
                    if c_n_name in n_publisher:
                        found_lang = c_lang
                        break
                else:
                    return False
        else:
            if c == '.show':
                if 'EN' in title_structs:
                    found_lang = 'EN'
                    break
                else:
                    for l in lang_codes:
                        if l in title_structs:
                            found_lang = l
                            break
            for lang, name in title_structs.items():
                if cktype == 'name':
                    n_name = normalize_name(name['short_name'], lang)
                    n_long_name = normalize_name(name['long_name'], lang)
                    c_n_name = normalize_name(c, lang)
                    if c_n_name.lower() in n_name.lower() or c_n_name.lower() in n_long_name.lower():
                        found_lang = lang
                        break
                elif cktype == 'strict_name':
                    if c in name['short_name'] or c in name['long_name']:
                        found_lang = lang
                        break
                elif cktype == 'publisher':
                    n_publisher = normalize_name(name['publisher'], lang)
                    c_n_name = normalize_name(c, lang)
                    if c_n_name in n_publisher:
                        found_lang = lang
                        break
                else:
                    return False

    if found_lang:
        return (found_lang, title_structs[found_lang])
    return False


search_results = OrderedDict()

for filename in big_list_of_files:
    read_smdh = a.name or a.strict_name or a.publisher
    read_exh = a.exh_name
    try:
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
                tid = ticket[0x1DC:0x1E4]

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
                is_cia_encrypted = content_type & 1

                if is_cia_encrypted:
                    if encryption_supported:
                        # get encrypted titlekey
                        enc_titlekey = ticket[0x1BF:0x1CF]
                        # get common key index
                        common_key_index = ticket[0x1F1]
                        # decrypt titlekey
                        cipher_titlekey = AES.new(bytes.fromhex(common_keys[common_key_index][is_dev]), AES.MODE_CBC, tid + (b'\0' * 8))
                        dec_titlekey = cipher_titlekey.decrypt(enc_titlekey)
                        f.seek(content_offset)
                        cipher_content0 = AES.new(dec_titlekey, AES.MODE_CBC, b'\0' * 0x10)
                        ncch_header_enc = f.read(0x200)
                        ncch_header_pre = cipher_content0.decrypt(ncch_header_enc)
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

                # this is hell
                if read_exh or read_smdh:
                    exefs_offset = int.from_bytes(ncch_header[0xA0:0xA4], 'little') * 0x200
                    ctr_exh_value = int.from_bytes(tid + b'\1' + (b'\0' * 7), 'big')
                    ctr_exefs_value = int.from_bytes(tid + b'\2' + (b'\0' * 7), 'big')
                    if is_ncch_encrypted:
                        if encryption_supported:
                            ncch_key = zerokey if is_ncch_zerokey_encrypted else ncch_keygen(ncch_key_y, is_dev)
                            if is_cia_encrypted:
                                if read_exh:
                                    if ncch_flag_5 & 2:
                                        cia_exh_iv = ncch_header_enc[0x1F0:0x200]
                                        cipher_cia_exh = AES.new(dec_titlekey, AES.MODE_CBC, cia_exh_iv)
                                        f.seek(content_offset + 0x200)
                                        exh_cia_enc = f.read(0x400)  # not the full exheader, just enough for hashing
                                        exh = cipher_cia_exh.decrypt(exh_cia_enc)
                                    else:
                                        continue  # cfa does not have exheader
                                if read_smdh:
                                    if exefs_offset != 0:
                                        f.seek(content_offset + exefs_offset - 0x10)
                                        cia_exefs_iv = f.read(0x10)
                                        cipher_cia_exefs = AES.new(dec_titlekey, AES.MODE_CBC, cia_exefs_iv)
                                        exefs_cia_enc = f.read(0x200)
                                        exefs_header = cipher_cia_exefs.decrypt(exefs_cia_enc)
                                    else:
                                        continue  # no exefs, no smdh
                            else:
                                if read_exh:
                                    if ncch_flag_5 & 2:
                                        f.seek(content_offset + 0x200)
                                        exh = f.read(0x400)
                                    else:
                                        continue  # cfa does not have exheader
                                if read_smdh:
                                    if exefs_offset != 0:
                                        f.seek(content_offset + exefs_offset)
                                        exefs_header = f.read(0x200)
                                    else:
                                        continue  # no exefs, no smdh
                            if read_exh:
                                ctr_exh = Counter.new(128, initial_value=ctr_exh_value)
                                cipher_exh = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exh)
                                exh = cipher_exh.decrypt(exh)
                            if read_smdh:
                                ctr_exefs = Counter.new(128, initial_value=ctr_exefs_value)
                                cipher_exefs = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exefs)
                                exefs_header = cipher_exefs.decrypt(exefs_header)
                        else:
                            print_v('Not searching {} any further due to no encryption support.'.format(filename))
                            continue
                    else:
                        if read_exh:
                            if ncch_flag_5 & 2:
                                if is_cia_encrypted:
                                    # not tested
                                    cia_exh_iv = ncch_header_enc[0x1F0:0x200]
                                    cipher_cia_exh = AES.new(dec_titlekey, AES.MODE_CBC, cia_exh_iv)
                                    f.seek(content_offset + 0x200)
                                    exh_cia_enc = f.read(0x400)  # not the full exheader, just enough for hashing
                                    exh = cipher_cia_exh.decrypt(exh_cia_enc)
                                else:
                                    f.seek(content_offset + 0x200)
                                    exh = f.read(0x400)
                            else:
                                continue  # cfa does not have exheader
                        if read_smdh:
                            if exefs_offset != 0:
                                if is_cia_encrypted:
                                    # not tested
                                    f.seek(content_offset + exefs_offset - 0x10)
                                    cia_exefs_iv = f.read(0x10)
                                    cipher_cia_exefs = AES.new(dec_titlekey, AES.MODE_CBC, cia_exefs_iv)
                                    exefs_cia_enc = f.read(0x200)
                                    exefs_header = cipher_cia_exefs.decrypt(exefs_cia_enc)
                                else:
                                    f.seek(content_offset + exefs_offset)
                                    exefs_header = f.read(0x200)
                            else:
                                continue  # no exefs, no smdh

                    # get icon
                    if read_smdh:
                        exefs_files = [exefs_header[i:i + 0x10] for i in range(0, 0xA0, 0x10)]
                        icon_offset = 0
                        for en in exefs_files:
                            if en[0:8].rstrip(b'\0') == b'icon':
                                icon_offset = int.from_bytes(en[8:12], 'little') + 0x200
                                break
                        if icon_offset:
                            if is_cia_encrypted:
                                f.seek(content_offset + exefs_offset + icon_offset - 0x10)
                                cia_exefs_icon_iv = f.read(0x10)
                                cipher_cia_exefs_icon = AES.new(dec_titlekey, AES.MODE_CBC, cia_exefs_icon_iv)
                                exefs_icon_enc_cia = f.read(0x36C0)
                                icon = cipher_cia_exefs_icon.decrypt(exefs_icon_enc_cia)
                            else:
                                f.seek(content_offset + exefs_offset + icon_offset)
                                icon = f.read(0x36C0)
                            if is_ncch_encrypted:
                                ctr_exefs_icon = Counter.new(128, initial_value=ctr_exefs_value + (icon_offset >> 4))
                                cipher_exefs_icon = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exefs_icon)
                                icon = cipher_exefs_icon.decrypt(icon)

                            if a.name:
                                res = check_smdh(icon, a.name, 'name')
                                if res:
                                    result['name'] = res
                                    matches = True
                                else:
                                    continue

                            if a.strict_name:
                                res = check_smdh(icon, a.strict_name, 'strict_name')
                                if res:
                                    result['name'] = res
                                    matches = True
                                else:
                                    continue

                            if a.publisher:
                                res = check_smdh(icon, a.publisher, 'publisher')
                                if res:
                                    result['publisher'] = res
                                    matches = True
                                else:
                                    continue

                        else:
                            print_v('Failed to find icon in exefs in {}'.format(filename))
                            continue

                    if read_exh:
                        res = check_exh(exh, a.exh_name, 'appname')
                        if res:
                            result['appname'] = res
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
                tid = file_header[0x8:0x10][::-1]
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

                    if read_exh or read_smdh:
                        exefs_offset = int.from_bytes(file_header[0xA0:0xA4], 'little') * 0x200
                        ctr_exh_value = int.from_bytes(tid + b'\1' + (b'\0' * 7), 'big')
                        ctr_exefs_value = int.from_bytes(tid + b'\2' + (b'\0' * 7), 'big')
                        if is_ncch_encrypted:
                            uses_dev = None
                            if encryption_supported:
                                # test retail, then dev if fail
                                ncch_key = zerokey if is_ncch_zerokey_encrypted else ncch_keygen(ncch_key_y, 0)
                                if not is_ncch_zerokey_encrypted:
                                    ncch_key_dev = ncch_keygen(ncch_key_y, 1)
                                if read_exh:
                                    if ncch_flag_5 & 2:
                                        f.seek(0x200)
                                        exh_enc = f.read(0x400)
                                        ctr_exh = Counter.new(128, initial_value=ctr_exh_value)
                                        cipher_exh = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exh)
                                        exh = cipher_exh.decrypt(exh_enc)
                                        exh_hash = hashlib.sha256(exh).digest()
                                        if exh_hash != file_header[0x60:0x80]:
                                            uses_dev = True
                                            cipher_exh = AES.new(ncch_key_dev, AES.MODE_CTR, counter=ctr_exh)
                                            exh = cipher_exh.decrypt(exh_enc)
                                            exh_hash = hashlib.sha256(exh).digest()
                                            if exh_hash != file_header[0x60:0x80]:
                                                print_v('ExHeader hash check fail for {}'.format(filename))
                                                continue
                                    else:
                                        continue  # cfa does not have exheader
                                if read_smdh:
                                    if exefs_offset != 0:
                                        f.seek(exefs_offset)
                                        exefs_enc = f.read(0x200)
                                        ctr_exefs = Counter.new(128, initial_value=ctr_exefs_value)
                                        if uses_dev is None:
                                            cipher_exefs = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exefs)
                                            exefs_header = cipher_exefs.decrypt(exefs_enc)
                                            exefs_hash = hashlib.sha256(exefs_header).digest()
                                            if exefs_hash != file_header[0xC0:0xE0]:
                                                uses_dev = True
                                                cipher_exefs = AES.new(ncch_key_dev, AES.MODE_CTR, counter=ctr_exefs)
                                                exefs_header = cipher_exefs.decrypt(exefs_enc)
                                                exefs_hash = hashlib.sha256(exefs_header).digest()
                                                if exefs_hash != file_header[0xC0:0xE0]:
                                                    print_v('ExeFS header hash check fail for {}'.format(filename))
                                                    continue
                                        else:
                                            cipher_exefs = AES.new(ncch_key_dev if uses_dev else ncch_key, AES.MODE_CTR, counter=ctr_exefs)
                                            exefs_header = cipher_exefs.decrypt(exefs_enc)
                                            exefs_hash = hashlib.sha256(exefs_header).digest()
                                            if exefs_hash != file_header[0xC0:0xE0]:
                                                print_v('ExeFS header hash check fail for {}'.format(filename))
                                                continue
                                    else:
                                        continue  # no exefs, no smdh
                                if uses_dev is True:
                                    result['type'] += ' (dev)'
                            else:
                                print_v('Not searching {} any further due to no encryption support.'.format(filename))
                                continue

                        else:
                            if read_exh:
                                if ncch_flag_5 & 2:
                                    f.seek(0x200)
                                    exh = f.read(0x400)
                                else:
                                    continue  # cfa does not have exheader
                            if read_smdh:
                                if exefs_offset != 0:
                                    f.seek(exefs_offset)
                                    exefs_header = f.read(0x200)
                                else:
                                    continue  # no exefs, no smdh

                        # get icon
                        if read_smdh:
                            exefs_files = [exefs_header[i:i + 0x10] for i in range(0, 0xA0, 0x10)]
                            icon_offset = 0
                            for en in exefs_files:
                                if en[0:8].rstrip(b'\0') == b'icon':
                                    icon_offset = int.from_bytes(en[8:12], 'little') + 0x200
                                    break
                            if icon_offset:
                                f.seek(exefs_offset + icon_offset)
                                icon = f.read(0x36C0)
                                if is_ncch_encrypted:
                                    ctr_exefs_icon = Counter.new(128, initial_value=ctr_exefs_value + (icon_offset >> 4))
                                    cipher_exefs_icon = AES.new(ncch_key_dev if uses_dev else ncch_key, AES.MODE_CTR, counter=ctr_exefs_icon)
                                    icon = cipher_exefs_icon.decrypt(icon)

                                if a.name:
                                    res = check_smdh(icon, a.name, 'name')
                                    if res:
                                        result['name'] = res
                                        matches = True
                                    else:
                                        continue

                                if a.strict_name:
                                    res = check_smdh(icon, a.strict_name, 'strict_name')
                                    if res:
                                        result['name'] = res
                                        matches = True
                                    else:
                                        continue

                                if a.publisher:
                                    res = check_smdh(icon, a.publisher, 'publisher')
                                    if res:
                                        result['publisher'] = res
                                        matches = True
                                    else:
                                        continue

                        if read_exh:
                            res = check_exh(exh, a.exh_name, 'appname')
                            if res:
                                result['appname'] = res
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

                    if read_exh or read_smdh:
                        exefs_offset = int.from_bytes(ncch_header[0xA0:0xA4], 'little') * 0x200
                        ctr_exh_value = int.from_bytes(tid + b'\1' + (b'\0' * 7), 'big')
                        ctr_exefs_value = int.from_bytes(tid + b'\2' + (b'\0' * 7), 'big')
                        if is_ncch_encrypted:
                            uses_dev = None
                            if encryption_supported:
                                # test retail, then dev if fail
                                ncch_key = zerokey if is_ncch_zerokey_encrypted else ncch_keygen(ncch_key_y, 0)
                                if not is_ncch_zerokey_encrypted:
                                    ncch_key_dev = ncch_keygen(ncch_key_y, 1)
                                if read_exh:
                                    if ncch_flag_5 & 2:
                                        f.seek(0x4200)
                                        exh_enc = f.read(0x400)
                                        ctr_exh = Counter.new(128, initial_value=ctr_exh_value)
                                        cipher_exh = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exh)
                                        exh = cipher_exh.decrypt(exh_enc)
                                        exh_hash = hashlib.sha256(exh).digest()
                                        if exh_hash != ncch_header[0x60:0x80]:
                                            uses_dev = True
                                            cipher_exh = AES.new(ncch_key_dev, AES.MODE_CTR, counter=ctr_exh)
                                            exh = cipher_exh.decrypt(exh_enc)
                                            exh_hash = hashlib.sha256(exh).digest()
                                            if exh_hash != ncch_header[0x60:0x80]:
                                                print_v('ExHeader hash check fail for {}'.format(filename))
                                                continue
                                    else:
                                        continue  # cfa does not have exheader
                                if read_smdh:
                                    if exefs_offset != 0:
                                        f.seek(0x4000 + exefs_offset)
                                        exefs_enc = f.read(0x200)
                                        ctr_exefs = Counter.new(128, initial_value=ctr_exefs_value)
                                        if uses_dev is None:
                                            cipher_exefs = AES.new(ncch_key, AES.MODE_CTR, counter=ctr_exefs)
                                            exefs_header = cipher_exefs.decrypt(exefs_enc)
                                            exefs_hash = hashlib.sha256(exefs_header).digest()
                                            if exefs_hash != ncch_header[0xC0:0xE0]:
                                                uses_dev = True
                                                cipher_exefs = AES.new(ncch_key_dev, AES.MODE_CTR, counter=ctr_exefs)
                                                exefs_header = cipher_exefs.decrypt(exefs_enc)
                                                exefs_hash = hashlib.sha256(exefs_header).digest()
                                                if exefs_hash != ncch_header[0xC0:0xE0]:
                                                    print_v('ExeFS header hash check fail for {}'.format(filename))
                                                    continue
                                        else:
                                            cipher_exefs = AES.new(ncch_key_dev if uses_dev else ncch_key, AES.MODE_CTR, counter=ctr_exefs)
                                            exefs_header = cipher_exefs.decrypt(exefs_enc)
                                            exefs_hash = hashlib.sha256(exefs_header).digest()
                                            if exefs_hash != ncch_header[0xC0:0xE0]:
                                                print_v('ExeFS header hash check fail for {}'.format(filename))
                                                continue
                                    else:
                                        continue  # no exefs, no smdh
                                if uses_dev is True:
                                    result['type'] += ' (dev)'
                            else:
                                print_v('Not searching {} any further due to no encryption support.'.format(filename))
                                continue

                        else:
                            if read_exh:
                                if ncch_flag_5 & 2:
                                    f.seek(0x4200)
                                    exh = f.read(0x400)
                                else:
                                    continue  # cfa does not have exheader
                            if read_smdh:
                                if exefs_offset != 0:
                                    f.seek(0x4000 + exefs_offset)
                                    exefs_header = f.read(0x200)
                                else:
                                    continue  # no exefs, no smdh

                        # get icon
                        if read_smdh:
                            exefs_files = [exefs_header[i:i + 0x10] for i in range(0, 0xA0, 0x10)]
                            icon_offset = 0
                            for en in exefs_files:
                                if en[0:8].rstrip(b'\0') == b'icon':
                                    icon_offset = int.from_bytes(en[8:12], 'little') + 0x200
                                    break
                            if icon_offset:
                                f.seek(0x4000 + exefs_offset + icon_offset)
                                icon = f.read(0x36C0)
                                if is_ncch_encrypted:
                                    ctr_exefs_icon = Counter.new(128, initial_value=ctr_exefs_value + (icon_offset >> 4))
                                    cipher_exefs_icon = AES.new(ncch_key_dev if uses_dev else ncch_key, AES.MODE_CTR, counter=ctr_exefs_icon)
                                    icon = cipher_exefs_icon.decrypt(icon)

                                if a.name:
                                    res = check_smdh(icon, a.name, 'name')
                                    if res:
                                        result['name'] = res
                                        matches = True
                                    else:
                                        continue

                                if a.strict_name:
                                    res = check_smdh(icon, a.strict_name, 'strict_name')
                                    if res:
                                        result['name'] = res
                                        matches = True
                                    else:
                                        continue

                                if a.publisher:
                                    res = check_smdh(icon, a.publisher, 'publisher')
                                    if res:
                                        result['publisher'] = res
                                        matches = True
                                    else:
                                        continue

                        if read_exh:
                            res = check_exh(exh, a.exh_name, 'appname')
                            if res:
                                result['appname'] = res
                                matches = True
                            else:
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

                        if a.product_code or read_exh or read_smdh:
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

                        if a.product_code or read_exh or read_smdh:
                            continue  # not relevant to a tmd

            # if still matches (mostly a failsafe), add it to the search results
            if matches:
                search_results[filename] = result

    except Exception as e:
        print('Exception occured when searching {}'.format(filename))
        if a.err:
            traceback.print_exception(type(e), e, e.__traceback__)
        else:
            print('  {}: {}'.format(type(e).__name__, e))


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
    if a.name or a.strict_name:
        header.append('Short Name')
        header.append('Long Name')
    if a.publisher:
        header.append('Publisher')
    if a.exh_name:
        header.append('ExH Name')
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
        if 'name' in result:
            line.append('{}: {}'.format(result['name'][0], result['name'][1]['short_name']))
            line.append('{}: {}'.format(result['name'][0], result['name'][1]['long_name']))
        if 'publisher' in result:
            line.append('{}: {}'.format(result['publisher'][0], result['publisher'][1]['publisher']))
        if 'appname' in result:
            line.append(result['appname'])
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
