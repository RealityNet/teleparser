# -*- coding: utf-8 -*-
# pylint: disable= C0103,C0114,C0116

import re
import sys

with open(sys.argv[1], 'r') as jclass:
    prev_line = None
    for line in jclass:
        res = re.search('constructor = ([^;]+);', line)
        if res:
            value = int(res.group(1))
            value_hex = (value + (1 << 32)) % (1 << 32)
            res = re.search('class ([^ ]+) ', prev_line)
            if res:
                fn = res.group(1)
                fn = fn.replace('TL_', '', 1)
                fn = re.sub(r'([A-Z])', r'_\1', fn).lower()
                print('0x{:08x} : (None, \'{}\', None), # {}'.format(
                    value_hex, fn, value))
            else:
                sys.exit('Unexpected!')
        prev_line = line
