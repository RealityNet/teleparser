#!/usr/bin/python3
# -*- coding: utf-8 -*-

# pylint: disable=C0103,C0114

import sys
import tblob

with open(sys.argv[1], 'rb') as blob_file:
    tparser = tblob.tblob()
    blob = tparser.parse_blob(blob_file.read())
    print(blob)
