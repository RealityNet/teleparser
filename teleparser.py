#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Telegram cache4 db parser.
# Part of the project: tblob.py tdb.py logger.py
#
# Version History
# - 20200418: change eol terminators, added requirements file
# - 20200407: [tblob] fixed a bug, [tdb] added a couple of checks base on
#             version 4.8.11, added small script to test/debug single blobs
# - 20200406: first public release (5.5.0, 5.6.2)
# - 20190729: first private release
#
# Released under MIT License
#
# Copyright (c) 2019 Francesco "dfirfpi" Picasso, Reality Net System Solutions
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
'''Telegram cache4 db parser, script entry point.'''

# pylint: disable= C0103,C0116

import argparse
import os
import sqlite3
import sys

import logger
import tblob
import tdb

VERSION = '20200418'

#------------------------------------------------------------------------------

def process(infilename, outdirectory):

    db_connection = None
    db_uri = 'file:' + infilename + '?mode=ro'

    tparse = tblob.tblob()

    with sqlite3.connect(db_uri, uri=True) as db_connection:
        db_connection.row_factory = sqlite3.Row
        db_cursor = db_connection.cursor()

        teledb = tdb.tdb(outdirectory, tparse, db_cursor)
        teledb.parse()

    teledb.save_parsed_tables()
    teledb.create_timeline()

#------------------------------------------------------------------------------

if __name__ == '__main__':

    if sys.version_info[0] < 3:
        sys.exit('Python 3 or a more recent version is required.')

    description = 'Telegram parser version {}'.format(VERSION)
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('infilename', help='input file cache4.db')
    parser.add_argument('outdirectory', help='output directory, must exist')
    parser.add_argument('-v', '--verbose', action='count',
                        help='verbose level, -v to -vvv')
    args = parser.parse_args()

    logger.configure_logging(args.verbose)

    if os.path.exists(args.infilename):
        if os.path.isdir(args.outdirectory):
            process(args.infilename, args.outdirectory)
        else:
            logger.error('Output directory [%s] does not exist!',
                         args.outdirectory)
    else:
        logger.error('The provided input file does not exist!')
