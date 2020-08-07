#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Telegram cache4 db parser, signatures file.
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
'''Telegram blobs parsing.'''

# pylint: disable=C0302,C0115,C0116,W0212,W0108,R0201,R0904

import datetime
from construct import * # pylint: disable=W0401,W0622,W0614
import logger

#------------------------------------------------------------------------------

def decode_tstring(binarray):
    try:
        str_utf = binarray.decode('utf-8')
    except UnicodeDecodeError:
        logger.error('unable to decode string: %s', binarray)
        str_utf = binarray
    return str_utf

#------------------------------------------------------------------------------

class tblob(): # pylint: disable=C0103

    #--------------------------------------------------------------------------

    tstring_struct = Struct(
        '_sname' /  Computed('tstring'),
        '_check' / Peek(Byte),
        '_pl' / IfThenElse(this._check >= 254, Int32ul, Byte),
        '_len' / IfThenElse(this._check >= 254,
                            Computed(this._pl >> 8),
                            Computed(this._pl)),
        #'value' / PaddedString(this._len, 'utf-8'),
        '_value' / Bytes(this._len),
        'string' / Computed(lambda x: decode_tstring(x._value)),
        IfThenElse(this._check >= 254,
                   If(this._len % 4, Padding(4 - this._len % 4)),
                   If((this._len + 1) % 4, Padding(4 - (this._len + 1) % 4))))

    tbytes_struct = Struct(
        '_sname' /  Computed('tbytes'),
        '_check' / Peek(Byte),
        '_pl' / IfThenElse(this._check >= 254, Int32ul, Byte),
        'len' / IfThenElse(this._check >= 254,
                           Computed(this._pl >> 8),
                           Computed(this._pl)),
        #'bytes' / Array(this.len, Byte),
        'bytes' / Hex(Bytes(this.len)),
        IfThenElse(this._check >= 254,
                   If(this.len % 4, Padding(4 - this.len % 4)),
                   If((this.len + 1) % 4, Padding(4 - (this.len + 1) % 4))))

    tbool_struct = Struct(
        'sname' / Computed('boolean'),
        '_signature' / Int32ul,
        'value' / IfThenElse(this._signature == 0xbc799737,
                             Computed('false'),
                             IfThenElse(this._signature == 0x997275b5,
                                        Computed('true'),
                                        Computed('ERROR'))))

    # This is not struct define by Telegram, but it's useful to get human
    # readable timestamps.
    ttimestamp_struct = Struct(
        'epoch' / Int32ul,
        'date' / Computed(lambda this: datetime.datetime.utcfromtimestamp(
            this.epoch).isoformat()))

    #--------------------------------------------------------------------------

    def __init__(self):
        setGlobalPrintFullStrings(True)
        setGlobalPrintPrivateEntries(False)
        self._callbacks = {}
        logger.debug('building callbacks ...')
        for signature, blob_tuple in tblob.tdss_callbacks.items():
            logger.debug('adding callback %s (%s)',
                         hex(signature), blob_tuple[1])
            self._callbacks[signature] = blob_tuple
        logger.debug('building callbacks ended')

    #--------------------------------------------------------------------------

    @property
    def callbacks(self):
        assert self._callbacks
        return self._callbacks

    #--------------------------------------------------------------------------

    def parse_blob(self, data):
        pblob = None
        signature = int.from_bytes(data[:4], 'little')
        if signature in self.callbacks:
            blob_parser, name, beautify = self.callbacks[signature]
            if blob_parser:
                pblob = blob_parser(self).parse(data)
                # Some structures has the 'UNPARSED' field to get the remaining
                # bytes. It's expected to get some of these cases (e.g. wrong
                # flags, it happens...) and I want everything to be in front of
                # the analyst. So, if UNPARSED has a length > 0, a warning
                # message is raised, but the missing data is in the blob.
                unparsed = getattr(pblob, 'UNPARSED', None)
                if unparsed:
                    unparsed_len = len(pblob.UNPARSED)
                    if unparsed_len:
                        logger.warning('Object: %s [0x%x] contains unparsed '
                                       'data [%d bytes], see UPARSED field',
                                       name, signature, unparsed_len)
                data_len = len(data)
                # In case the object has not (yet) the UNPARSED field, the next
                # check will raise and error and report the missed data. Note
                # that the missed data will be not reported in the blob.
                object_len = pblob._io.tell()
                if data_len != object_len:
                    logger.error('Not all data parsed for object: %s [0x%x], '
                                 'input: %d, parsed: %d, missed: %s',
                                 name, signature, data_len, object_len,
                                 data[object_len:])
                if beautify:
                    pass # [TBR] Actually not implemented.
            else:
                logger.warning('blob \'%s\' [%s] not supported',
                               name, hex(signature))
        else:
            logger.error('unknown signature %s', hex(signature))
        return pblob

    #--------------------------------------------------------------------------
    # TDSs implementation
    #--------------------------------------------------------------------------

    def audio_old2_struct(self):
        return Struct(
            'sname' / Computed('audio_old2'),
            'signature' / Hex(Const(0xc7ac6496, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'dc_id' / Int32ul)

    def audio_layer45_struct(self):
        return Struct(
            'sname' / Computed('audio_layer45'),
            'signature' / Hex(Const(0xf9e35055, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'dc_id' / Int32ul)

    def audio_old_struct(self):
        return Struct(
            'sname' / Computed('audio_old'),
            'signature' / Hex(Const(0x427425e7, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'size' / Int32ul,
            'dc_id' / Int32ul)

    def audio_encrypted_struct(self):
        return Struct(
            'sname' / Computed('audio_encrypted'),
            'signature' / Hex(Const(0x555555f6, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'size' / Int32ul,
            'dc_id' / Int32ul,
            'key' / self.tbytes_struct,
            'iv' / self.tbytes_struct)

    def audio_empty_layer45_struct(self):
        return Struct(
            'sname' / Computed('audio_empty_layer45'),
            'signature' / Hex(Const(0x586988d8, Int32ul)),
            'id' / Int64ul)

    def audio_structures(self, name):
        tag_map = {
            0xc7ac6496: LazyBound(lambda: self.audio_old2_struct()),
            0xf9e35055: LazyBound(lambda: self.audio_layer45_struct()),
            0x427425e7: LazyBound(lambda: self.audio_old_struct()),
            0x555555f6: LazyBound(lambda: self.audio_encrypted_struct()),
            0x586988d8: LazyBound(lambda: self.audio_empty_layer45_struct())
        }
        return 'audio_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def bot_command_struct(self):
        return Struct(
            'sname' / Computed('bot_command'),
            'signature' / Hex(Const(0xc27ac8c7, Int32ul)),
            'command' / self.tstring_struct,
            'description' / self.tstring_struct)

    #--------------------------------------------------------------------------

    def base_theme_night_struct(self):
        return Struct(
            'sname' / Computed('base_theme_night'),
            'signature' / Hex(Const(0xb7b31ea8, Int32ul)))

    def base_theme_classic_struct(self):
        return Struct(
            'sname' / Computed('base_theme_classic'),
            'signature' / Hex(Const(0xc3a12462, Int32ul)))

    def base_theme_day_struct(self):
        return Struct(
            'sname' / Computed('base_theme_day'),
            'signature' / Hex(Const(0xfbd81688, Int32ul)))

    def base_theme_arctic_struct(self):
        return Struct(
            'sname' / Computed('base_theme_arctic'),
            'signature' / Hex(Const(0x5b11125a, Int32ul)))

    def base_theme_tinted_struct(self):
        return Struct(
            'sname' / Computed('base_theme_tinted'),
            'signature' / Hex(Const(0x6d5f77ee, Int32ul)))

    def base_theme_structures(self, name):
        tag_map = {
            0xb7b31ea8: LazyBound(lambda: self.base_theme_night_struct()),
            0xc3a12462: LazyBound(lambda: self.base_theme_classic_struct()),
            0xfbd81688: LazyBound(lambda: self.base_theme_day_struct()),
            0x5b11125a: LazyBound(lambda: self.base_theme_arctic_struct()),
            0x6d5f77ee: LazyBound(lambda: self.base_theme_tinted_struct())
        }
        return 'base_theme_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def bot_info_struct(self):
        return Struct(
            'sname' / Computed('bot_info'),
            'signature' / Hex(Const(0x98e81d3a, Int32ul)),
            'user_id' / Int32ul,
            'description' / self.tstring_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'bot_commands_num' / Int32ul,
            'bot_commands_array' / Array(this.bot_commands_num,
                                         self.bot_command_struct()))

    def bot_info_layer48_struct(self):
        return Struct(
            'sname' / Computed('bot_info_layer48'),
            'signature' / Hex(Const(0x09cf585d, Int32ul)),
            'user_id' / Int32ul,
            'version' / Int32ul,
            'unknown' / self.tstring_struct,
            'description' / self.tstring_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'bot_commands_num' / Int32ul,
            'bot_commands_array' / Array(this.bot_commands_num,
                                         self.bot_command_struct()))

    def bot_info_empty_layer48_struct(self):
        return Struct(
            'sname' / Computed('bot_info_empty_layer48'),
            'signature' / Hex(Const(0xbb2e37ce, Int32ul)))

    def bot_info_structures(self, name):
        tag_map = {
            0x98e81d3a: LazyBound(lambda: self.bot_info_struct()),
            0xbb2e37ce: LazyBound(lambda: self.bot_info_empty_layer48_struct()),
            0x09cf585d: LazyBound(lambda: self.bot_info_layer48_struct())
        }
        return 'bot_info_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def channel_admin_rights_layer92_struct(self):
        return Struct(
            'sname' / Computed('channel_admin_rights_layer92'),
            'signature' / Hex(Const(0x5d7ceba5, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                change_info=1,
                                post_messages=2,
                                edit_messages=4,
                                delete_messages=8,
                                ban_users=16,
                                invite_users=32,
                                pin_messages=128,
                                add_admins=512,
                                manage_call=1024))

    def channel_banned_rights_layer92_struct(self):
        return Struct(
            'sname' / Computed('channel_banned_rights_layer92'),
            'signature' / Hex(Const(0x58cf4249, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                view_messages=1,
                                send_messages=2,
                                send_media=4,
                                send_stickers=8,
                                send_gifs=16,
                                send_games=32,
                                send_inline=64,
                                embed_links=128),
            'until_timestamp' / Int32ul)

    def chat_admin_rights_struct(self):
        return Struct(
            'sname' / Computed('chat_admin_rights'),
            'signature' / Hex(Const(0x5fb224d5, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                change_info=1,
                                post_messages=2,
                                edit_messages=4,
                                delete_messages=8,
                                ban_users=16,
                                invite_users=32,
                                pin_messages=128,
                                add_admins=512))

    def chat_banned_rights_struct(self):
        return Struct(
            'sname' / Computed('chat_banned_rights'),
            'signature' / Hex(Const(0x9f120418, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                view_messages=1,
                                send_messages=2,
                                send_media=4,
                                send_stickers=8,
                                send_gifs=16,
                                send_games=32,
                                send_inline=64,
                                embed_links=128,
                                send_polls=256,
                                change_info=1024,
                                invite_users=32768,
                                pin_messages=131072),
            'until_timestamp' / Int32ul)

    #--------------------------------------------------------------------------

    def chat_empty_struct(self):
        return Struct('sname' / Computed('chat_empty'),
                      'signature' / Hex(Const(0x9ba2d800, Int32ul)),
                      'id' / Int32ul,
                      'title' / Computed('DELETED'))

    def channel_forbidden_struct(self):
        return Struct(
            'sname' / Computed('channel_forbidden'),
            'signature' / Hex(Const(0x289da732, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                broadcast=32,
                                megagroup=256,
                                has_expiration=65536),
            'id' / Int32ul,
            'access_hash' / Int64ul,
            'title' / self.tstring_struct,
            'util_timestamp' / If(this.flags.has_expiration, Int32ul))

    def channel_forbidden_layer52_struct(self):
        return Struct(
            'sname' / Computed('channel_forbidden_layer52'),
            'signature' / Hex(Const(0x2d85832c, Int32ul)),
            'id' / Int32ul,
            'access_hash' / Int64ul,
            'title' / self.tstring_struct)

    def channel_forbidden_layer67_struct(self):
        return Struct(
            'sname' / Computed('channel_forbidden_layer67'),
            'signature' / Hex(Const(0x8537784f, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                broadcast=32,
                                megagroup=256),
            'id' / Int32ul,
            'access_hash' / Int64ul,
            'title' / self.tstring_struct)

    def channel_layer104_struct(self):
        return Struct(
            'sname' / Computed('channel_layer104'),
            'signature' / Hex(Const(0x4df30834, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                left=4,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_admin_rights=16384,
                                has_banned_rights=32768,
                                has_participant_count=131072,
                                has_access_hash=8192,
                                scam=524288),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.chat_admin_rights_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.chat_banned_rights_struct()),
            'participants_count' / If(this.flags.has_participant_count,
                                      Int32ul))

    def channel_old_struct(self):
        return Struct(
            'sname' / Computed('channel_old'),
            'signature' / Hex(Const(0x678e9587, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                moderator=16,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                explicit_content=512),
            'id' / Int32ul,
            'access_hash' / Int64ul,
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul)

    def channel_layer48_struct(self):
        return Struct(
            'sname' / Computed('channel_layer48'),
            'signature' / Hex(Const(0x4b1b7506, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                moderator=16,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_access_hash=8192),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct))

    def channel_layer67_struct(self):
        return Struct(
            'sname' / Computed('channel_layer67'),
            'signature' / Hex(Const(0xa14dca52, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                moderator=16,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_access_hash=8192),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct))

    def channel_layer72_struct(self):
        return Struct(
            'sname' / Computed('channel_layer72'),
            'signature' / Hex(Const(0x0cb44b1c, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                left=4,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_admin_rights=16384,
                                has_banned_rights=32768,
                                has_access_hash=8192),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.channel_admin_rights_layer92_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.channel_banned_rights_layer92_struct()))

    def channel_layer77_struct(self):
        return Struct(
            'sname' / Computed('channel_layer77'),
            'signature' / Hex(Const(0x450b7115, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                left=4,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_admin_rights=16384,
                                has_banned_rights=32768,
                                has_participant_count=131072,
                                has_access_hash=8192),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.channel_admin_rights_layer92_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.channel_banned_rights_layer92_struct()),
            'participants_count' / If(this.flags.has_participant_count,
                                      Int32ul))

    def channel_layer92_struct(self):
        return Struct(
            'sname' / Computed('channel_layer92'),
            'signature' / Hex(Const(0xc88974ac, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                left=4,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_admin_rights=16384,
                                has_banned_rights=32768,
                                has_participant_count=131072,
                                has_access_hash=8192),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reason' / If(this.flags.restricted, self.tstring_struct),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.channel_admin_rights_layer92_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.channel_banned_rights_layer92_struct()),
            'participants_count' / If(this.flags.has_participant_count,
                                      Int32ul))

    def channel_struct(self):
        return Struct(
            'sname' / Computed('channel'),
            'signature' / Hex(Const(0xd31a961e, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                left=4,
                                broadcast=32,
                                has_username=64,
                                verified=128,
                                megagroup=256,
                                restricted=512,
                                signatures=2048,
                                is_min=4096,
                                has_access_hash=8192,
                                has_admin_rights=16384,
                                has_banned_rights=32768,
                                has_participant_count=131072,
                                is_scam=524288,
                                has_link=1048576,
                                has_geo=2097152,
                                is_slowmode_enabled=4194304),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'title' / self.tstring_struct,
            'username' / If(this.flags.has_username, self.tstring_struct),
            'photo' / self.chat_photo_structures('photo'),
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'restrict_reasons' / If(this.flags.restricted, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'restrict_reasons_num' / Int32ul,
                'restrict_reasons_array' / Array(
                    this.restrict_reasons_num,
                    self.restriction_reason_struct()))),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.chat_admin_rights_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.chat_banned_rights_struct()),
            'participants_count' / If(this.flags.has_participant_count,
                                      Int32ul))

    def chat_struct(self):
        return Struct(
            'sname' / Computed('chat'),
            'signature' / Hex(Const(0x3bda1bde, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                deactivated=32,
                                is_migrated=64,
                                has_admin_rights=16384,
                                has_banned_rights=262144),
            'id' / Int32ul,
            'title' / self.tstring_struct,
            'photo' / self.chat_photo_structures('photo'),
            'participants_count' / Int32ul,
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'migrated_to' / If(this.flags.is_migrated,
                               self.input_channel_structures('migrated_to')),
            'admin_rights' / If(this.flags.has_admin_rights,
                                self.chat_admin_rights_struct()),
            'banned_rights' / If(this.flags.has_banned_rights,
                                 self.chat_banned_rights_struct()))

    def chat_old_struct(self):
        return Struct(
            'sname' / Computed('chat_old'),
            'signature' / Hex(Const(0x6e9c9bc7, Int32ul)),
            'id' / Int32ul,
            'title' / self.tstring_struct,
            'photo' / self.chat_photo_structures('photo'),
            'participants_count' / Int32ul,
            'date' / self.ttimestamp_struct,
            'left' / self.tbool_struct,
            'version' / Int32ul)

    def chat_old2_struct(self):
        return Struct(
            'sname' / Computed('chat_old2'),
            'signature' / Hex(Const(0x7312bc48, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                deactivated=32),
            'id' / Int32ul,
            'title' / self.tstring_struct,
            'photo' / self.chat_photo_structures('photo'),
            'participants_count' / Int32ul,
            'date' / self.ttimestamp_struct,
            'version' / Int32ul)

    def chat_forbidden_struct(self):
        return Struct(
            'sname' / Computed('chat_forbidden'),
            'signature' / Hex(Const(0x07328bdb, Int32ul)),
            'id' / Int32ul,
            'title' / self.tstring_struct)

    def chat_forbidden_old_struct(self):
        return Struct(
            'sname' / Computed('chat_forbidden_old'),
            'signature' / Hex(Const(0xfb0ccc41, Int32ul)),
            'id' / Int32ul,
            'title' / self.tstring_struct,
            'date' / Int32ul)

    def chat_layer92_struct(self):
        return Struct(
            'sname' / Computed('chat_layer92'),
            'signature' / Hex(Const(0xd91cdd54, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                kicked=2,
                                left=4,
                                deactivated=32,
                                is_migrated=64),
            'id' / Int32ul,
            'title' / self.tstring_struct,
            'photo' / self.chat_photo_structures('photo'),
            'participants_count' / Int32ul,
            'date' / self.ttimestamp_struct,
            'version' / Int32ul,
            'migrated_to' / If(this.flags.is_migrated,
                               self.input_channel_structures('migrated_to')))

    def chat_structures(self, name):
        tag_map = {
            0xd31a961e: LazyBound(lambda: self.channel_struct()),
            0x8537784f: LazyBound(lambda: self.channel_forbidden_layer67_struct()),
            0x9ba2d800: LazyBound(lambda: self.chat_empty_struct()),
            0xa14dca52: LazyBound(lambda: self.channel_layer67_struct()),
            0xc88974ac: LazyBound(lambda: self.channel_layer92_struct()),
            0xd91cdd54: LazyBound(lambda: self.chat_layer92_struct()),
            0xfb0ccc41: LazyBound(lambda: self.chat_forbidden_old_struct()),
            0x07328bdb: LazyBound(lambda: self.chat_forbidden_struct()),
            0x0cb44b1c: LazyBound(lambda: self.channel_layer72_struct()),
            0x289da732: LazyBound(lambda: self.channel_forbidden_struct()),
            0x2d85832c: LazyBound(lambda: self.channel_forbidden_layer52_struct()),
            0x3bda1bde: LazyBound(lambda: self.chat_struct()),
            0x450b7115: LazyBound(lambda: self.channel_layer77_struct()),
            0x4b1b7506: LazyBound(lambda: self.channel_layer48_struct()),
            0x4df30834: LazyBound(lambda: self.channel_layer104_struct()),
            0x678e9587: LazyBound(lambda: self.channel_old_struct()),
            0x6e9c9bc7: LazyBound(lambda: self.chat_old_struct()),
            0x7312bc48: LazyBound(lambda: self.chat_old2_struct())
        }
        return 'chat_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def chat_photo_layer115_struct(self):
        return Struct(
            'sname' / Computed('chat_photo_layer115'),
            'signature' / Hex(Const(0x475cdbd5, Int32ul)),
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'),
            'dc_id' / Int32ul)

    def chat_photo_empty_struct(self):
        return Struct('sname' / Computed('chat_photo_empty'),
                      'signature' / Hex(Const(0x37c1011c, Int32ul)))

    def chat_photo_layer97_struct(self):
        return Struct(
            'sname' / Computed('chat_photo_layer97'),
            'signature' / Hex(Const(0x6153276a, Int32ul)),
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'))

    def chat_photo_struct(self):
        return Struct(
            'sname' / Computed('chat_photo'),
            'signature' / Hex(Const(0xd20b9f3c, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_video=1,),
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'),
            'dc_id' / Int32ul)

    def chat_photo_structures(self, name):
        tag_map = {
            0x37c1011c: LazyBound(lambda: self.chat_photo_empty_struct()),
            0x6153276a: LazyBound(lambda: self.chat_photo_layer97_struct()),
            0x475cdbd5: LazyBound(lambda: self.chat_photo_layer115_struct()),
            0xd20b9f3c: LazyBound(lambda: self.chat_photo_struct())
        }
        return 'chat_photo_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def contact_link_contact_struct(self):
        return Struct(
            'sname' / Computed('contact_link_contact'),
            'signature' / Hex(Const(0xd502c2d0, Int32ul)))

    def contact_link_none_struct(self):
        return Struct(
            'sname' / Computed('contact_link_none'),
            'signature' / Hex(Const(0xfeedd3ad, Int32ul)))

    def contact_link_has_phone_struct(self):
        return Struct(
            'sname' / Computed('contact_link_has_phone'),
            'signature' / Hex(Const(0x268f3f59, Int32ul)))

    def contact_link_unknown_struct(self):
        return Struct(
            'sname' / Computed('contact_link_unknown'),
            'signature' / Hex(Const(0x5f4f9247, Int32ul)))

    def contact_link_structures(self, name):
        tag_map = {
            0xd502c2d0: LazyBound(lambda: self.contact_link_contact_struct()),
            0xfeedd3ad: LazyBound(lambda: self.contact_link_none_struct()),
            0x268f3f59: LazyBound(lambda: self.contact_link_has_phone_struct()),
            0x5f4f9247: LazyBound(lambda: self.contact_link_unknown_struct())
        }
        return 'contact_link_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    def contacts_link_layer101_struct(self):
        return Struct(
            'sname' / Computed('contacts_link_layer101'),
            'signature' / Hex(Const(0x3ace484c, Int32ul)),
            'my_link' / self.contact_link_structures('my_link'),
            'foreign_link' / self.contact_link_structures('foreign_link'),
            'user' / self.user_structures('user'))

    #--------------------------------------------------------------------------

    def decrypted_message_action_set_message_ttl_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_set_message_ttl'),
            'signature' / Hex(Const(0xa1733aec, Int32ul)),
            'ttl_seconds' / Int32ul)

    def decrypted_message_action_screenshot_messages_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_screenshot_messages'),
            'signature' / Hex(Const(0x8ac1f475, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'random_ids_num' / Int32ul,
            'random_ids_array' / Array(this.random_ids_num, Int64ul))

    def decrypted_message_action_noop_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_noop'),
            'signature' / Hex(Const(0xa82fdd63, Int32ul)))

    def decrypted_message_action_typing_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_typing'),
            'signature' / Hex(Const(0xccb27641, Int32ul)),
            'action' / self.send_message_action_structures('action'))

    def decrypted_message_action_abort_key_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_abort_key'),
            'signature' / Hex(Const(0xdd05ec6b, Int32ul)),
            'exchange_id' / Int64ul)

    def decrypted_message_action_commit_key_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_commit_key'),
            'signature' / Hex(Const(0xec2e0b9b, Int32ul)),
            'exchange_id' / Int64ul,
            'key_fingerprint' / Int64ul)

    def decrypted_message_action_notify_layer_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_notify_layer'),
            'signature' / Hex(Const(0xf3048883, Int32ul)),
            'layer' / Int32ul)

    def decrypted_message_action_request_key_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_request_key'),
            'signature' / Hex(Const(0xf3c9611b, Int32ul)),
            'exchange_id' / Int64ul,
            'g_a' / self.tbytes_struct)

    def decrypted_message_action_read_messages_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_read_messages'),
            'signature' / Hex(Const(0x0c4f40be, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'random_ids_num' / Int32ul,
            'random_ids_array' / Array(this.random_ids_num, Int64ul))

    def decrypted_message_action_resend_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_resend'),
            'signature' / Hex(Const(0x511110b0, Int32ul)),
            'start_seq_no' / Int32ul,
            'end_seq_no' / Int32ul)

    def decrypted_message_action_delete_messages_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_delete_messages'),
            'signature' / Hex(Const(0x65614304, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'random_ids_num' / Int32ul,
            'random_ids_array' / Array(this.random_ids_num, Int64ul))

    def decrypted_message_action_flush_history_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_flush_history'),
            'signature' / Hex(Const(0x6719e45c, Int32ul)))

    def decrypted_message_action_accept_key_struct(self):
        return Struct(
            'sname' / Computed('decrypted_message_action_accept_key'),
            'signature' / Hex(Const(0x6fe1735b, Int32ul)),
            'exchange_id' / Int64ul,
            'g_b' / self.tbytes_struct,
            'key_fingerprint' / Int64ul)

    def decrypted_message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x8ac1f475: LazyBound(lambda: self.decrypted_message_action_screenshot_messages_struct()),
            0xa82fdd63: LazyBound(lambda: self.decrypted_message_action_noop_struct()),
            0xccb27641: LazyBound(lambda: self.decrypted_message_action_typing_struct()),
            0xdd05ec6b: LazyBound(lambda: self.decrypted_message_action_abort_key_struct()),
            0xec2e0b9b: LazyBound(lambda: self.decrypted_message_action_commit_key_struct()),
            0xf3048883: LazyBound(lambda: self.decrypted_message_action_notify_layer_struct()),
            0xf3c9611b: LazyBound(lambda: self.decrypted_message_action_request_key_struct()),
            0x0c4f40be: LazyBound(lambda: self.decrypted_message_action_read_messages_struct()),
            0x511110b0: LazyBound(lambda: self.decrypted_message_action_resend_struct()),
            0x65614304: LazyBound(lambda: self.decrypted_message_action_delete_messages_struct()),
            0x6719e45c: LazyBound(lambda: self.decrypted_message_action_flush_history_struct()),
            0x6fe1735b: LazyBound(lambda: self.decrypted_message_action_accept_key_struct()),
            0xa1733aec: LazyBound(lambda: self.decrypted_message_action_set_message_ttl_struct())
        }
        return 'decrypted_message_action_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def document_attribute_has_stickers_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_has_stickers'),
            'signature' / Hex(Const(0x9801d2f7, Int32ul)))

    def document_attribute_sticker_old_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_sticker_old'),
            'signature' / Hex(Const(0xfb0a5727, Int32ul)),
            'alt' / self.tstring_struct)

    def document_attribute_sticker_old2_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_sticker_old2'),
            'signature' / Hex(Const(0x994c9882, Int32ul)),
            'alt' / self.tstring_struct)

    def document_attribute_audio_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_audio'),
            'signature' / Hex(Const(0x9852f9c6, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_title=1,
                                has_performer=2,
                                has_waveform=4,
                                is_voice=1024),
            'duration' / Int32ul,
            'title' / If(this.flags.has_title, self.tstring_struct),
            'performer' / If(this.flags.has_performer, self.tstring_struct),
            'waveform' / If(this.flags.has_waveform, self.tbytes_struct))

    def document_attribute_audio_layer45_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_audio_layer45'),
            'signature' / Hex(Const(0xded218e0, Int32ul)),
            'duration' / Int32ul,
            'title' / self.tstring_struct,
            'performer' / self.tstring_struct)

    def document_attribute_audio_old_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_audio_old'),
            'signature' / Hex(Const(0x051448e5, Int32ul)),
            'duration' / Int32ul)

    def document_attribute_video_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_video'),
            'signature' / Hex(Const(0x0ef02ce6, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                round_message=1,
                                supports_streaming=2),
            'duration' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def document_attribute_animated_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_animated'),
            'signature' / Hex(Const(0x11b58939, Int32ul)))

    def document_attribute_filename_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_filename'),
            'signature' / Hex(Const(0x15590068, Int32ul)),
            'file_name' / self.tstring_struct)

    def document_attribute_sticker_layer55_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_sticker_layer55'),
            'signature' / Hex(Const(0x3a556302, Int32ul)),
            'alt' / self.tstring_struct,
            'sticker_set' / self.input_sticker_set_structures('sticker_set'))

    def document_attribute_video_layer65_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_video_layer65'),
            'signature' / Hex(Const(0x5910cccb, Int32ul)),
            'duration' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def document_attribute_sticker_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_sticker'),
            'signature' / Hex(Const(0x6319d612, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_mask_coords=1,
                                mask=2),
            'alt' / self.tstring_struct,
            'sticker_set' / self.input_sticker_set_structures('sticker_set'),
            'mask_coords' / If(this.flags.has_mask_coords, self.mask_coords_struct()))

    def document_attribute_image_size_struct(self):
        return Struct(
            'sname' / Computed('document_attribute_image_size'),
            'signature' / Hex(Const(0x6c37c15c, Int32ul)),
            'w' / Int32ul,
            'h' / Int32ul)

    def document_attribute_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x9801d2f7: LazyBound(lambda: self.document_attribute_has_stickers_struct()),
            0x9852f9c6: LazyBound(lambda: self.document_attribute_audio_struct()),
            0x994c9882: LazyBound(lambda: self.document_attribute_sticker_old2_struct()),
            0xded218e0: LazyBound(lambda: self.document_attribute_audio_layer45_struct()),
            0xfb0a5727: LazyBound(lambda: self.document_attribute_sticker_old_struct()),
            0x051448e5: LazyBound(lambda: self.document_attribute_audio_old_struct()),
            0x0ef02ce6: LazyBound(lambda: self.document_attribute_video_struct()),
            0x11b58939: LazyBound(lambda: self.document_attribute_animated_struct()),
            0x15590068: LazyBound(lambda: self.document_attribute_filename_struct()),
            0x3a556302: LazyBound(lambda: self.document_attribute_sticker_layer55_struct()),
            0x5910cccb: LazyBound(lambda: self.document_attribute_video_layer65_struct()),
            0x6319d612: LazyBound(lambda: self.document_attribute_sticker_struct()),
            0x6c37c15c: LazyBound(lambda: self.document_attribute_image_size_struct())
        }
        return 'document_attribute_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def document_empty_struct(self):
        return Struct('sname' / Computed('document_empty'),
                      'signature' / Hex(Const(0x36f8c871, Int32ul)),
                      'id' / Int64ul)

    def document_layer82_struct(self):
        return Struct(
            'sname' / Computed('document_layer82'),
            'signature' / Hex(Const(0x87232bc7, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            '_pad' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')))

    def document_layer113_struct(self):
        return Struct(
            'sname' / Computed('document_layer113'),
            'signature' / Hex(Const(0x9ba29cc1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_photo_size=1,
                                mask=2),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'photo_size' / If(this.flags.has_photo_size, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'photo_sizes_num' / Int32ul,
                'photo_sizes_array' / Array(
                    this.photo_sizes_num,
                    self.photo_size_structures('photo')))),
            'dc_id' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')))

    def document_old_struct(self):
        return Struct(
            'sname' / Computed('document_old'),
            'signature' / Hex(Const(0x9efc6326, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'file_name' / self.tstring_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul)

    def document_layer53_struct(self):
        return Struct(
            'sname' / Computed('document_layer53'),
            'signature' / Hex(Const(0xf9a39f4f, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')))

    def document_encrypted_old_struct(self):
        return Struct(
            'sname' / Computed('document_encrypted_old'),
            'signature' / Hex(Const(0x55555556, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'file_name' / self.tstring_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'key' / self.tbytes_struct,
            'iv' / self.tbytes_struct)

    def document_encrypted_struct(self):
        return Struct(
            'sname' / Computed('document_encrypted'),
            'signature' / Hex(Const(0x55555558, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')),
            'key' / self.tbytes_struct,
            'iv' / self.tbytes_struct)

    def document_layer92_struct(self):
        return Struct(
            'sname' / Computed('document_layer92'),
            'signature' / Hex(Const(0x59534e4c, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')))

    def document_struct(self):
        return Struct(
            'sname' / Computed('document'),
            'signature' / Hex(Const(0x1e87342b, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_photo_size=1,
                                has_video_size=2),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'photo_size' / If(this.flags.has_photo_size, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'photo_sizes_num' / Int32ul,
                'photo_sizes_array' / Array(
                    this.photo_sizes_num,
                    self.photo_size_structures('photo_size')))),
            'video_size' / If(this.flags.has_video_size, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'video_sizes_num' / Int32ul,
                'video_sizes_array' / Array(
                    this.video_sizes_num,
                    self.video_size_structures('video_size')))),
            'dc_id' / Int32ul,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes_array' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document')))

    def document_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x1e87342b: LazyBound(lambda: self.document_struct()),
            0x87232bc7: LazyBound(lambda: self.document_layer82_struct()),
            0x9ba29cc1: LazyBound(lambda: self.document_layer113_struct()),
            0x9efc6326: LazyBound(lambda: self.document_old_struct()),
            0xf9a39f4f: LazyBound(lambda: self.document_layer53_struct()),
            0x36f8c871: LazyBound(lambda: self.document_empty_struct()),
            0x55555556: LazyBound(lambda: self.document_encrypted_old_struct()),
            0x55555558: LazyBound(lambda: self.document_encrypted_struct()),
            0x59534e4c: LazyBound(lambda: self.document_layer92_struct())
        }
        return 'document_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def encrypted_chat_empty_struct(self):
        return Struct('sname' / Computed('encrypted_chat_empty'),
                      'signature' / Hex(Const(0xab7ec0a0, Int32ul)),
                      'id' / Int32ul)

    def encrypted_chat_requested_struct(self):
        return Struct('sname' / Computed('encrypted_chat_requested'),
                      'signature' / Hex(Const(0x62718a82, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          has_folder_is=1),
                      'folder_id' / If(this.flags.has_folder_id, Int32ul),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul,
                      'g_a' / self.tbytes_struct)

    def encrypted_chat_requested_layer115_struct(self):
        return Struct('sname' / Computed('encrypted_chat_requested_layer115'),
                      'signature' / Hex(Const(0xc878527e, Int32ul)),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul,
                      'g_a' / self.tbytes_struct)

    def encrypted_chat_struct(self):
        return Struct('sname' / Computed('encrypted_chat'),
                      'signature' / Hex(Const(0xfa56ce36, Int32ul)),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul,
                      'g_a_or_b' / self.tbytes_struct,
                      'key_fingerprint' / Int64ul)

    def encrypted_chat_requested_old_struct(self):
        return Struct('sname' / Computed('encrypted_chat_requested_old'),
                      'signature' / Hex(Const(0xfda9a7b7, Int32ul)),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul,
                      'g_a' / self.tbytes_struct,
                      'nonce' / self.tbytes_struct)

    def encrypted_chat_discarded_struct(self):
        return Struct('sname' / Computed('encrypted_chat_discarded'),
                      'signature' / Hex(Const(0x13d6dd27, Int32ul)),
                      'id' / Int32ul)

    def encrypted_chat_waiting_struct(self):
        return Struct('sname' / Computed('encrypted_chat_waiting'),
                      'signature' / Hex(Const(0x3bf703dc, Int32ul)),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul)

    def encrypted_chat_old_struct(self):
        return Struct('sname' / Computed('encrypted_chat_old'),
                      'signature' / Hex(Const(0x6601d14f, Int32ul)),
                      'id' / Int32ul,
                      'access_hash' / Int64ul,
                      'date' / self.ttimestamp_struct,
                      'admin_id' / Int32ul,
                      'participant_id' / Int32ul,
                      'g_a_or_b' / self.tbytes_struct,
                      'nonce' / self.tbytes_struct,
                      'key_fingerprint' / Int64ul)

    def encrypted_chat_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x62718a82: LazyBound(lambda: self.encrypted_chat_requested_struct()),
            0xab7ec0a0: LazyBound(lambda: self.encrypted_chat_empty_struct()),
            0xc878527e: LazyBound(lambda: self.encrypted_chat_requested_layer115_struct()),
            0xfa56ce36: LazyBound(lambda: self.encrypted_chat_struct()),
            0xfda9a7b7: LazyBound(lambda: self.encrypted_chat_requested_old_struct()),
            0x13d6dd27: LazyBound(lambda: self.encrypted_chat_discarded_struct()),
            0x3bf703dc: LazyBound(lambda: self.encrypted_chat_waiting_struct()),
            0x6601d14f: LazyBound(lambda: self.encrypted_chat_old_struct())
        }
        return 'encrypted_chat_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def file_location_struct(self):
        return Struct('sname' / Computed('file_location'),
                      'signature' / Hex(Const(0x53d69076, Int32ul)),
                      'dc_id' / Int32ul,
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul,
                      'secret' / Int64ul)

    def file_encrypted_location_struct(self):
        return Struct('sname' / Computed('file_encrypted_location'),
                      'signature' / Hex(Const(0x55555554, Int32ul)),
                      'dc_id' / Int32ul,
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul,
                      'secret' / Int64ul,
                      'key' / self.tbytes_struct,
                      'iv' / self.tbytes_struct)

    def file_location_unavailable_struct(self):
        return Struct('sname' / Computed('file_location_unavailable'),
                      'signature' / Hex(Const(0x7c596b46, Int32ul)),
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul,
                      'secret' / Int64ul)

    def file_location_layer82_struct(self):
        return Struct('sname' / Computed('file_location'),
                      'signature' / Hex(Const(0x53d69076, Int32ul)),
                      'dc_id' / Int32ul,
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul,
                      'secret' / Int64ul)

    def file_location_layer97_struct(self):
        return Struct('sname' / Computed('file_location_layer97'),
                      'signature' / Hex(Const(0x091d11eb, Int32ul)),
                      'dc_id' / Int32ul,
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul,
                      'secret' / Int64ul,
                      'file_reference' / self.tbytes_struct)

    def file_location_to_be_deprecated_struct(self):
        return Struct('sname' / Computed('file_location_to_be_deprecated'),
                      'signature' / Hex(Const(0xbc7fc6cd, Int32ul)),
                      'volume_id' / Int64ul,
                      'local_id' / Int32ul)

    def file_location_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xbc7fc6cd: LazyBound(lambda: self.file_location_to_be_deprecated_struct()),
            0x091d11eb: LazyBound(lambda: self.file_location_layer97_struct()),
            0x53d69076: LazyBound(lambda: self.file_location_layer82_struct()),
            0x55555554: LazyBound(lambda: self.file_encrypted_location_struct()),
            0x7c596b46: LazyBound(lambda: self.file_location_unavailable_struct())
        }
        return 'file_location_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def game_struct(self):
        return Struct('sname' / Computed('game'),
                      'signature' / Hex(Const(0xbdf9653b, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          has_document=1),
                      'id' / Int64ul,
                      'access_hash' / Int64ul,
                      'short_name' / self.tstring_struct,
                      'title' / self.tstring_struct,
                      'description' / self.tstring_struct,
                      'photo' / self.photo_structures('photo'),
                      'document' / If(this.flags.has_document,
                                      self.document_structures('document')))

    #--------------------------------------------------------------------------

    def geo_point_empty_struct(self):
        return Struct('sname' / Computed('geo_point_empty'),
                      'signature' / Hex(Const(0x1117dd5f, Int32ul)))

    def geo_point_struct(self):
        return Struct('sname' / Computed('geo_point'),
                      'signature' / Hex(Const(0x0296f104, Int32ul)),
                      'long' / Float64b,
                      'lat' / Float64b,
                      'access_hash' / Int64ul)

    def geo_point_layer81_struct(self):
        return Struct('sname' / Computed('geo_point_layer81'),
                      'signature' / Hex(Const(0x2049d70c, Int32ul)),
                      'long' / Float64b,
                      'lat' / Float64b)

    def geo_point_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x0296f104: LazyBound(lambda: self.geo_point_struct()),
            0x1117dd5f: LazyBound(lambda: self.geo_point_empty_struct()),
            0x2049d70c: LazyBound(lambda: self.geo_point_layer81_struct())
        }
        return 'geo_point_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def input_channel_struct(self):
        return Struct('sname' / Computed('input_channel'),
                      'signature' / Hex(Const(0xafeb712e, Int32ul)),
                      'channel_id' / Int32ul,
                      'access_hash' / Int64ul)

    def input_channel_empty_struct(self):
        return Struct('sname' / Computed('input_channel_empty'),
                      'signature' / Hex(Const(0xee8c1e86, Int32ul)))

    def input_channel_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xafeb712e: LazyBound(lambda: self.input_channel_struct()),
            0xee8c1e86: LazyBound(lambda: self.input_channel_empty_struct())
        }
        return 'input_channel_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def input_group_call_struct(self):
        return Struct(
            'sname' / Computed('input_group_call'),
            'signature' / Hex(Const(0xd8aa840f, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul)

    #--------------------------------------------------------------------------

    def input_message_entity_mention_name_struct(self):
        return Struct(
            'sname' / Computed('input_message_entity_mention_name'),
            'signature' / Hex(Const(0x208e68c9, Int32ul)),
            'offset' / Int32ul,
            'length' / Int32ul,
            'user_id' / self.input_user_struct())

    #--------------------------------------------------------------------------

    def input_sticker_set_animated_emoji_struct(self):
        return Struct(
            'sname' / Computed('input_sticker_set_animated_emoji'))

    def input_sticker_set_dice_struct(self):
        return Struct(
            'sname' / Computed('input_sticker_set_dice'),
            'signature' / Hex(Const(0xe67f520e, Int32ul)),
            'emoticon' / self.tstring_struct)

    def input_sticker_set_empty_struct(self):
        return Struct(
            'sname' / Computed('input_sticker_set_empty'),
            'signature' / Hex(Const(0xffb62b95, Int32ul)))

    def input_sticker_set_id_struct(self):
        return Struct(
            'sname' / Computed('input_sticker_set_id'),
            'signature' / Hex(Const(0x9de7a269, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul)

    def input_sticker_set_short_name_struct(self):
        return Struct(
            'sname' / Computed('input_sticker_set_short_name'),
            'signature' / Hex(Const(0x861cc8a0, Int32ul)),
            'short_name' / self.tstring_struct)

    def input_sticker_set_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x028703c8: LazyBound(lambda: self.input_sticker_set_animated_emoji_struct()),
            0xe67f520e: LazyBound(lambda: self.input_sticker_set_dice_struct()),
            0xffb62b95: LazyBound(lambda: self.input_sticker_set_empty_struct()),
            0x9de7a269: LazyBound(lambda: self.input_sticker_set_id_struct()),
            0x861cc8a0: LazyBound(lambda: self.input_sticker_set_short_name_struct())
        }
        return 'input_sticker_set_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def input_user_empty_struct(self):
        return Struct(
            'sname' / Computed('input_user_empty'),
            'signature' / Hex(Const(0xb98886cf, Int32ul)))

    def input_user_struct(self):
        return Struct(
            'sname' / Computed('input_user'),
            'signature' / Hex(Const(0xd8292816, Int32ul)),
            'user_id' / Int32ul,
            'access_hash' / Int64ul)

    #--------------------------------------------------------------------------

    def keyboard_button_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button'),
            'signature' / Hex(Const(0xa2fa4880, Int32ul)),
            'text' / self.tstring_struct)

    def keyboard_button_buy_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_buy'),
            'signature' / Hex(Const(0xafd93fbb, Int32ul)),
            'text' / self.tstring_struct)

    def keyboard_button_request_phone_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_request_phone'),
            'signature' / Hex(Const(0xb16a6c29, Int32ul)),
            'text' / self.tstring_struct)

    def keyboard_button_request_poll_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_request_poll'),
            'signature' / Hex(Const(0xbbc7515d, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_quiz=1),
            'quiz' / If(this.flags.has_quiz, self.tbool_struct),
            'text' / self.tstring_struct)

    def keyboard_button_request_geo_location_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_request_geo_location'),
            'signature' / Hex(Const(0xfc796b3f, Int32ul)),
            'text' / self.tstring_struct)

    def keyboard_button_switch_inline_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_switch_inline'),
            'signature' / Hex(Const(0x0568a748, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                same_peer=1),
            'text' / self.tstring_struct,
            'query' / self.tstring_struct)

    def keyboard_button_url_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_url'),
            'signature' / Hex(Const(0x258aff05, Int32ul)),
            'text' / self.tstring_struct,
            'url' / self.tstring_struct)

    def keyboard_button_url_auth_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_url_auth'),
            'signature' / Hex(Const(0x10b78d29, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_fwd_text=1),
            'text' / self.tstring_struct,
            'fwd_text' / If(this.flags.has_fwd_text, self.tstring_struct),
            'url' / self.tstring_struct,
            'button_id' / Int32ul)

    def keyboard_button_game_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_game'),
            'signature' / Hex(Const(0x50f41ccf, Int32ul)),
            'text' / self.tstring_struct)

    def keyboard_button_callback_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_callback'),
            'signature' / Hex(Const(0x683a5e46, Int32ul)),
            'text' / self.tstring_struct,
            'data' / self.tbytes_struct)

    def keyboard_button_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x10b78d29: LazyBound(lambda: self.keyboard_button_url_auth_struct()),
            0xbbc7515d: LazyBound(lambda: self.keyboard_button_request_poll_struct()),
            0xa2fa4880: LazyBound(lambda: self.keyboard_button_struct()),
            0xafd93fbb: LazyBound(lambda: self.keyboard_button_buy_struct()),
            0xb16a6c29: LazyBound(lambda: self.keyboard_button_request_phone_struct()),
            0xfc796b3f: LazyBound(lambda: self.keyboard_button_request_geo_location_struct()),
            0x0568a748: LazyBound(lambda: self.keyboard_button_switch_inline_struct()),
            0x258aff05: LazyBound(lambda: self.keyboard_button_url_struct()),
            0x50f41ccf: LazyBound(lambda: self.keyboard_button_game_struct()),
            0x683a5e46: LazyBound(lambda: self.keyboard_button_callback_struct())
        }
        return 'keyboard_button_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    def keyboard_button_row_struct(self):
        return Struct(
            'sname' / Computed('keyboard_button_row'),
            'signature' / Hex(Const(0x77608b83, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'keyboard_buttons_row_num' / Int32ul,
            'keyboard_buttons_row_array' / Array(
                this.keyboard_buttons_row_num,
                self.keyboard_button_structures('keyboard_button')))

    #--------------------------------------------------------------------------

    def mask_coords_struct(self):
        return Struct(
            'sname' / Computed('mask_coords'),
            'signature' / Hex(Const(0xaed6dbb2, Int32ul)),
            'n' / Int32ul,
            'x' / Float64b,
            'y' / Float64b,
            'zoom' / Float64b)

    #--------------------------------------------------------------------------

    def message_action_chat_create_struct(self):
        return Struct('sname' / Computed('message_action_chat_create'),
                      'signature' / Hex(Const(0xa6638b9a, Int32ul)),
                      'title' / self.tstring_struct,
                      'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                      'users_num' / Int32ul,
                      'users' / Array(this.users_num, Int32ul))

    def message_action_chat_delete_photo_struct(self):
        return Struct('sname' / Computed('message_action_chat_delete_photo'),
                      'signature' / Hex(Const(0x95e3fbef, Int32ul)))

    def message_action_chat_delete_user_struct(self):
        return Struct('sname' / Computed('message_action_chat_delete_user'),
                      'signature' / Hex(Const(0xb2ae9b0c, Int32ul)),
                      'user_id' / Int32ul)

    def message_action_chat_edit_title_struct(self):
        return Struct('sname' / Computed('message_action_chat_edit_title'),
                      'signature' / Hex(Const(0xb5a1ce5a, Int32ul)),
                      'title' / self.tstring_struct)

    def message_action_empty_struct(self):
        return Struct('sname' / Computed('message_action_empty'),
                      'signature' / Hex(Const(0xb6aef7b0, Int32ul)))

    def message_action_ttl_change_struct(self):
        return Struct('sname' / Computed('message_action_ttl_change'),
                      'signature' / Hex(Const(0x55555552, Int32ul)),
                      'ttl_seconds' / Int32ul)

    def message_action_user_joined_struct(self):
        return Struct('sname' / Computed('message_action_user_joined'),
                      'signature' / Hex(Const(0x55555550, Int32ul)))

    def message_action_login_unknown_location_struct(self):
        return Struct(
            'sname' / Computed('message_action_login_unknown_location'),
            'signature' / Hex(Const(0x555555f5, Int32ul)),
            'title' / self.tstring_struct,
            'address' / self.tstring_struct)

    def message_action_chat_add_user_old_struct(self):
        return Struct('sname' / Computed('message_action_chat_add_user_old'),
                      'signature' / Hex(Const(0x5e3cfc4b, Int32ul)),
                      'user_id' / Int32ul)

    def message_action_bot_allowed_struct(self):
        return Struct('sname' / Computed('message_action_bot_allowed'),
                      'signature' / Hex(Const(0xabe9affe, Int32ul)),
                      'domain' / self.tstring_struct)

    def message_action_channel_create_struct(self):
        return Struct('sname' / Computed('message_action_channel_create'),
                      'signature' / Hex(Const(0x95d2ac92, Int32ul)),
                      'title' / self.tstring_struct)

    def message_action_channel_migrate_from_struct(self):
        return Struct(
            'sname' / Computed('message_action_channel_migrate_from'),
            'signature' / Hex(Const(0xb055eaee, Int32ul)),
            'title' / self.tstring_struct,
            'chat_id' / Int32ul)

    def message_action_chat_edit_photo_struct(self):
        return Struct('sname' / Computed('message_action_chat_edit_photo'),
                      'signature' / Hex(Const(0x7fcb13a8, Int32ul)),
                      'photo' / self.photo_structures('photo'))

    def message_action_history_clear_struct(self):
        return Struct('sname' / Computed('message_action_history_clear'),
                      'signature' / Hex(Const(0x9fbab604, Int32ul)))

    def message_action_game_score_struct(self):
        return Struct('sname' / Computed('message_action_game_score'),
                      'signature' / Hex(Const(0x92a72876, Int32ul)),
                      'game_id' / Int64ul,
                      'score' / Int32ul)

    def message_action_pin_message_struct(self):
        return Struct('sname' / Computed('message_action_pin_message'),
                      'signature' / Hex(Const(0x94bd38ed, Int32ul)))

    def message_action_phone_call_struct(self):
        return Struct(
            'sname' / Computed('message_action_phone_call'),
            'signature' / Hex(Const(0x80e11a7f, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_discarded=1,
                                has_duration=2,
                                is_video=4),
            'call_id' / Int64ul,
            'discard_reason' / If(
                this.flags.is_discarded,
                self.phone_call_discard_reason_structures('discard_reason')),
            'duration' / If(this.flags.has_duration, Int32ul))

    def message_action_contact_sign_up_struct(self):
        return Struct('sname' / Computed('message_action_contact_sign_up'),
                      'signature' / Hex(Const(0xf3f25f76, Int32ul)))

    def message_action_secure_values_sent_struct(self):
        return Struct(
            'sname' / Computed('message_action_secure_values_sent'),
            'signature' / Hex(Const(0xd95c6154, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'secure_values_num' / Int32ul,
            'secure_value_array' / Array(
                this.secure_values_num,
                self.secure_value_type_structures('secure_value')))

    def message_action_chat_joined_by_link_struct(self):
        return Struct('sname' / Computed('message_action_chat_joined_by_link'),
                      'signature' / Hex(Const(0xf89cf5e8, Int32ul)),
                      'inviter_id' / Int32ul)

    def message_action_custom_action_struct(self):
        return Struct('sname' / Computed('message_action_custom_action'),
                      'signature' / Hex(Const(0xfae69f56, Int32ul)),
                      'message' / self.tstring_struct)

    def message_action_payment_sent_struct(self):
        return Struct('sname' / Computed('message_action_payment_sent_struct'),
                      'signature' / Hex(Const(0x40699cd0, Int32ul)),
                      'currency' / self.tstring_struct,
                      'total_amount' / Int64ul)

    def message_action_screenshot_taken_struct(self):
        return Struct('sname' / Computed('message_action_screenshot_taken'),
                      'signature' / Hex(Const(0x4792929b, Int32ul)))

    def message_action_chat_add_user_struct(self):
        return Struct('sname' / Computed('message_action_chat_add_user'),
                      'signature' / Hex(Const(0x488a7337, Int32ul)),
                      '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                      'user_array_num' / Int32ul,
                      'user_array' / Array(this.user_array_num, Int32ul))

    def message_action_chat_migrate_to_struct(self):
        return Struct('sname' / Computed('message_action_chat_migrate_to'),
                      'signature' / Hex(Const(0x51bdb021, Int32ul)),
                      'channel_id' / Int32ul)

    def message_action_user_updated_photo_struct(self):
        return Struct('sname' / Computed('message_action_user_updated_photo'),
                      'signature' / Hex(Const(0x55555551, Int32ul)),
                      'new_user_photo' / self.user_profile_photo_structures(
                          'new_user_photo'))

    def message_action_created_broadcast_list_struct(self):
        return Struct(
            'sname' / Computed('message_action_created_broadcast_list'),
            'signature' / Hex(Const(0x55555557, Int32ul)))

    def message_encrypted_action_struct(self):
        return Struct(
            'sname' / Computed('message_encrypted_action'),
            'signature' / Hex(Const(0x555555f7, Int32ul)),
            'encrypted_action' / self.decrypted_message_action_structures(
                'encrypted_action'))

    def message_action_group_call_struct(self):
        return Struct('sname' / Computed('message_action_group_call'),
                      'signature' / Hex(Const(0x7a0d7f42, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          has_duration=1),
                      'call' / self.input_group_call_struct(),
                      'duration' / If(this.flags.has_duration, Int32ul))

    def message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x80e11a7f: LazyBound(lambda: self.message_action_phone_call_struct()),
            0x92a72876: LazyBound(lambda: self.message_action_game_score_struct()),
            0x94bd38ed: LazyBound(lambda: self.message_action_pin_message_struct()),
            0x95d2ac92: LazyBound(lambda: self.message_action_channel_create_struct()),
            0x95e3fbef: LazyBound(lambda: self.message_action_chat_delete_photo_struct()),
            0x9fbab604: LazyBound(lambda: self.message_action_history_clear_struct()),
            0xa6638b9a: LazyBound(lambda: self.message_action_chat_create_struct()),
            0xabe9affe: LazyBound(lambda: self.message_action_bot_allowed_struct()),
            0xb055eaee: LazyBound(lambda: self.message_action_channel_migrate_from_struct()),
            0xb2ae9b0c: LazyBound(lambda: self.message_action_chat_delete_user_struct()),
            0xb5a1ce5a: LazyBound(lambda: self.message_action_chat_edit_title_struct()),
            0xb6aef7b0: LazyBound(lambda: self.message_action_empty_struct()),
            0xd95c6154: LazyBound(lambda: self.message_action_secure_values_sent_struct()),
            0xf3f25f76: LazyBound(lambda: self.message_action_contact_sign_up_struct()),
            0xf89cf5e8: LazyBound(lambda: self.message_action_chat_joined_by_link_struct()),
            0xfae69f56: LazyBound(lambda: self.message_action_custom_action_struct()),
            0x40699cd0: LazyBound(lambda: self.message_action_payment_sent_struct()),
            0x4792929b: LazyBound(lambda: self.message_action_screenshot_taken_struct()),
            0x488a7337: LazyBound(lambda: self.message_action_chat_add_user_struct()),
            0x51bdb021: LazyBound(lambda: self.message_action_chat_migrate_to_struct()),
            0x55555550: LazyBound(lambda: self.message_action_user_joined_struct()),
            0x55555551: LazyBound(lambda: self.message_action_user_updated_photo_struct()),
            0x55555552: LazyBound(lambda: self.message_action_ttl_change_struct()),
            0x55555557: LazyBound(lambda: self.message_action_created_broadcast_list_struct()),
            0x555555f5: LazyBound(lambda: self.message_action_login_unknown_location_struct()),
            0x555555f7: LazyBound(lambda: self.message_encrypted_action_struct()),
            0x5e3cfc4b: LazyBound(lambda: self.message_action_chat_add_user_old_struct()),
            0x7a0d7f42: LazyBound(lambda: self.message_action_group_call_struct()),
            0x7fcb13a8: LazyBound(lambda: self.message_action_chat_edit_photo_struct())
        }
        return 'message_action_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def message_entity_italic_struct(self):
        return Struct('sname' / Computed('message_entity_italic'),
                      'signature' / Hex(Const(0x826f8b60, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_phone_struct(self):
        return Struct('sname' / Computed('message_entity_phone'),
                      'signature' / Hex(Const(0x9b69e34b, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_unknown_struct(self):
        return Struct('sname' / Computed('message_entity_unknown'),
                      'signature' / Hex(Const(0xbb92ba95, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_bank_card_struct(self):
        return Struct('sname' / Computed('message_entity_bank_card'),
                      'signature' / Hex(Const(0x761e6af4, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_blockquote_struct(self):
        return Struct('sname' / Computed('message_entity_blockquote'),
                      'signature' / Hex(Const(0x020df5d0, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_bold_struct(self):
        return Struct('sname' / Computed('message_entity_bold'),
                      'signature' / Hex(Const(0xbd610bc9, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_mention_struct(self):
        return Struct('sname' / Computed('message_entity_mention'),
                      'signature' / Hex(Const(0xfa04579d, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_code_struct(self):
        return Struct('sname' / Computed('message_entity_code'),
                      'signature' / Hex(Const(0x28a20571, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_mention_name_struct(self):
        return Struct('sname' / Computed('message_entity_mention_name'),
                      'signature' / Hex(Const(0x352dca58, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul,
                      'user_id' / Int32ul)

    def message_entity_cashtag_struct(self):
        return Struct('sname' / Computed('message_entity_cashtag'),
                      'signature' / Hex(Const(0x4c4e743f, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_email_struct(self):
        return Struct('sname' / Computed('message_entity_email'),
                      'signature' / Hex(Const(0x64e475c2, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_bot_command_struct(self):
        return Struct('sname' / Computed('message_entity_bot_command'),
                      'signature' / Hex(Const(0x6cef8ac7, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_url_struct(self):
        return Struct('sname' / Computed('message_entity_url'),
                      'signature' / Hex(Const(0x6ed02538, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_hashtag_struct(self):
        return Struct('sname' / Computed('message_entity_hashtag'),
                      'signature' / Hex(Const(0x6f635b0d, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_pre_struct(self):
        return Struct('sname' / Computed('message_entity_pre'),
                      'signature' / Hex(Const(0x73924be0, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul,
                      'language' / self.tstring_struct)

    def message_entity_text_url_struct(self):
        return Struct('sname' / Computed('message_entity_text_url'),
                      'signature' / Hex(Const(0x76a6d327, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul,
                      'url' / self.tstring_struct)

    def message_entity_strike_struct(self):
        return Struct('sname' / Computed('message_entity_strike'),
                      'signature' / Hex(Const(0xbf0693d4, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_underline_struct(self):
        return Struct('sname' / Computed('message_entity_underline'),
                      'signature' / Hex(Const(0x9c4e7e8b, Int32ul)),
                      'offset' / Int32ul,
                      'length' / Int32ul)

    def message_entity_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x9c4e7e8b: LazyBound(lambda: self.message_entity_underline_struct()),
            0xbf0693d4: LazyBound(lambda: self.message_entity_strike_struct()),
            0x761e6af4: LazyBound(lambda: self.message_entity_bank_card_struct()),
            0x020df5d0: LazyBound(lambda: self.message_entity_blockquote_struct()),
            0x826f8b60: LazyBound(lambda: self.message_entity_italic_struct()),
            0x9b69e34b: LazyBound(lambda: self.message_entity_phone_struct()),
            0xbb92ba95: LazyBound(lambda: self.message_entity_unknown_struct()),
            0xbd610bc9: LazyBound(lambda: self.message_entity_bold_struct()),
            0xfa04579d: LazyBound(lambda: self.message_entity_mention_struct()),
            0x208e68c9: LazyBound(lambda: self.input_message_entity_mention_name_struct()),
            0x28a20571: LazyBound(lambda: self.message_entity_code_struct()),
            0x352dca58: LazyBound(lambda: self.message_entity_mention_name_struct()),
            0x4c4e743f: LazyBound(lambda: self.message_entity_cashtag_struct()),
            0x64e475c2: LazyBound(lambda: self.message_entity_email_struct()),
            0x6cef8ac7: LazyBound(lambda: self.message_entity_bot_command_struct()),
            0x6ed02538: LazyBound(lambda: self.message_entity_url_struct()),
            0x6f635b0d: LazyBound(lambda: self.message_entity_hashtag_struct()),
            0x73924be0: LazyBound(lambda: self.message_entity_pre_struct()),
            0x76a6d327: LazyBound(lambda: self.message_entity_text_url_struct())
        }
        return 'message_entity_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def message_empty_struct(self):
        return Struct('sname' / Computed('message_empty'),
                      'signature' / Hex(Const(0x83e5de54, Int32ul)),
                      'id' / Int32ul,
                      # It seems empty messages without 'to_id' exists.
                      '_extra_signature' / Peek(Int32ul),
                      'to_id' / IfThenElse(this._extra_signature,
                                           self.peer_structures('to_id'),
                                           Terminated))

    #--------------------------------------------------------------------------

    def message_fwd_header_struct(self):
        return Struct(
            'sname' / Computed('message_fwd_header'),
            'signature' / Hex(Const(0x353a686b, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_from_id=1,
                                has_channel_id=2,
                                has_channel_post=4,
                                has_post_author=8,
                                has_saved_from_peer=16,
                                has_from_name=32,
                                has_psa_type=64),
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'from_name' / If(this.flags.has_from_name, self.tstring_struct),
            'date' / self.ttimestamp_struct,
            'channel_id' / If(this.flags.has_channel_id, Int32ul),
            'channel_post' / If(this.flags.has_channel_post, Int32ul),
            'post_author' / If(this.flags.has_post_author, self.tstring_struct),
            'saved_from_peer' / If(this.flags.has_saved_from_peer,
                                   self.peer_structures('saved_from_peer')),
            'saved_from_msg_id' / If(this.flags.has_saved_from_peer, Int32ul),
            'psa_type' / If(this.flags.has_psa_type, self.tstring_struct))

    def message_fwd_header_layer112_struct(self):
        return Struct(
            'sname' / Computed('message_fwd_header_layer112'),
            'signature' / Hex(Const(0xec338270, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_from_id=1,
                                has_channel_id=2,
                                has_channel_post=4,
                                has_post_author=8,
                                has_saved_from_peer=16,
                                has_from_name=32),
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'from_name' / If(this.flags.has_from_name, self.tstring_struct),
            'date' / self.ttimestamp_struct,
            'channel_id' / If(this.flags.has_channel_id, Int32ul),
            'channel_post' / If(this.flags.has_channel_post, Int32ul),
            'post_author' / If(this.flags.has_post_author, self.tstring_struct),
            'saved_from_peer' / If(this.flags.has_saved_from_peer,
                                   self.peer_structures('saved_from_peer')),
            'saved_from_msg_id' / If(this.flags.has_saved_from_peer, Int32ul))

    def message_fwd_header_layer68_struct(self):
        return Struct(
            'sname' / Computed('message_fwd_header_layer68'),
            'signature' / Hex(Const(0xc786ddcb, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_from_id=1,
                                has_channel_id=2,
                                has_channel_post=4),
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'channel_id' / If(this.flags.has_channel_id, Int32ul),
            'channel_post' / If(this.flags.has_channel_post, Int32ul))

    def message_fwd_header_layer72_struct(self):
        return Struct(
            'sname' / Computed('message_fwd_header_layer72'),
            'signature' / Hex(Const(0xfadff4ac, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_from_id=1,
                                has_channel_id=2,
                                has_channel_post=4,
                                has_post_author=8),
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'channel_id' / If(this.flags.has_channel_id, Int32ul),
            'channel_post' / If(this.flags.has_channel_post, Int32ul),
            'post_author' / If(this.flags.has_post_author, self.tstring_struct))

    def message_fwd_header_layer96_struct(self):
        return Struct(
            'sname' / Computed('message_fwd_header_layer96'),
            'signature' / Hex(Const(0x559ebe6d, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_from_id=1,
                                has_channel_id=2,
                                has_channel_post=4,
                                has_post_author=8,
                                has_saved_from_peer=16),
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'channel_id' / If(this.flags.has_channel_id, Int32ul),
            'channel_post' / If(this.flags.has_channel_post, Int32ul),
            'post_author' / If(this.flags.has_post_author, self.tstring_struct),
            'saved_from_peer' / If(this.flags.has_saved_from_peer,
                                   self.peer_structures('saved_from_peer')),
            'saved_from_msg_id' / If(this.flags.has_saved_from_peer, Int32ul))

    def message_fwd_header_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x353a686b: LazyBound(lambda: self.message_fwd_header_struct()),
            0xc786ddcb: LazyBound(lambda: self.message_fwd_header_layer68_struct()),
            0xec338270: LazyBound(lambda: self.message_fwd_header_layer112_struct()),
            0xfadff4ac: LazyBound(lambda: self.message_fwd_header_layer72_struct()),
            0x559ebe6d: LazyBound(lambda: self.message_fwd_header_layer96_struct())
        }
        return 'message_fwd_header_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def message_reactions_struct(self):
        return Struct(
            'sname' / Computed('message_reactions'),
            'signature' / Hex(Const(0xb87a24d1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                min=1),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'reaction_count_num' / Int32ul,
            'reaction_count_array' / Array(
                this.reaction_count_num,
                self.reaction_count_struct()))

    #--------------------------------------------------------------------------

    def message_media_empty_struct(self):
        return Struct('sname' / Computed('message_media_empty'),
                      'signature' / Hex(Const(0x3ded6320, Int32ul)))

    def message_media_invoice_struct(self):
        return Struct(
            'sname' / Computed('message_media_invoice'),
            'signature' / Hex(Const(0x84551347, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_photo=1,
                                shipping_address_requested=2,
                                has_receipt_msg_id=4,
                                is_test=8),
            'title' / self.tstring_struct,
            'description' / self.tstring_struct,
            'photo' / If(this.flags.has_photo,
                         self.web_document_structures('photo')),
            'receipt_msg_id' / If(this.flags.has_receipt_msg_id, Int32ul),
            'currency' / self.tstring_struct,
            'total_amount' / Int64ul,
            'start_param' / self.tstring_struct)

    def message_media_document_struct(self):
        return Struct(
            'sname' / Computed('message_media_document'),
            'signature' / Hex(Const(0x9cb070d7, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_document=1,
                                has_ttl_seconds=4),
            'document' / If(this.flags.has_document,
                            self.document_structures('document')),
            'ttl_seconds' / If(this.flags.has_ttl_seconds, Int32ul))

    def message_media_unsupported_struct(self):
        return Struct(
            'sname' / Computed('message_media_unsupported'),
            'signature' / Hex(Const(0x9f84f49e, Int32ul)))

    def message_media_video_old_struct(self):
        return Struct(
            'sname' / Computed('message_media_video_old'),
            'signature' / Hex(Const(0xa2d24290, Int32ul)),
            'video_unused' / self.video_structures('video_unused'))

    def message_media_web_page_struct(self):
        return 'message_media_web_page' / Struct(
            'sname' / Computed('message_media_web_page'),
            'signature' / Hex(Const(0xa32dd600, Int32ul)),
            'webpage' / self.web_page_structures('webpage'))

    def message_media_photo_layer74_struct(self):
        return Struct(
            'sname' / Computed('message_media_photo_layer74'),
            'signature' / Hex(Const(0xb5223b0f, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_photo=1,
                                has_caption=2,
                                has_ttl=4),
            'photo' / If(this.flags.has_photo, self.photo_structures('photo')),
            'caption_legacy' / If(this.flags.has_caption, self.tstring_struct),
            'ttl_seconds' / If(this.flags.has_ttl, Int32ul))

    def message_media_audio_layer45_struct(self):
        return Struct(
            'sname' / Computed('message_media_audio_layer45'),
            'signature' / Hex(Const(0xc6b68300, Int32ul)),
            'audio' / self.audio_structures('audio'))

    def message_media_photo_old_struct(self):
        return Struct(
            'sname' / Computed('message_media_photo_old'),
            'signature' / Hex(Const(0xc8c45a2a, Int32ul)),
            'photo' / self.photo_structures('photo'))

    def message_media_contact_struct(self):
        return Struct(
            'sname' / Computed('message_media_contact'),
            'signature' / Hex(Const(0xcbf24940, Int32ul)),
            'phone_number' / self.tstring_struct,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'vcard' / self.tstring_struct,
            'user_id' / Int32ul)

    def message_media_document_layer68_struct(self):
        return Struct(
            'sname' / Computed('message_media_document_layer68'),
            'signature' / Hex(Const(0xf3e02ea8, Int32ul)),
            'document' / self.document_structures('document'),
            'caption_legacy' / self.tstring_struct)

    def message_media_game_struct(self):
        return Struct(
            'sname' / Computed('message_media_game'),
            'signature' / Hex(Const(0xfdb19008, Int32ul)),
            'game' / self.game_struct())

    def message_media_unsupported_old_struct(self):
        return Struct(
            'sname' / Computed('message_media_unsupported_old'),
            'signature' / Hex(Const(0x29632a36, Int32ul)),
            'bytes' / self.tbytes_struct)

    def message_media_venue_struct(self):
        return Struct(
            'sname' / Computed('message_media_venue'),
            'signature' / Hex(Const(0x2ec0533f, Int32ul)),
            'geo' / self.geo_point_structures('geo'),
            'title' / self.tstring_struct,
            'address' / self.tstring_struct,
            'provider' / self.tstring_struct,
            'venue_id' / self.tstring_struct,
            'venue_type' / self.tstring_struct)

    def message_media_document_old_struct(self):
        return Struct(
            'sname' / Computed('message_media_document_old'),
            'signature' / Hex(Const(0x2fda2204, Int32ul)),
            'document' / self.document_structures('document'))

    def message_media_photo_layer68_struct(self):
        return Struct(
            'sname' / Computed('message_media_photo_layer68'),
            'signature' / Hex(Const(0x3d8ce53d, Int32ul)),
            'photo' / self.photo_structures('photo'),
            'caption_legacy' / self.tstring_struct)

    def message_media_poll_struct(self):
        return Struct(
            'sname' / Computed('message_media_poll'),
            'signature' / Hex(Const(0x4bd6e798, Int32ul)),
            'poll' / self.poll_struct(),
            'results' / self.poll_results_structures('results'))

    def message_media_geo_struct(self):
        return Struct(
            'sname' / Computed('message_media_geo'),
            'signature' / Hex(Const(0x56e0d474, Int32ul)),
            'geo' / self.geo_point_structures('geo'))

    def message_media_video_layer45_struct(self):
        return Struct(
            'sname' / Computed('message_media_video_layer45'),
            'signature' / Hex(Const(0x5bcf1675, Int32ul)),
            'video_unused' / self.video_structures('video_unused'),
            'caption_legacy' / self.tstring_struct)

    def message_media_contact_layer81_struct(self):
        return Struct(
            'sname' / Computed('message_media_contact_layer81'),
            'signature' / Hex(Const(0x5e7d2f39, Int32ul)),
            'phone_number' / self.tstring_struct,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'user_id' / Int32ul)

    def message_media_dice_struct(self):
        return Struct(
            'sname' / Computed('message_media_dice'),
            'signature' / Hex(Const(0x3f7ee58b, Int32ul)),
            'emoticon' / self.tstring_struct)

    def message_media_dice_layer111_struct(self):
        return Struct(
            'sname' / Computed('message_media_dice_layer111'),
            'signature' / Hex(Const(0x638fe46b, Int32ul)),
            'value' / Int32ul)

    def message_media_photo_struct(self):
        return Struct(
            'sname' / Computed('message_media_photo'),
            'signature' / Hex(Const(0x695150d7, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_photo=1,
                                has_ttl=4),
            'photo' / If(this.flags.has_photo, self.photo_structures('photo')),
            'ttl_seconds' / If(this.flags.has_ttl, Int32ul))

    def message_media_venue_layer71_struct(self):
        return Struct(
            'sname' / Computed('message_media_venue_layer71'),
            'signature' / Hex(Const(0x7912b71f, Int32ul)),
            'geo' / self.geo_point_structures('geo'),
            'title' / self.tstring_struct,
            'address' / self.tstring_struct,
            'provider' / self.tstring_struct,
            'venue_id' / self.tstring_struct)

    def message_media_geo_live_struct(self):
        return Struct(
            'sname' / Computed('message_media_geo_live'),
            'signature' / Hex(Const(0x7c3c2609, Int32ul)),
            'geo' / self.geo_point_structures('geo'),
            'period' / Int32ul)

    def message_media_document_layer74_struct(self):
        return Struct(
            'sname' / Computed('message_media_document_layer74'),
            'signature' / Hex(Const(0x7c4414d3, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_document=1,
                                has_caption=2,
                                has_ttl=4),
            'document' / If(this.flags.has_document,
                            self.document_structures('document')),
            'caption_legacy' / If(this.flags.has_caption, self.tstring_struct),
            'ttl_seconds' / If(this.flags.has_ttl, Int32ul))

    def message_media_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x3f7ee58b: LazyBound(lambda: self.message_media_dice_struct()),
            0x638fe46b: LazyBound(lambda: self.message_media_dice_layer111_struct()),
            0x3ded6320: LazyBound(lambda: self.message_media_empty_struct()),
            0xa32dd600: LazyBound(lambda: self.message_media_web_page_struct()),
            0x84551347: LazyBound(lambda: self.message_media_invoice_struct()),
            0x9cb070d7: LazyBound(lambda: self.message_media_document_struct()),
            0x9f84f49e: LazyBound(lambda: self.message_media_unsupported_struct()),
            0xa2d24290: LazyBound(lambda: self.message_media_video_old_struct()),
            0xb5223b0f: LazyBound(lambda: self.message_media_photo_layer74_struct()),
            0xc6b68300: LazyBound(lambda: self.message_media_audio_layer45_struct()),
            0xc8c45a2a: LazyBound(lambda: self.message_media_photo_old_struct()),
            0xcbf24940: LazyBound(lambda: self.message_media_contact_struct()),
            0xf3e02ea8: LazyBound(lambda: self.message_media_document_layer68_struct()),
            0xfdb19008: LazyBound(lambda: self.message_media_game_struct()),
            0x29632a36: LazyBound(lambda: self.message_media_unsupported_old_struct()),
            0x2ec0533f: LazyBound(lambda: self.message_media_venue_struct()),
            0x2fda2204: LazyBound(lambda: self.message_media_document_old_struct()),
            0x3d8ce53d: LazyBound(lambda: self.message_media_photo_layer68_struct()),
            0x4bd6e798: LazyBound(lambda: self.message_media_poll_struct()),
            0x56e0d474: LazyBound(lambda: self.message_media_geo_struct()),
            0x5bcf1675: LazyBound(lambda: self.message_media_video_layer45_struct()),
            0x5e7d2f39: LazyBound(lambda: self.message_media_contact_layer81_struct()),
            0x695150d7: LazyBound(lambda: self.message_media_photo_struct()),
            0x7912b71f: LazyBound(lambda: self.message_media_venue_layer71_struct()),
            0x7c3c2609: LazyBound(lambda: self.message_media_geo_live_struct()),
            0x7c4414d3: LazyBound(lambda: self.message_media_document_layer74_struct())
        }
        return 'message_media_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def message_forwarded_old_struct(self):
        return Struct(
            'sname' / Computed('message_forwarded_old'),
            'signature' / Hex(Const(0x05f46804, Int32ul)),
            'id' / Int32ul,
            'fwd_from_id' / Int32ul,
            'fwd_from_date' / self.ttimestamp_struct,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'out' / self.tbool_struct,
            'unread' / self.tbool_struct,
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / self.message_media_structures('media'))

    def message_forwarded_old2_struct(self):
        return Struct(
            'sname' / Computed('message_forwarded_old2'),
            'signature' / Hex(Const(0xa367e716, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                mentioned=16,
                                media_unread=32),
            'id' / Int32ul,
            'fwd_from_id' / Int32ul,
            'fwd_from_date' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / self.message_media_structures('media'))

    def message_old3_struct(self):
        return Struct(
            'sname' / Computed('message_old3'),
            'signature' / Hex(Const(0xa7ab1991, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                is_forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32),
            'id' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'fwd_from_id' / If(this.flags.is_forwarded, Int32ul),
            'fwd_from_date' / If(this.flags.is_forwarded, Int32ul),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / self.message_media_structures('media'))

    def message_service_struct(self):
        return Struct(
            'sname' / Computed('message_service'),
            'signature' / Hex(Const(0x9e19a1f6, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_from_id=256,
                                post=16384,
                                silent=8192,
                                is_grouped_id=131072),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'action' / self.message_action_structures('action'))

    def message_service_old_struct(self):
        return Struct(
            'sname' / Computed('message_service_old'),
            'signature' / Hex(Const(0x9f8d60bb, Int32ul)),
            'id' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'out' / self.tbool_struct,
            'unread' / self.tbool_struct,
            'date' / self.ttimestamp_struct,
            'action' / self.message_action_structures('action'))

    def message_secret_struct(self):
        return Struct(
            'sname' / Computed('message_secret'),
            'signature' / Hex(Const(0x555555fa, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                is_reply_to_random_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_via_bot_name=2048,
                                has_grouped_id=131072),
            'id' / Int32ul,
            'ttl' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / self.message_media_structures('media'),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'message_entity_num' / Int32ul,
            'message_entity_array' / Array(
                this.message_entity_num,
                self.message_entity_structures('message_entity')),
            'via_bot_name' / If(this.flags.has_via_bot_name,
                                self.tstring_struct),
            'reply_to_random_id' / If(this.flags.is_reply_to_random_id,
                                      Int64ul),
            'grouped_id' / If(this.flags.has_grouped_id, Int64ul),
            'UNPARSED' / GreedyBytes)

    def message_layer72_struct(self):
        return Struct(
            'sname' / Computed('message_layer72'),
            'signature' / Hex(Const(0x90dddc11, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128,
                                has_from_id=256,
                                has_media=512,
                                has_views=1024,
                                is_via_bot=2048,
                                silent=8192,
                                post=16384,
                                is_edited=32768,
                                has_author=65536),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id_type' / FlagsEnum(Int32ul,
                                     channel=0xbddde532,
                                     chat=0xbad0e5bb,
                                     user=0x9db1bc6d),
            'to_id' / Int32ul,
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.is_via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.has_media,
                         self.message_media_structures('media')),
            # The following two fields are copied from media, ignored.
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.has_views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, Int32ul),
            'post_author' / If(this.flags.has_author, Int32ul))

    def message_service_layer48_struct(self):
        return Struct(
            'sname' / Computed('message_service_layer48'),
            'signature' / Hex(Const(0xc06b9607, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                mentioned=16,
                                media_unread=32,
                                has_from_id=256,
                                is_via_bot=2048,
                                post=16384,
                                silent=8192,
                                is_grouped_id=131072),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'from_id_adjusted' / If(
                this.from_id == 0,
                IfThenElse(this.to_id.user_id != 0,
                           'from_id_adjusted' / this.to_id.user_id,
                           'from_id_adjusted' / this.to_id.channel_id * -1)),
            'date' / self.ttimestamp_struct,
            'action' / self.message_action_structures('action'))

    def message_layer68_struct(self):
        return Struct(
            'sname' / Computed('message_layer68'),
            'signature' / Hex(Const(0xc09be45f, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128,
                                has_from_id=256,
                                has_media=512,
                                has_views=1024,
                                is_via_bot=2048,
                                post=16384,
                                is_edited=32768,
                                silent=8192,
                                with_my_score=1073741824),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'from_id_adjusted' / If(
                this.from_id == 0,
                IfThenElse(this.to_id.user_id != 0,
                           'from_id_adjusted' / this.to_id.user_id,
                           'from_id_adjusted' / this.to_id.channel_id * -1)),
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.is_via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.has_media,
                         self.message_media_structures('media')),
            # The following two fields are copied from media, ignored.
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.has_views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, Int32ul))

    def message_old4_struct(self):
        return Struct(
            'sname' / Computed('message_old4'),
            'signature' / Hex(Const(0xc3060325, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128),
            'id' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'fwd_from_id' / If(this.flags.forwarded, 'fwd_from_id' / Int32ul),
            'fwd_from_timestamp' / If(
                this.flags.forwarded,
                'fwd_from_timestamp' / self.ttimestamp_struct),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / self.message_media_structures('media'),
            # The following field is copied from media, ignored.
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))))

    def message_old5_struct(self):
        return Struct(
            'sname' / Computed('message_old5'),
            'signature' / Hex(Const(0xf07814c8, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                unread=1,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128),
            'id' / Int32ul,
            'from_id' / Int32ul,
            'to_id' / self.peer_structures('to_id'),
            'fwd_from_id' / If(this.flags.forwarded, 'fwd_from_id' / Int32ul),
            'fwd_from_timestamp' / If(
                this.flags.forwarded,
                'fwd_from_timestamp' / self.ttimestamp_struct),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.has_media,
                         self.message_media_structures('media')),
            # Thee following two fields are copied from media, ignored.
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.has_views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, Int32ul))

    def message_layer104_struct(self):
        return Struct(
            'sname' / Computed('message_layer104'),
            'signature' / Hex(Const(0x44f9b43d, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128,
                                has_from_id=256,
                                has_media=512,
                                has_views=1024,
                                is_via_bot=2048,
                                silent=8192,
                                post=16384,
                                is_edited=32768,
                                has_author=65536,
                                is_grouped_id=131072),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.is_via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.has_media,
                         self.message_media_structures('media')),
            # The following two fields are copied from media, ignored.
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.has_views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, Int32ul),
            'post_author' / If(this.flags.has_author, self.tstring_struct),
            'grouped_id' / If(this.flags.is_grouped_id, Int64ul),
            'UNPARSED' / GreedyBytes)

    def message_layer104_2_struct(self):
        return Struct(
            'sname' / Computed('message_layer104_2'),
            'signature' / Hex(Const(0x1c9b1027, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                out=2,
                                forwarded=4,
                                reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                reply_markup=64,
                                entities=128,
                                media=512,
                                views=1024,
                                via_bot=2048,
                                silent=8192,
                                post=16384,
                                edited=32768,
                                author=65536,
                                grouped_id=131072,
                                from_scheduled=262144,
                                legacy=524288,
                                reactions=1048576,
                                edit_hide=2097152,
                                restricted=4194304),
            'id' / Int32ul,
            'from_id' / If(this.flags.from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.media,
                         self.message_media_structures('media')),
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, self.ttimestamp_struct),
            'post_author' / If(this.flags.author, self.tstring_struct),
            'grouped_id' / If(this.flags.grouped_id, Int64ul),
            'reactions' / If(this.flags.reactions,
                             self.message_reactions_struct()),
            'restricted' / If(this.flags.restricted, self.tstring_struct),
            'UNPARSED' / GreedyBytes)

    def message_layer104_3_struct(self):
        return Struct(
            'sname' / Computed('message_layer104_3'),
            'signature' / Hex(Const(0x9789dac4, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                out=2,
                                forwarded=4,
                                reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                reply_markup=64,
                                entities=128,
                                media=512,
                                views=1024,
                                via_bot=2048,
                                silent=8192,
                                post=16384,
                                edited=32768,
                                author=65536,
                                grouped_id=131072,
                                from_scheduled=262144,
                                legacy=524288,
                                reactions=1048576,
                                edit_hide=2097152,
                                restricted=4194304),
            'id' / Int32ul,
            'from_id' / If(this.flags.from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.media,
                         self.message_media_structures('media')),
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, self.ttimestamp_struct),
            'post_author' / If(this.flags.author, self.tstring_struct),
            'grouped_id' / If(this.flags.grouped_id, Int64ul),
            'reactions' / If(this.flags.reactions,
                             self.message_reactions_struct()),
            'restricted' / If(this.flags.restricted, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'restricted_reasons_num' / Int32ul,
                'restricted_reasons_array' / Array(
                    this.restricted_reasons_num,
                    self.restriction_reason_struct()))),
            'UNPARSED' / GreedyBytes)

    def message_struct(self):
        return Struct(
            'sname' / Computed('message_struct'),
            'signature' / Hex(Const(0x452c0e65, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                out=2,
                                forwarded=4,
                                is_reply_to_msg_id=8,
                                mentioned=16,
                                media_unread=32,
                                has_reply_markup=64,
                                has_entities=128,
                                has_from_id=256,
                                has_media=512,
                                has_views=1024,
                                is_via_bot=2048,
                                silent=8192,
                                post=16384,
                                is_edited=32768,
                                has_author=65536,
                                is_grouped_id=131072,
                                is_from_scheduled=262144,
                                is_restricted=4194304,
                                is_legacy=524288,
                                is_edit_hide=2097152),
            'id' / Int32ul,
            'from_id' / If(this.flags.has_from_id, Int32ul),
            'to_id' / self.peer_structures('to_id'),
            'fwd_from' / If(this.flags.forwarded,
                            self.message_fwd_header_structures('fwd_from')),
            'via_bot_id' / If(this.flags.is_via_bot, Int32ul),
            'reply_to_msg_id' / If(this.flags.is_reply_to_msg_id, Int32ul),
            'date' / self.ttimestamp_struct,
            'message' / self.tstring_struct,
            'media' / If(this.flags.has_media,
                         self.message_media_structures('media')),
            # The following two fields are copied from media, ignored.
            '_media_ttl' / Computed('ignored'),
            '_media_caption_legacy' / Computed('ignored'),
            'reply_markup' / If(this.flags.has_reply_markup,
                                self.reply_markup_structures('reply_markup')),
            'entities' / If(this.flags.has_entities, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'message_entity_num' / Int32ul,
                'message_entity_array' / Array(
                    this.message_entity_num,
                    self.message_entity_structures('message_entity')))),
            'views' / If(this.flags.has_views, Int32ul),
            'edit_timestamp' / If(this.flags.is_edited, self.ttimestamp_struct),
            'post_author' / If(this.flags.has_author, self.tstring_struct),
            'grouped_id' / If(this.flags.is_grouped_id, Int64ul),
            'restriction_reasons' / If(this.flags.is_restricted, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'restriction_reasons_num' / Int32ul,
                'restriction_reasons_array' / Array(
                    this.restriction_reasons_num,
                    self.restriction_reason_struct()))),
            'UNPARSED' / GreedyBytes)

    def message_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x452c0e65: LazyBound(lambda: self.message_struct()),
            0x44f9b43d: LazyBound(lambda: self.message_layer104_struct()),
            0x1c9b1027: LazyBound(lambda: self.message_layer104_2_struct()),
            0x9789dac4: LazyBound(lambda: self.message_layer104_3_struct()),
            0x83e5de54: LazyBound(lambda: self.message_empty_struct()),
            0x90dddc11: LazyBound(lambda: self.message_layer72_struct()),
            0x9e19a1f6: LazyBound(lambda: self.message_service_struct()),
            0x9f8d60bb: LazyBound(lambda: self.message_service_old_struct()),
            0x05f46804: LazyBound(lambda: self.message_forwarded_old_struct()),
            0xa367e716: LazyBound(lambda: self.message_forwarded_old2_struct()),
            0xc06b9607: LazyBound(lambda: self.message_service_layer48_struct()),
            0xc09be45f: LazyBound(lambda: self.message_layer68_struct()),
            0xa7ab1991: LazyBound(lambda: self.message_old3_struct()),
            0xc3060325: LazyBound(lambda: self.message_old4_struct()),
            0xf07814c8: LazyBound(lambda: self.message_old5_struct()),
            0x555555fa: LazyBound(lambda: self.message_secret_struct())
        }
        return 'message_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    '''
    TODO not yet implemented

    case -260565816: result = new TL_message_old5();
    case 495384334: result = new TL_messageService_old2();
    case 585853626: result = new TL_message_old();
    case 736885382: result = new TL_message_old6();
    case 1431655928: result = new TL_message_secret_old();
    case 1431655929: result = new TL_message_secret_layer72();
    case 1450613171: result = new TL_message_old2();
    case 1537633299: result = new TL_message_old7();
    case -913120932: result = new TL_message_layer47();
    '''

    #--------------------------------------------------------------------------

    def page_caption_struct(self):
        return Struct(
            'sname' / Computed('page_caption'),
            'signature' / Hex(Const(0x6f747657, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'credit' / self.rich_text_structures('credit'))

    #--------------------------------------------------------------------------

    def page_list_ordered_item_blocks_struct(self):
        return Struct(
            'sname' / Computed('page_list_ordered_item_blocks'),
            'signature' / Hex(Const(0x98dd8936, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')))

    def page_list_ordered_item_text_struct(self):
        return Struct(
            'sname' / Computed('page_list_ordered_item_text'),
            'signature' / Hex(Const(0x5e068047, Int32ul)),
            'num' / self.tstring_struct,
            'text' / self.rich_text_structures('text'))

    def page_list_ordered_item_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x98dd8936: LazyBound(lambda: self.page_list_ordered_item_blocks_struct()),
            0x5e068047: LazyBound(lambda: self.page_list_ordered_item_text_struct())
        }
        return 'page_list_ordered_item_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def page_block_audio_struct(self):
        return Struct(
            'sname' / Computed('page_block_audio'),
            'signature' / Hex(Const(0x804361ea, Int32ul)),
            'audio_id' / Int64ul,
            'caption' / self.page_caption_struct())

    def page_block_subtitle_struct(self):
        return Struct(
            'sname' / Computed('page_block_subtitle'),
            'signature' / Hex(Const(0x8ffa9a1f, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_ordered_list_struct(self):
        return Struct(
            'sname' / Computed('page_block_ordered_list'),
            'signature' / Hex(Const(0x9a8ae1e1, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_list_oitems_num' / Int32ul,
            'page_list_oitems' / Array(
                this.page_list_oitems_num,
                self.page_list_ordered_item_structures('page_list')))

    def page_block_map_struct(self):
        return Struct(
            'sname' / Computed('page_block_map'),
            'signature' / Hex(Const(0xa44f3ef6, Int32ul)),
            'geo' / self.geo_point_structures('geo'),
            'zoom' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul,
            'caption' / self.page_caption_struct())

    def page_block_embed_struct(self):
        return Struct(
            'sname' / Computed('page_block_embed'),
            'signature' / Hex(Const(0xa8718dc5, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                full_width=1,
                                has_url=2,
                                has_html=4,
                                allow_scrolling=8,
                                has_poster_photo_id=16,
                                has_dimensions=32),
            'url' / If(this.flags.has_url, self.tstring_struct),
            'html' / If(this.flags.has_html, self.tstring_struct),
            'poster_photo_id' / If(this.flags.has_poster_photo_id, Int64ul),
            'w' / If(this.flags.has_dimensions, Int32ul),
            'h' / If(this.flags.has_dimensions, Int32ul),
            'caption' / self.page_caption_struct())

    def page_block_author_date_struct(self):
        return Struct(
            'sname' / Computed('page_block_author_date'),
            'signature' / Hex(Const(0xbaafe5e0, Int32ul)),
            'author' / self.rich_text_structures('author'),
            'published_timestamp' / Int32ul)

    def page_block_table_struct(self):
        return Struct(
            'sname' / Computed('page_block_table'),
            'signature' / Hex(Const(0xbf4dea82, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                bordered=1,
                                striped=2),
            'title' / self.rich_text_structures('title'),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_table_row_num' / Int32ul,
            'page_table_row_array' / Array(this.page_table_row_num,
                                           self.page_table_row_struct()))

    def page_block_header_struct(self):
        return Struct(
            'sname' / Computed('page_block_header'),
            'signature' / Hex(Const(0xbfd064ec, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_preformatted_struct(self):
        return Struct(
            'sname' / Computed('page_block_preformatted'),
            'signature' / Hex(Const(0xc070d93e, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'language' / self.tstring_struct)

    def page_block_embed_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_embed_layer82'),
            'signature' / Hex(Const(0xcde200d1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                full_width=1,
                                has_url=2,
                                has_html=4,
                                allow_scrolling=8,
                                has_poster_photo_id=16),
            'url' / If(this.flags.has_url, self.tstring_struct),
            'html' / If(this.flags.has_html, self.tstring_struct),
            'poster_photo_id' / If(this.flags.has_poster_photo_id, Int64ul),
            'w' / Int32ul,
            'h' / Int32ul,
            'caption' /self.rich_text_structures('caption'))

    def page_block_anchor_struct(self):
        return Struct(
            'sname' / Computed('page_block_anchor'),
            'signature' / Hex(Const(0xce0d37b0, Int32ul)),
            'name' / self.tstring_struct)

    def page_block_embed_layer60_struct(self):
        return Struct(
            'sname' / Computed('page_block_embed_layer60'),
            'signature' / Hex(Const(0xd935d8fb, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                full_width=1,
                                has_url=2,
                                has_html=4,
                                allow_scrolling=8),
            'url' / If(this.flags.has_url, self.tstring_struct),
            'html' / If(this.flags.has_html, self.tstring_struct),
            'w' / Int32ul,
            'h' / Int32ul,
            'caption' / self.rich_text_structures('caption'))

    def page_block_video_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_video_layer82'),
            'signature' / Hex(Const(0xd9d71866, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                autoplay=1,
                                loop=2),
            'video_id' / Int64ul,
            'caption' / self.rich_text_structures('caption'))

    def page_block_divider_struct(self):
        return Struct(
            'sname' / Computed('page_block_divider'),
            'signature' / Hex(Const(0xdb20b188, Int32ul)))

    def page_block_list_struct(self):
        return Struct(
            'sname' / Computed('page_block_list'),
            'signature' / Hex(Const(0xe4e88011, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_list_item_num' / Int32ul,
            'page_list_item_array' / Array(
                this.page_list_item_num,
                self.page_list_item_structures('page_list_item')))

    def page_block_photo_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_photo_layer82'),
            'signature' / Hex(Const(0xe9c69982, Int32ul)),
            'photo_id' / Int64ul,
            'caption' / self.rich_text_structures('caption'))

    def page_block_channel_struct(self):
        return Struct(
            'sname' / Computed('page_block_channel'),
            'signature' / Hex(Const(0xef1751b5, Int32ul)),
            'channel' / self.chat_structures('channel'))

    def page_block_subheader_struct(self):
        return Struct(
            'sname' / Computed('page_block_subheader'),
            'signature' / Hex(Const(0xf12bb6e1, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_embed_post_struct(self):
        return Struct(
            'sname' / Computed('page_block_embed_post'),
            'signature' / Hex(Const(0xf259a80b, Int32ul)),
            'url' / self.tstring_struct,
            'webpage_id' / Int64ul,
            'author_photo_id' / Int64ul,
            'date' / self.ttimestamp_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption' / self.page_caption_struct())

    def page_block_slideshow_struct(self):
        return Struct(
            'sname' / Computed('page_block_slideshow'),
            'signature' / Hex(Const(0x031f9590, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption' / self.page_caption_struct())

    def page_block_collage_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_collage_layer82'),
            'signature' / Hex(Const(0x08b31c4f, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption_text' / self.rich_text_structures('caption_text'))

    def page_block_slideshow_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_slideshow_layer82'),
            'signature' / Hex(Const(0x130c8963, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption_text' / self.rich_text_structures('caption_text'))

    def page_block_unsupported_struct(self):
        return Struct(
            'sname' / Computed('page_block_unsupported'),
            'signature' / Hex(Const(0x13567e8a, Int32ul)))

    def page_block_related_articles_struct(self):
        return Struct(
            'sname' / Computed('page_block_related_articles'),
            'signature' / Hex(Const(0x16115a96, Int32ul)),
            'title' / self.rich_text_structures('title'),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_related_articles_num' / Int32ul,
            'page_related_articles_array' / Array(
                this.page_related_articles_num,
                self.page_related_article_struct()))

    def page_block_photo_struct(self):
        return Struct(
            'sname' / Computed('page_block_photo'),
            'signature' / Hex(Const(0x1759c560, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_url=1),
            'photo_id' / Int64ul,
            'caption' / self.page_caption_struct(),
            'url' / If(this.flags.has_url, self.tstring_struct),
            'webpage_id' / If(this.flags.has_url, Int64ul))

    def page_block_kicker_struct(self):
        return Struct(
            'sname' / Computed('page_block_kicker'),
            'signature' / Hex(Const(0x1e148390, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_blockquote_struct(self):
        return Struct(
            'sname' / Computed('page_block_blockquote'),
            'signature' / Hex(Const(0x263d7c26, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'caption' / self.rich_text_structures('caption'))

    def page_block_embed_post_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_embed_post_layer82'),
            'signature' / Hex(Const(0x292c7be9, Int32ul)),
            'url' / self.tstring_struct,
            'webpage_id' / Int64ul,
            'author_photo_id' / Int64ul,
            'author' / self.tstring_struct,
            'date' / self.ttimestamp_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption_text' / self.rich_text_structures('caption_text'))

    def page_block_audio_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_audio_layer82'),
            'signature' / Hex(Const(0x31b81a7f, Int32ul)),
            'audio_id' / Int64ul,
            'caption_text' / self.rich_text_structures('caption_text'))

    def page_block_cover_struct(self):
        return Struct(
            'sname' / Computed('page_block_cover'),
            'signature' / Hex(Const(0x39f23300, Int32ul)),
            'cover' / self.page_block_structures('cover'))

    def page_block_list_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_block_list_layer82'),
            'signature' / Hex(Const(0x3a58c7f4, Int32ul)),
            'ordered' / self.tbool_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'rich_text_num' / Int32ul,
            'rich_text_array' / Array(this.rich_text_num,
                                      self.rich_text_structures('rich_text')))

    def page_block_author_date_layer60_struct(self):
        return Struct(
            'sname' / Computed('page_block_author_date_layer60'),
            'signature' / Hex(Const(0x3d5b64f2, Int32ul)),
            'author_string' / self.tstring_struct,
            'published_timestamp' / Int32ul)

    def page_block_paragraph_struct(self):
        return Struct(
            'sname' / Computed('page_block_paragraph'),
            'signature' / Hex(Const(0x467a0766, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_footer_struct(self):
        return Struct(
            'sname' / Computed('page_block_footer'),
            'signature' / Hex(Const(0x48870999, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_pullquote_struct(self):
        return Struct(
            'sname' / Computed('page_block_pullquote'),
            'signature' / Hex(Const(0x4f4456d3, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'caption' / self.rich_text_structures('caption'))

    def page_block_collage_struct(self):
        return Struct(
            'sname' / Computed('page_block_collage'),
            'signature' / Hex(Const(0x65a0fa4d, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'caption' / self.page_caption_struct())

    def page_block_title_struct(self):
        return Struct(
            'sname' / Computed('page_block_title'),
            'signature' / Hex(Const(0x70abc3fd, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_block_details_struct(self):
        return Struct(
            'sname' / Computed('page_block_details'),
            'signature' / Hex(Const(0x76768bed, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_open=1),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_blocks_num' / Int32ul,
            'page_blocks_array' / Array(
                this.page_blocks_num,
                self.page_block_structures('page_block')),
            'title' / self.rich_text_structures('title'))

    def page_block_video_struct(self):
        return Struct(
            'sname' / Computed('page_block_video'),
            'signature' / Hex(Const(0x7c8fe7b6, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                autoplay=1,
                                loop=2),
            'video_id' / Int64ul,
            'caption' / self.page_caption_struct())

    def page_block_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x804361ea: LazyBound(lambda: self.page_block_audio_struct()),
            0x8ffa9a1f: LazyBound(lambda: self.page_block_subtitle_struct()),
            0x9a8ae1e1: LazyBound(lambda: self.page_block_ordered_list_struct()),
            0xa44f3ef6: LazyBound(lambda: self.page_block_map_struct()),
            0xa8718dc5: LazyBound(lambda: self.page_block_embed_struct()),
            0xbaafe5e0: LazyBound(lambda: self.page_block_author_date_struct()),
            0xbf4dea82: LazyBound(lambda: self.page_block_table_struct()),
            0xbfd064ec: LazyBound(lambda: self.page_block_header_struct()),
            0xc070d93e: LazyBound(lambda: self.page_block_preformatted_struct()),
            0xcde200d1: LazyBound(lambda: self.page_block_embed_layer82_struct()),
            0xce0d37b0: LazyBound(lambda: self.page_block_anchor_struct()),
            0xd935d8fb: LazyBound(lambda: self.page_block_embed_layer60_struct()),
            0xd9d71866: LazyBound(lambda: self.page_block_video_layer82_struct()),
            0xdb20b188: LazyBound(lambda: self.page_block_divider_struct()),
            0xe4e88011: LazyBound(lambda: self.page_block_list_struct()),
            0xe9c69982: LazyBound(lambda: self.page_block_photo_layer82_struct()),
            0xef1751b5: LazyBound(lambda: self.page_block_channel_struct()),
            0xf12bb6e1: LazyBound(lambda: self.page_block_subheader_struct()),
            0xf259a80b: LazyBound(lambda: self.page_block_embed_post_struct()),
            0x031f9590: LazyBound(lambda: self.page_block_slideshow_struct()),
            0x08b31c4f: LazyBound(lambda: self.page_block_collage_layer82_struct()),
            0x130c8963: LazyBound(lambda: self.page_block_slideshow_layer82_struct()),
            0x13567e8a: LazyBound(lambda: self.page_block_unsupported_struct()),
            0x16115a96: LazyBound(lambda: self.page_block_related_articles_struct()),
            0x1759c560: LazyBound(lambda: self.page_block_photo_struct()),
            0x1e148390: LazyBound(lambda: self.page_block_kicker_struct()),
            0x263d7c26: LazyBound(lambda: self.page_block_blockquote_struct()),
            0x292c7be9: LazyBound(lambda: self.page_block_embed_post_layer82_struct()),
            0x31b81a7f: LazyBound(lambda: self.page_block_audio_layer82_struct()),
            0x39f23300: LazyBound(lambda: self.page_block_cover_struct()),
            0x3a58c7f4: LazyBound(lambda: self.page_block_list_layer82_struct()),
            0x3d5b64f2: LazyBound(lambda: self.page_block_author_date_layer60_struct()),
            0x467a0766: LazyBound(lambda: self.page_block_paragraph_struct()),
            0x48870999: LazyBound(lambda: self.page_block_footer_struct()),
            0x4f4456d3: LazyBound(lambda: self.page_block_pullquote_struct()),
            0x65a0fa4d: LazyBound(lambda: self.page_block_collage_struct()),
            0x70abc3fd: LazyBound(lambda: self.page_block_title_struct()),
            0x76768bed: LazyBound(lambda: self.page_block_details_struct()),
            0x7c8fe7b6: LazyBound(lambda: self.page_block_video_struct())
        }
        return 'page_block_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def page_part_layer67_struct(self):
        return Struct(
            'sname' / Computed('page_part_layer67'),
            'signature' / Hex(Const(0x8dee6c44, Int32ul)),
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')))

    def page_full_layer67_struct(self):
        return Struct(
            'sname' / Computed('page_full_layer67'),
            'signature' / Hex(Const(0xd7a19d69, Int32ul)),
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')))

    def page_part_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_part_layer82'),
            'signature' / Hex(Const(0x8e3f9ebe, Int32ul)),
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')))

    def page_full_layer82_struct(self):
        return Struct(
            'sname' / Computed('page_full_layer82'),
            'signature' / Hex(Const(0x556ec7aa, Int32ul)),
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')))

    def page_layer110_struct(self):
        return Struct(
            'sname' / Computed('page_layer110'),
            'signature' / Hex(Const(0xae891bec, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                part=1,
                                rtl=2),
            'url' / self.tstring_struct,
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')))

    def page_struct(self):
        return Struct(
            'sname' / Computed('page'),
            'signature' / Hex(Const(0x98657f0d, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                part=1,
                                rtl=2,
                                v2=4,
                                has_views=8),
            'url' / self.tstring_struct,
            'vector_sig_page_block' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_block')),
            'vector_sig_photo' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_num' / Int32ul,
            'photo_array' / Array(this.photo_num,
                                  self.photo_structures('photo')),
            'vector_sig_document' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_num' / Int32ul,
            'document_array' / Array(this.document_num,
                                     self.document_structures('document')),
            'views' / If(this.flags.has_views, Int32ul))

    def page_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x98657f0d: LazyBound(lambda: self.page_struct()),
            0x8dee6c44: LazyBound(lambda: self.page_part_layer67_struct()),
            0x8e3f9ebe: LazyBound(lambda: self.page_part_layer82_struct()),
            0xae891bec: LazyBound(lambda: self.page_layer110_struct()),
            0xd7a19d69: LazyBound(lambda: self.page_full_layer67_struct()),
            0x556ec7aa: LazyBound(lambda: self.page_full_layer82_struct())
        }
        return 'page_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def page_list_item_text_struct(self):
        return Struct(
            'sname' / Computed('page_list_item_text'),
            'signature' / Hex(Const(0xb92fb6cd, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def page_list_item_blocks_struct(self):
        return Struct(
            'sname' / Computed('page_list_item_blocks'),
            'signature' / Hex(Const(0x25e073fc, Int32ul)),
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_block_num' / Int32ul,
            'page_block_array' / Array(
                this.page_block_num,
                self.page_block_structures('page_table_cell')))

    def page_list_item_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xb92fb6cd: LazyBound(lambda: self.page_list_item_text_struct()),
            0x25e073fc: LazyBound(lambda: self.page_list_item_blocks_struct())
        }
        return 'page_list_item_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def page_related_article_struct(self):
        return Struct(
            'sname' / Computed('page_related_article'),
            'signature' / Hex(Const(0xb390dc08, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_title=1,
                                has_description=2,
                                has_photo=4,
                                has_author=8,
                                has_published_timestamp=16),
            'url' / self.tstring_struct,
            'webpage_id' / Int64ul,
            'title' / If(this.flags.has_title, self.tstring_struct),
            'description' / If(this.flags.has_description, self.tstring_struct),
            'photo_id' / If(this.flags.has_photo, Int64ul),
            'author' / If(this.flags.has_author, self.tstring_struct),
            'published_timestamp' / If(this.flags.has_published_timestamp,
                                       Int32ul))

    #--------------------------------------------------------------------------

    def page_table_cell_struct(self):
        return Struct('sname' / Computed('page_table_cell'),
                      'signature' / Hex(Const(0x34566b6a, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          header=1,
                                          has_colspan=2,
                                          has_rowspan=4,
                                          align_center=8,
                                          align_right=16,
                                          valign_middle=32,
                                          valign_bottom=64,
                                          has_text=128),
                      'text' / If(this.flags.has_text,
                                  self.rich_text_structures('text')),
                      'colspan' / If(this.flags.has_colspan, Int32ul),
                      'rowspan' / If(this.flags.has_rowspan, Int32ul))

    def page_table_row_struct(self):
        return Struct(
            'sname' / Computed('page_table_row'),
            'signature' / Hex(Const(0xe0c0c5e5, Int32ul)),
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'page_table_cell_num' / Int32ul,
            'page_table_cell_array' / Array(this.page_table_cell_num,
                                            self.page_table_cell_struct()))

    #--------------------------------------------------------------------------

    def peer_channel_struct(self):
        return Struct('sname' / Computed('peer_channel'),
                      'signature' / Hex(Const(0xbddde532, Int32ul)),
                      'channel_id' / Int32ul)

    def peer_chat_struct(self):
        return Struct('sname' / Computed('peer_chat'),
                      'signature' / Hex(Const(0xbad0e5bb, Int32ul)),
                      'chat_id' / Int32ul)

    def peer_user_struct(self):
        return Struct('sname' / Computed('peer_user'),
                      'signature' / Hex(Const(0x9db1bc6d, Int32ul)),
                      'user_id' / Int32ul)

    def peer_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xbddde532: LazyBound(lambda: self.peer_channel_struct()),
            0xbad0e5bb: LazyBound(lambda: self.peer_chat_struct()),
            0x9db1bc6d: LazyBound(lambda: self.peer_user_struct())
        }
        return 'peer_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def peer_notify_settings_layer47_struct(self):
        return Struct('sname' / Computed('peer_notify_settings_layer47'),
                      'signature' / Hex(Const(0x8d5e11ee, Int32ul)),
                      'mute_until' / Int32ul,
                      'sound' / self.tstring_struct,
                      'show_previews' / self.tbool_struct,
                      'event_mask' / Int32ul)

    def peer_notify_settings_layer77_struct(self):
        return Struct('sname' / Computed('peer_notify_settings_layer77'),
                      'signature' / Hex(Const(0x9acda4c0, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          show_previews=1,
                                          is_silent=2),
                      'mute_until' / Int32ul,
                      'sound' / self.tstring_struct)

    def peer_notify_settings_struct(self):
        return Struct(
            'sname' / Computed('peer_notify_settings'),
            'signature' / Hex(Const(0xaf509d20, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_show_previews=1,
                                has_silent=2,
                                has_mute_until=4,
                                has_sound=8),
            'show_previews' / If(this.flags.has_show_previews,
                                 self.tbool_struct),
            'silent' / If(this.flags.has_silent, self.tbool_struct),
            'mute_until' / If(this.flags.has_mute_until, Int32ul),
            'sound' / If(this.flags.has_sound, self.tstring_struct))

    def peer_notify_settings_empty_layer77_struct(self):
        return Struct('sname' / Computed('peer_notify_settings_empty_layer77'),
                      'signature' / Hex(Const(0x70a68512, Int32ul)))

    def peer_notify_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x8d5e11ee: LazyBound(lambda: self.peer_notify_settings_layer47_struct()),
            0x9acda4c0: LazyBound(lambda: self.peer_notify_settings_layer77_struct()),
            0xaf509d20: LazyBound(lambda: self.peer_notify_settings_struct()),
            0x70a68512: LazyBound(lambda: self.peer_notify_settings_empty_layer77_struct())
        }
        return 'peer_notify_settings_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def peer_settings_v_5_15_0_struct(self):
        return Struct(
            'sname' / Computed('peer_settings_v_5_15_0'),
            'signature' / Hex(Const(0x818426cd, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                report_spam=1,
                                add_contact=2,
                                block_contact=4,
                                share_contact=8,
                                need_contacts_exception=16,
                                report_geo=32))

    def peer_settings_struct(self):
        return Struct(
            'sname' / Computed('peer_settings'),
            'signature' / Hex(Const(0x733f2961, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                report_spam=1,
                                add_contact=2,
                                block_contact=4,
                                share_contact=8,
                                need_contacts_exception=16,
                                report_geo=32,
                                has_geo_distance=64,
                                autoarchived=128),
            'geo_distance' / If(this.flags.has_geo_distance, Int32ul))

    def peer_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x818426cd: LazyBound(lambda: self.peer_settings_v_5_15_0_struct()),
            0x733f2961: LazyBound(lambda: self.peer_settings_struct())
        }
        return 'peer_settings_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def phone_call_discard_reason_missed_struct(self):
        return Struct('sname' / Computed('phone_call_discard_reason_missed'),
                      'signature' / Hex(Const(0x85e42301, Int32ul)))

    def phone_call_discard_reason_busy_struct(self):
        return Struct('sname' / Computed('phone_call_discard_reason_busy'),
                      'signature' / Hex(Const(0xfaf7e8c9, Int32ul)))

    def phone_call_discard_reason_hangup_struct(self):
        return Struct('sname' / Computed('phone_call_discard_reason_hangup'),
                      'signature' / Hex(Const(0x57adc690, Int32ul)))

    def phone_call_discard_reason_disconnect_struct(self):
        return Struct(
            'sname' / Computed('phone_call_discard_reason_disconnect'),
            'signature' / Hex(Const(0xe095c1a0, Int32ul)))

    def phone_call_discard_reason_allow_group_call_struct(self):
        return Struct(
            'sname' / Computed('phone_call_discard_reason_allow_group_call'),
            'signature' / Hex(Const(0xafe2b839, Int32ul)),
            'encrypted_key' / self.tbytes_struct)

    def phone_call_discarded_struct(self):
        return Struct(
            'sname' / Computed('phone_call_discarded'),
            'signature' / Hex(Const(0x50ca4de1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_discarded=1,
                                has_duration=2,
                                need_rating=4,
                                need_debug=8,
                                is_video=32),
            'id' / Int64ul,
            'discard_reason' / If(
                this.flags.is_discarded,
                self.phone_call_discard_reason_structures('discard_reason')),
            'duration' / If(this.flags.has_duration, Int32ul))

    def phone_call_discard_reason_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x85e42301: LazyBound(lambda: self.phone_call_discard_reason_missed_struct()),
            0xafe2b839: LazyBound(lambda: self.phone_call_discard_reason_allow_group_call_struct()),
            0xe095c1a0: LazyBound(lambda: self.phone_call_discard_reason_disconnect_struct()),
            0xfaf7e8c9: LazyBound(lambda: self.phone_call_discard_reason_busy_struct()),
            0x57adc690: LazyBound(lambda: self.phone_call_discard_reason_hangup_struct())
        }
        return 'phone_call_discard_reason_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def photo_size_empty_struct(self):
        return Struct('sname' / Computed('photo_size_empty'),
                      'signature' / Hex(Const(0x0e17e23c, Int32ul)),
                      'type' / self.tstring_struct)

    def photo_size_struct(self):
        return Struct(
            'sname' / Computed('photo_size'),
            'signature' / Hex(Const(0x77bfb61b, Int32ul)),
            'type' / self.tstring_struct,
            'file_location' / self.file_location_structures('file_location'),
            'w' / Int32ul,
            'h' / Int32ul,
            'size' / Int32ul)

    def photo_stripped_size_struct(self):
        return Struct('sname' / Computed('photo_stripped_size'),
                      'signature' / Hex(Const(0xe0b0bc2e, Int32ul)),
                      'type' / self.tstring_struct,
                      'bytes' / self.tbytes_struct,
                      'h' / Computed(50),
                      'w' / Computed(50))

    def photo_cached_size_struct(self):
        return Struct('sname' / Computed('photo_cached_size'),
                      'signature' / Hex(Const(0xe9a734fa, Int32ul)),
                      'type' / self.tstring_struct,
                      'location' / self.file_location_structures('location'),
                      'w' / Int32ul,
                      'h' / Int32ul,
                      'bytes' / self.tbytes_struct)

    def photo_size_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x0e17e23c: LazyBound(lambda: self.photo_size_empty_struct()),
            0xe0b0bc2e: LazyBound(lambda: self.photo_stripped_size_struct()),
            0xe9a734fa: LazyBound(lambda: self.photo_cached_size_struct()),
            0x77bfb61b: LazyBound(lambda: self.photo_size_struct())
        }
        return 'photo_size_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def photo_empty_struct(self):
        return Struct('sname' / Computed('photo_empty'),
                      'signature' / Hex(Const(0x2331b22d, Int32ul)),
                      'id' / Int64ul)

    def photo_layer55_struct(self):
        return Struct(
            'sname' / Computed('photo_layer55'),
            'signature' / Hex(Const(0xcded42fe, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')))

    def photo_layer82_struct(self):
        return Struct(
            'sname' / Computed('photo_layer82'),
            'signature' / Hex(Const(0x9288dd29, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_stickers=1),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')))

    def photo_old_struct(self):
        return Struct(
            'sname' / Computed('photo_old'),
            'signature' / Hex(Const(0x22b56751, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'caption' / self.tstring_struct,
            'geo' / self.geo_point_structures('geo'),
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')))

    def photo_old2_struct(self):
        return Struct(
            'sname' / Computed('photo_old2'),
            'signature' / Hex(Const(0xc3838076, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'geo' / self.geo_point_structures('geo'),
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')))

    def photo_layer97_struct(self):
        return Struct(
            'sname' / Computed('photo_layer97'),
            'signature' / Hex(Const(0x9c477dd8, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_stickers=1),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')))

    def photo_layer115_struct(self):
        return Struct(
            'sname' / Computed('photo_layer115'),
            'signature' / Hex(Const(0xd07504a5, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_stickers=1),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')),
            'dc_id' / Int32ul)

    def photo_struct(self):
        return Struct(
            'sname' / Computed('photo'),
            'signature' / Hex(Const(0xfb197a65, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_stickers=1,
                                has_video_size=2),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'file_reference' / self.tbytes_struct,
            'date' / self.ttimestamp_struct,
            'vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'photo_size_num' / Int32ul,
            'photo_size_array' / Array(
                this.photo_size_num,
                self.photo_size_structures('photo_size')),
            'video_size' / If(this.flags.has_video_size, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'video_sizes_num' / Int32ul,
                'video_sizes_array' / Array(
                    this.video_sizes_num,
                    self.video_size_structures('video_size')))),
            'dc_id' / Int32ul)

    def photo_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xfb197a65: LazyBound(lambda: self.photo_struct()),
            0xd07504a5: LazyBound(lambda: self.photo_layer115_struct()),
            0x9288dd29: LazyBound(lambda: self.photo_layer82_struct()),
            0x9c477dd8: LazyBound(lambda: self.photo_layer97_struct()),
            0xc3838076: LazyBound(lambda: self.photo_old2_struct()),
            0xcded42fe: LazyBound(lambda: self.photo_layer55_struct()),
            0x22b56751: LazyBound(lambda: self.photo_old_struct()),
            0x2331b22d: LazyBound(lambda: self.photo_empty_struct())
        }
        return 'photo_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def poll_answer_struct(self):
        return Struct('sname' / Computed('poll_answer'),
                      'signature' / Hex(Const(0x6ca9c2e9, Int32ul)),
                      'text' / self.tstring_struct,
                      'option' / self.tbytes_struct)


    def poll_answer_voters_struct(self):
        return Struct('sname' / Computed('poll_answer_voters'),
                      'signature' / Hex(Const(0x3b6ddad2, Int32ul)),
                      'flags' / FlagsEnum(Int32ul,
                                          is_chosen=1),
                      'option' / self.tbytes_struct,
                      'voters' / Int32ul)

    #--------------------------------------------------------------------------

    def poll_layer111_struct(self):
        return Struct('sname' / Computed('poll_layer111'),
                      'signature' / Hex(Const(0xd5529d06, Int32ul)),
                      'id' / Int64ul,
                      'flags' / FlagsEnum(Int32ul,
                                          closed=1),
                      'question' / self.tstring_struct,
                      '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                      'poll_answers_num' / Int32ul,
                      'poll_answers_array' / Array(this.poll_answers_num,
                                                   self.poll_answer_struct()))

    def poll_struct(self):
        return Struct('sname' / Computed('poll'),
                      'signature' / Hex(Const(0x86e18161, Int32ul)),
                      'id' / Int64ul,
                      'flags' / FlagsEnum(Int32ul,
                                          closed=1,
                                          public_voters=2,
                                          multiple_choice=4,
                                          quiz=8,
                                          has_close_period=16,
                                          has_close_date=32),
                      'question' / self.tstring_struct,
                      '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                      'poll_answers_num' / Int32ul,
                      'poll_answers_array' / Array(this.poll_answers_num,
                                                   self.poll_answer_struct()),
                      'close_period' / If(this.flags.has_close_period,
                                          Int32ul),
                      'close_date' / If(this.flags.has_close_date,
                                        self.ttimestamp_struct))

    def poll_to_delete_struct(self):
        return Struct('sname' / Computed('poll_to_delete'),
                      'signature' / Hex(Const(0xaf746786, Int32ul)),
                      'id' / Int64ul,
                      'flags' / FlagsEnum(Int32ul,
                                          closed=1,
                                          public_voters=2,
                                          multiple_choice=4,
                                          quiz=8,
                                          has_close_date=16),
                      'question' / self.tstring_struct,
                      '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                      'poll_answers_num' / Int32ul,
                      'poll_answers_array' / Array(this.poll_answers_num,
                                                   self.poll_answer_struct()),
                      'close_date' / If(this.flags.has_close_date,
                                        self.ttimestamp_struct))

    def poll_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x86e18161: LazyBound(lambda: self.poll_struct()),
            0xd5529d06: LazyBound(lambda: self.poll_layer111_struct()),
            0xaf746786: LazyBound(lambda: self.poll_to_delete_struct())
        }
        return 'poll_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def poll_results_layer108_struct(self):
        return Struct(
            'sname' / Computed('poll_results_layer108'),
            'signature' / Hex(Const(0x5755785a, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                min=1,
                                voters=2,
                                total=4),
            'poll_answer_voters' / If(
                this.flags.voters,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'poll_answer_voters_num' / Int32ul,
                    'poll_answer_voters_array' / Array(
                        this.poll_answer_voters_num,
                        self.poll_answer_voters_struct()))),
            'total_voters' / If(this.flags.total, Int32ul))

    def poll_results_layer111_struct(self):
        return Struct(
            'sname' / Computed('poll_results_layer111'),
            'signature' / Hex(Const(0xc87024a2, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                min=1,
                                voters=2,
                                total=4,
                                recent_voters=8),
            'poll_answer_voters' / If(
                this.flags.voters,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'poll_answer_voters_num' / Int32ul,
                    'poll_answer_voters_array' / Array(
                        this.poll_answer_voters_num,
                        self.poll_answer_voters_struct()))),
            'total_voters' / If(this.flags.total, Int32ul),
            'poll_recent_voters' / If(
                this.flags.recent_voters,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'poll_answer_voters_num' / Int32ul,
                    'poll_answer_voters_array' / Array(
                        this.poll_answer_voters_num, Int32ul))))

    def poll_results_struct(self):
        return Struct(
            'sname' / Computed('poll_results'),
            'signature' / Hex(Const(0xbadcc1a3, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                min=1,
                                voters=2,
                                total=4,
                                recent_voters=8,
                                has_solution=16),
            'poll_answer_voters' / If(
                this.flags.voters,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'poll_answer_voters_num' / Int32ul,
                    'poll_answer_voters_array' / Array(
                        this.poll_answer_voters_num,
                        self.poll_answer_voters_struct()))),
            'total_voters' / If(this.flags.total, Int32ul),
            'poll_recent_voters' / If(
                this.flags.has_recent_voters,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'poll_answer_voters_num' / Int32ul,
                    'poll_answer_voters_array' / Array(
                        this.poll_answer_voters_num, Int32ul))),
            'solution' / If(this.flags.has_solution,
                            self.tstring_struct),
            'solution_entities' / If(
                this.flags.has_solution,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'entities_num' / Int32ul,
                    'entities_array' / Array(
                        this.entities_num,
                        self.message_entity_structures('message_entity')))))

    def poll_results_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xbadcc1a3: LazyBound(lambda: self.poll_results_struct()),
            0x5755785a: LazyBound(lambda: self.poll_results_layer108_struct()),
            0xc87024a2: LazyBound(lambda: self.poll_results_layer111_struct())
        }
        return 'poll_results_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def reaction_count_struct(self):
        return Struct(
            'sname' / Computed('reaction_count'),
            'signature' / Hex(Const(0x6fb250d1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                chosen=1),
            'reaction' / self.tstring_struct,
            'count' / Int32ul)

    #--------------------------------------------------------------------------

    def reply_keyboard_hide_struct(self):
        return Struct(
            'sname' / Computed('reply_keyboard_hide'),
            'signature' / Hex(Const(0xa03e5b85, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                selective=4))

    def reply_keyboard_force_reply_struct(self):
        return Struct(
            'sname' / Computed('reply_keyboard_force_reply'),
            'signature' / Hex(Const(0xf4108aa0, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                single_use=2,
                                selective=4))

    def reply_keyboard_markup_struct(self):
        return Struct(
            'sname' / Computed('reply_keyboard_markup'),
            'signature' / Hex(Const(0x3502758c, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                resize=1,
                                single_use=2,
                                selective=4),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'keyboard_button_rows_num' / Int32ul,
            'keyboard_button_rows' / Array(this.keyboard_button_rows_num,
                                           self.keyboard_button_row_struct()))

    def reply_inline_markup_struct(self):
        return Struct(
            'sname' / Computed('reply_inline_markup'),
            'signature' / Hex(Const(0x48a30254, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'keyboard_button_rows_num' / Int32ul,
            'keyboard_button_rows' / Array(this.keyboard_button_rows_num,
                                           self.keyboard_button_row_struct()))

    def reply_markup_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xa03e5b85: LazyBound(lambda: self.reply_keyboard_hide_struct()),
            0xf4108aa0: LazyBound(lambda: self.reply_keyboard_force_reply_struct()),
            0x3502758c: LazyBound(lambda: self.reply_keyboard_markup_struct()),
            0x48a30254: LazyBound(lambda: self.reply_inline_markup_struct())
        }
        return 'reply_markup_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def restriction_reason_struct(self):
        return Struct(
            'sname' / Computed('restriction_reason'),
            'signature' / Hex(Const(0xd072acb4, Int32ul)),
            'platform' / self.tstring_struct,
            'reason' / self.tstring_struct,
            'text' / self.tstring_struct)

    #--------------------------------------------------------------------------

    def send_message_record_round_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_record_round_action'),
            'signature' / Hex(Const(0x88f27fbc, Int32ul)))

    def send_message_upload_document_action_old_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_document_action_old'),
            'signature' / Hex(Const(0x8faee98e, Int32ul)))

    def send_message_upload_video_action_old_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_video_action_old'),
            'signature' / Hex(Const(0x92042ff7, Int32ul)))

    def send_message_upload_photo_action_old_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_photo_action_old'),
            'signature' / Hex(Const(0x990a3c1a, Int32ul)))

    def send_message_record_video_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_record_video_action'),
            'signature' / Hex(Const(0xa187d66f, Int32ul)))

    def send_message_upload_document_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_document_action'),
            'signature' / Hex(Const(0xaa0cd9e4, Int32ul)),
            'progress' / Int32ul)

    def send_message_upload_photo_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_photo_action'),
            'signature' / Hex(Const(0xd1d34a26, Int32ul)),
            'progress' / Int32ul)

    def send_message_record_audio_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_record_audio_action'),
            'signature' / Hex(Const(0xd52f73f7, Int32ul)))

    def send_message_game_play_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_game_play_action'),
            'signature' / Hex(Const(0xdd6a8f48, Int32ul)))

    def send_message_upload_audio_action_old_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_audio_action_old'),
            'signature' / Hex(Const(0xe6ac8a6f, Int32ul)))

    def send_message_upload_video_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_video_action'),
            'signature' / Hex(Const(0xe9763aec, Int32ul)),
            'progress' / Int32ul)

    def send_message_upload_audio_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_audio_action'),
            'signature' / Hex(Const(0xf351d7ab, Int32ul)),
            'progress' / Int32ul)

    def send_message_cancel_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_cancel_action'),
            'signature' / Hex(Const(0xfd5ec8f5, Int32ul)))

    def send_message_typing_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_typing_action'),
            'signature' / Hex(Const(0x16bf744e, Int32ul)))

    def send_message_geo_location_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_geo_location_action'),
            'signature' / Hex(Const(0x176f8ba1, Int32ul)))

    def send_message_upload_round_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_upload_round_action'),
            'signature' / Hex(Const(0x243e1c66, Int32ul)),
            'progress' / Int32ul)

    def send_message_choose_contact_action_struct(self):
        return Struct(
            'sname' / Computed('send_message_choose_contact_action'),
            'signature' / Hex(Const(0x628cbc6f, Int32ul)))

    def send_message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x88f27fbc: LazyBound(lambda: self.send_message_record_round_action_struct()),
            0x8faee98e: LazyBound(lambda: self.send_message_upload_document_action_old_struct()),
            0x92042ff7: LazyBound(lambda: self.send_message_upload_video_action_old_struct()),
            0x990a3c1a: LazyBound(lambda: self.send_message_upload_photo_action_old_struct()),
            0xa187d66f: LazyBound(lambda: self.send_message_record_video_action_struct()),
            0xaa0cd9e4: LazyBound(lambda: self.send_message_upload_document_action_struct()),
            0xd1d34a26: LazyBound(lambda: self.send_message_upload_photo_action_struct()),
            0xd52f73f7: LazyBound(lambda: self.send_message_record_audio_action_struct()),
            0xdd6a8f48: LazyBound(lambda: self.send_message_game_play_action_struct()),
            0xe6ac8a6f: LazyBound(lambda: self.send_message_upload_audio_action_old_struct()),
            0xe9763aec: LazyBound(lambda: self.send_message_upload_video_action_struct()),
            0xf351d7ab: LazyBound(lambda: self.send_message_upload_audio_action_struct()),
            0xfd5ec8f5: LazyBound(lambda: self.send_message_cancel_action_struct()),
            0x16bf744e: LazyBound(lambda: self.send_message_typing_action_struct()),
            0x176f8ba1: LazyBound(lambda: self.send_message_geo_location_action_struct()),
            0x243e1c66: LazyBound(lambda: self.send_message_upload_round_action_struct()),
            0x628cbc6f: LazyBound(lambda: self.send_message_choose_contact_action_struct())
        }
        return 'send_message_action_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def secure_value_type_bank_statement_struct(self):
        return Struct('sname' / Computed('secure_value_type_bank_statement'),
                      'signature' / Hex(Const(0x89137c0d, Int32ul)))

    def secure_value_type_rental_agreement_struct(self):
        return Struct('sname' / Computed('secure_value_type_rental_agreement'),
                      'signature' / Hex(Const(0x8b883488, Int32ul)))

    def secure_value_type_email_struct(self):
        return Struct('sname' / Computed('secure_value_type_email'),
                      'signature' / Hex(Const(0x8e3ca7ee, Int32ul)))

    def secure_value_type_internal_passport_struct(self):
        return Struct(
            'sname' / Computed('secure_value_type_internal_passport'),
            'signature' / Hex(Const(0x99a48f23, Int32ul)))

    def secure_value_type_passport_registration_struct(self):
        return Struct(
            'sname' / Computed('secure_value_type_passport_registration'),
            'signature' / Hex(Const(0x99e3806a, Int32ul)))

    def secure_value_type_personal_details_struct(self):
        return Struct('sname' / Computed('secure_value_type_personal_details'),
                      'signature' / Hex(Const(0x9d2a81e3, Int32ul)))

    def secure_value_type_identity_card_struct(self):
        return Struct('sname' / Computed('secure_value_type_identity_card'),
                      'signature' / Hex(Const(0xa0d0744b, Int32ul)))

    def secure_value_type_phone_struct(self):
        return Struct('sname' / Computed('secure_value_type_phone'),
                      'signature' / Hex(Const(0xb320aadb, Int32ul)))

    def secure_value_type_address_struct(self):
        return Struct('sname' / Computed('secure_value_type_address'),
                      'signature' / Hex(Const(0xcbe31e26, Int32ul)))

    def secure_value_type_temporary_registration_struct(self):
        return Struct(
            'sname' / Computed('secure_value_type_temporary_registration'),
            'signature' / Hex(Const(0xea02ec33, Int32ul)))

    def secure_value_type_utility_bill_struct(self):
        return Struct('sname' / Computed('secure_value_type_utility_bill'),
                      'signature' / Hex(Const(0xfc36954e, Int32ul)))

    def secure_value_type_driver_license_struct(self):
        return Struct('sname' / Computed('secure_value_type_driver_license'),
                      'signature' / Hex(Const(0x06e425c4, Int32ul)))

    def secure_value_type_passport_struct(self):
        return Struct('sname' / Computed('secure_value_type_passport'),
                      'signature' / Hex(Const(0x3dac6a00, Int32ul)))

    def secure_value_type_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xcbe31e26: LazyBound(lambda: self.secure_value_type_address_struct()),
            0x89137c0d: LazyBound(lambda: self.secure_value_type_bank_statement_struct()),
            0x06e425c4: LazyBound(lambda: self.secure_value_type_driver_license_struct()),
            0x8e3ca7ee: LazyBound(lambda: self.secure_value_type_email_struct()),
            0xa0d0744b: LazyBound(lambda: self.secure_value_type_identity_card_struct()),
            0x99a48f23: LazyBound(lambda: self.secure_value_type_internal_passport_struct()),
            0x3dac6a00: LazyBound(lambda: self.secure_value_type_passport_struct()),
            0x99e3806a: LazyBound(lambda: self.secure_value_type_passport_registration_struct()),
            0x9d2a81e3: LazyBound(lambda: self.secure_value_type_personal_details_struct()),
            0xb320aadb: LazyBound(lambda: self.secure_value_type_phone_struct()),
            0x8b883488: LazyBound(lambda: self.secure_value_type_rental_agreement_struct()),
            0xea02ec33: LazyBound(lambda: self.secure_value_type_temporary_registration_struct()),
            0xfc36954e: LazyBound(lambda: self.secure_value_type_utility_bill_struct())
        }
        return 'secure_value_type_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def text_strike_struct(self):
        return Struct(
            'sname' / Computed('text_strike'),
            'signature' / Hex(Const(0x9bf8bb95, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_underline_struct(self):
        return Struct(
            'sname' / Computed('text_underline'),
            'signature' / Hex(Const(0xc12622c4, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_superscript_struct(self):
        return Struct(
            'sname' / Computed('text_superscript'),
            'signature' / Hex(Const(0xc7fb5e01, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_italic_struct(self):
        return Struct(
            'sname' / Computed('text_italic'),
            'signature' / Hex(Const(0xd912a59c, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_empty_struct(self):
        return Struct(
            'sname' / Computed('text_empty'),
            'signature' / Hex(Const(0xdc3d824f, Int32ul)))

    def text_email_struct(self):
        return Struct(
            'sname' / Computed('text_email'),
            'signature' / Hex(Const(0xde5a0dd6, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'email' / self.tstring_struct)

    def text_subscript_struct(self):
        return Struct(
            'sname' / Computed('text_subscript'),
            'signature' / Hex(Const(0xed6a8504, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_marked_struct(self):
        return Struct(
            'sname' / Computed('text_marked'),
            'signature' / Hex(Const(0x034b8621, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_image_struct(self):
        return Struct(
            'sname' / Computed('text_image'),
            'signature' / Hex(Const(0x081ccf4f, Int32ul)),
            'document_id' / Int64ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def text_phone_struct(self):
        return Struct(
            'sname' / Computed('text_phone'),
            'signature' / Hex(Const(0x1ccb966a, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'phone' / self.tstring_struct)

    def text_anchor_struct(self):
        return Struct(
            'sname' / Computed('text_anchor'),
            'signature' / Hex(Const(0x35553762, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'name' / self.tstring_struct)

    def text_url_struct(self):
        return Struct(
            'sname' / Computed('text_url'),
            'signature' / Hex(Const(0x3c2884c1, Int32ul)),
            'text' / self.rich_text_structures('text'),
            'url' / self.tstring_struct,
            'webpage_id' / Int64ul)

    def text_bold_struct(self):
        return Struct(
            'sname' / Computed('text_bold'),
            'signature' / Hex(Const(0x6724abc4, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_fixed_struct(self):
        return Struct(
            'sname' / Computed('text_fixed'),
            'signature' / Hex(Const(0x6c3f19b9, Int32ul)),
            'text' / self.rich_text_structures('text'))

    def text_concat_struct(self):
        return Struct(
            'sname' / Computed('text_concat'),
            'signature' / Hex(Const(0x7e6260d7, Int32ul)),
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'rich_texts_num' / Int32ul,
            'rich_texts' / Array(this.rich_texts_num,
                                 self.rich_text_structures('rich_text')))

    def text_plain_struct(self):
        return Struct(
            'sname' / Computed('text_plain'),
            'signature' / Hex(Const(0x744694e0, Int32ul)),
            'text' / self.tstring_struct)

    def rich_text_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x744694e0: LazyBound(lambda: self.text_plain_struct()),
            0xc12622c4: LazyBound(lambda: self.text_underline_struct()),
            0xc7fb5e01: LazyBound(lambda: self.text_superscript_struct()),
            0xd912a59c: LazyBound(lambda: self.text_italic_struct()),
            0xdc3d824f: LazyBound(lambda: self.text_empty_struct()),
            0xde5a0dd6: LazyBound(lambda: self.text_email_struct()),
            0xed6a8504: LazyBound(lambda: self.text_subscript_struct()),
            0x034b8621: LazyBound(lambda: self.text_marked_struct()),
            0x081ccf4f: LazyBound(lambda: self.text_image_struct()),
            0x1ccb966a: LazyBound(lambda: self.text_phone_struct()),
            0x35553762: LazyBound(lambda: self.text_anchor_struct()),
            0x3c2884c1: LazyBound(lambda: self.text_url_struct()),
            0x6724abc4: LazyBound(lambda: self.text_bold_struct()),
            0x6c3f19b9: LazyBound(lambda: self.text_fixed_struct()),
            0x7e6260d7: LazyBound(lambda: self.text_concat_struct()),
            0x9bf8bb95: LazyBound(lambda: self.text_strike_struct())
        }
        return 'rich_text_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def theme_settings_struct(self):
        return Struct(
            'sname' / Computed('theme_settings'),
            'signature' / Hex(Const(0x9c14984a, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_top_color=1,
                                has_wallpaper=2),
            'base_theme' / self.base_theme_structures('base_theme'),
            'accent_color' / Int32ul,
            'message_top_color' / If(this.flags.has_top_color, Int32ul),
            'message_bottom_color' / If(this.flags.has_top_color, Int32ul),
            'wallpaper' / If(this.flags.has_wallpaper,
                             self.wall_paper_structures('wallpaper')))

    #--------------------------------------------------------------------------

    def user_full_layer98_struct(self):
        return Struct(
            'sname' / Computed('user_full_layer98'),
            'signature' / Hex(Const(0x8ea4a881, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_blocked=1,
                                has_about=2,
                                has_profile_photo=4,
                                has_bot_info=8,
                                phone_calls_available=16,
                                phone_calls_private=32,
                                has_pinned_msg_id=64,
                                can_pin_message=128),
            'user' / self.user_structures('user'),
            'about' / If(this.flags.has_about, self.tstring_struct),
            'link' / self.contacts_link_layer101_struct(),
            'profile_photo' / If(this.flags.has_profile_photo,
                                 self.photo_structures('profile_photo')),
            'notify_settings' / self.peer_notify_settings_structures(
                'notify_settings'),
            'bot_info' / If(this.flags.has_bot_info,
                            self.bot_info_structures('bot_info')),
            'pinned_msg_id' / If(this.flags.has_pinned_msg_id, Int32ul),
            'common_chats_count' / Int32ul)

    def user_full_layer101_struct(self):
        return Struct(
            'sname' / Computed('user_full_layer101'),
            'signature' / Hex(Const(0x745559cc, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_blocked=1,
                                has_about=2,
                                has_profile_photo=4,
                                has_bot_info=8,
                                phone_calls_available=16,
                                phone_calls_private=32,
                                has_pinned_msg_id=64,
                                can_pin_message=128,
                                has_folder_id=2048),
            'user' / self.user_structures('user'),
            'about' / If(this.flags.has_about, self.tstring_struct),
            'link' / self.contacts_link_layer101_struct(),
            'profile_photo' / If(this.flags.has_profile_photo,
                                 self.photo_structures('profile_photo')),
            'notify_settings' / self.peer_notify_settings_structures(
                'notify_settings'),
            'bot_info' / If(this.flags.has_bot_info,
                            self.bot_info_structures('bot_info')),
            'pinned_msg_id' / If(this.flags.has_pinned_msg_id, Int32ul),
            'common_chats_count' / Int32ul,
            'folder_id' / If(this.flags.has_folder_id, Int32ul))

    def user_full_struct(self):
        return Struct(
            'sname' / Computed('user_full'),
            'signature' / Hex(Const(0xedf17c12, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_blocked=1,
                                has_about=2,
                                has_profile_photo=4,
                                has_bot_info=8,
                                phone_calls_available=16,
                                phone_calls_private=32,
                                has_pinned_msg_id=64,
                                can_pin_message=128,
                                has_folder_id=2048,
                                has_scheduled=4096),
            'user' / self.user_structures('user'),
            'about' / If(this.flags.has_about, self.tstring_struct),
            'settings' / self.peer_settings_structures('peer_settings'),
            'profile_photo' / If(this.flags.has_profile_photo,
                                 self.photo_structures('profile_photo')),
            'notify_settings' / self.peer_notify_settings_structures(
                'notify_settings'),
            'bot_info' / If(this.flags.has_bot_info,
                            self.bot_info_structures('bot_info')),
            'pinned_msg_id' / If(this.flags.has_pinned_msg_id, Int32ul),
            'common_chats_count' / Int32ul,
            'folder_id' / If(this.flags.has_folder_id, Int32ul))

    def user_full_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x745559cc: LazyBound(lambda: self.user_full_layer101_struct()),
            0x8ea4a881: LazyBound(lambda: self.user_full_layer98_struct()),
            0xedf17c12: LazyBound(lambda: self.user_full_struct())
        }
        return 'user_full_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def user_layer104_struct(self):
        return Struct(
            'sname' / Computed('user_layer104'),
            'signature' / Hex(Const(0x2e13f4c3, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_access_hash=1,
                                has_first_name=2,
                                has_last_name=4,
                                has_username=8,
                                has_phone=16,
                                has_profile_photo=32,
                                has_status=64,
                                is_self=1024,
                                is_contact=2048,
                                is_mutual_contact=4096,
                                is_deleted=8192,
                                is_bot=16384,
                                is_bot_chat_history=32768,
                                is_bot_no_chats=65536,
                                is_verified=131072,
                                is_restricted=262144,
                                has_lang_code=4194304,
                                has_bot_inline_placeholder=524288,
                                has_min=1048576,
                                is_bot_inline_geo=2097152,
                                is_support=8388608),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'first_name' / If(this.flags.has_first_name, self.tstring_struct),
            'last_name' / If(this.flags.has_last_name, self.tstring_struct),
            'username' / If(this.flags.has_username, self.tstring_struct),
            'phone' / If(this.flags.has_phone, self.tstring_struct),
            'photo' / If(this.flags.has_profile_photo,
                         self.user_profile_photo_structures('photo')),
            'status' / If(this.flags.has_status,
                          self.user_status_structures('status')),
            'bot_info_version' / If(this.flags.is_bot, Int32ul),
            'restriction_reason' / If(this.flags.is_restricted,
                                      self.tstring_struct),
            'bot_inline_placeholder' / If(this.flags.has_bot_inline_placeholder,
                                          self.tstring_struct),
            'lang_code' / If(this.flags.has_lang_code, self.tstring_struct))

    def user_deleted_old_struct(self):
        return Struct(
            'sname' / Computed('user_deleted_old'),
            'signature' / Hex(Const(0xb29ad7cc, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct)

    def user_deleted_old2_struct(self):
        return Struct(
            'sname' / Computed('user_deleted_old2'),
            'signature' / Hex(Const(0xd6016d7a, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct)

    def user_contact_old2_struct(self):
        return Struct(
            'sname' / Computed('user_contact_old2'),
            'signature' / Hex(Const(0xcab35e18, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct,
            'access_hash' / Int64ul,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_layer65_struct(self):
        return Struct(
            'sname' / Computed('user_layer65'),
            'signature' / Hex(Const(0xd10d979a, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_access_hash=1,
                                has_first_name=2,
                                has_last_name=4,
                                has_username=8,
                                has_phone=16,
                                has_profile_photo=32,
                                has_status=64,
                                is_self=1024,
                                is_contact=2048,
                                is_mutual_contact=4096,
                                is_deleted=8192,
                                is_bot=16384,
                                is_bot_chat_history=32768,
                                is_bot_no_chats=65536,
                                is_verified=131072,
                                is_restricted=262144,
                                has_bot_inline_placeholder=524288,
                                has_min=1048576,
                                is_bot_inline_geo=2097152),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'first_name' / If(this.flags.has_first_name, self.tstring_struct),
            'last_name' / If(this.flags.has_last_name, self.tstring_struct),
            'username' / If(this.flags.has_username, self.tstring_struct),
            'phone' / If(this.flags.has_phone, self.tstring_struct),
            'photo' / If(this.flags.has_profile_photo,
                         self.user_profile_photo_structures('photo')),
            'status' / If(this.flags.has_status,
                          self.user_status_structures('status')),
            'bot_info_version' / If(this.flags.is_bot, Int32ul),
            'restriction_reason' / If(this.flags.is_restricted,
                                      self.tstring_struct),
            'bot_inline_placeholder' / If(this.flags.has_bot_inline_placeholder,
                                          self.tstring_struct))

    def user_request_old2_struct(self):
        return Struct(
            'sname' / Computed('user_request_old2'),
            'signature' / Hex(Const(0xd9ccc4ef, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct,
            'access_hash' / Int64ul,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_contact_old_struct(self):
        return Struct(
            'sname' / Computed('user_contact_old'),
            'signature' / Hex(Const(0xf2fb8319, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'access_hash' / Int64ul,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_foreign_old2_struct(self):
        return Struct(
            'sname' / Computed('user_foreign_old2'),
            'signature' / Hex(Const(0x075cf7a8, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct,
            'access_hash' / Int64ul,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_self_old3_struct(self):
        return Struct(
            'sname' / Computed('user_self_old3'),
            'signature' / Hex(Const(0x1c60e608, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_empty_struct(self):
        return Struct(
            'sname' / Computed('user_empty'),
            'signature' / Hex(Const(0x200250ba, Int32ul)),
            'id' / Int32ul)

    def user_old_struct(self):
        return Struct(
            'sname' / Computed('user_old'),
            'signature' / Hex(Const(0x22e49072, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_access_hash=1,
                                has_first_name=2,
                                has_last_name=4,
                                has_username=8,
                                has_phone=16,
                                has_profile_photo=32,
                                has_status=64,
                                is_self=1024,
                                is_contact=2048,
                                is_mutual_contact=4096,
                                is_deleted=8192,
                                is_bot=16384,
                                is_bot_chat_history=32768,
                                is_bot_no_chats=65536,
                                is_verified=131072,
                                is_explicit_content=262144),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'first_name' / If(this.flags.has_first_name, self.tstring_struct),
            'last_name' / If(this.flags.has_last_name, self.tstring_struct),
            'username' / If(this.flags.has_username, self.tstring_struct),
            'phone' / If(this.flags.has_phone, self.tstring_struct),
            'photo' / If(this.flags.has_profile_photo,
                         self.user_profile_photo_structures('photo')),
            'status' / If(this.flags.has_status,
                          self.user_status_structures('status')),
            'bot_info_version' / If(this.flags.is_bot, Int32ul))

    def user_request_old_struct(self):
        return Struct(
            'sname' / Computed('user_request_old'),
            'signature' / Hex(Const(0x22e8ceb0, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'access_hash' / Int64ul,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_foreign_old_struct(self):
        return Struct(
            'sname' / Computed('user_foreign_old'),
            'signature' / Hex(Const(0x5214c89d, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'access_hash' / Int64ul,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'))

    def user_self_old2_struct(self):
        return Struct(
            'sname' / Computed('user_self_old2'),
            'signature' / Hex(Const(0x7007b451, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'username' / self.tstring_struct,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'),
            'inactive' / self.tbool_struct)

    def user_self_old_struct(self):
        return Struct(
            'sname' / Computed('user_self_old'),
            'signature' / Hex(Const(0x720535ec, Int32ul)),
            'id' / Int32ul,
            'first_name' / self.tstring_struct,
            'last_name' / self.tstring_struct,
            'phone' / self.tstring_struct,
            'photo' / self.user_profile_photo_structures('photo'),
            'status' / self.user_status_structures('status'),
            'inactive' / self.tbool_struct)

    def user_struct(self):
        return Struct(
            'sname' / Computed('user_struct'),
            'signature' / Hex(Const(0x938458c1, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_access_hash=1,
                                has_first_name=2,
                                has_last_name=4,
                                has_username=8,
                                has_phone=16,
                                has_profile_photo=32,
                                has_status=64,
                                is_self=1024,
                                is_contact=2048,
                                is_mutual_contact=4096,
                                is_deleted=8192,
                                is_bot=16384,
                                is_bot_chat_history=32768,
                                is_bot_no_chats=65536,
                                is_min=1048576,
                                is_verified=131072,
                                is_bot_inline_geo=2097152,
                                is_restricted=262144,
                                is_support=8388608),
            'id' / Int32ul,
            'access_hash' / If(this.flags.has_access_hash, Int64ul),
            'first_name' / If(this.flags.has_first_name, self.tstring_struct),
            'last_name' / If(this.flags.has_last_name, self.tstring_struct),
            'username' / If(this.flags.has_username, self.tstring_struct),
            'phone' / If(this.flags.has_phone, self.tstring_struct),
            'photo' / If(this.flags.has_profile_photo,
                         self.user_profile_photo_structures('photo')),
            'status' / If(this.flags.has_status,
                          self.user_status_structures('status')),
            'bot_info_version' / If(this.flags.is_bot, Int32ul),
            'restrictions' / If(this.flags.is_restricted, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'restrictions_num' / Int32ul,
                'restrictions_array' / Array(
                    this.restrictions_num,
                    self.restriction_reason_struct()))))


    def user_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x938458c1: LazyBound(lambda: self.user_struct()),
            0x2e13f4c3: LazyBound(lambda: self.user_layer104_struct()),
            0xb29ad7cc: LazyBound(lambda: self.user_deleted_old_struct()),
            0xcab35e18: LazyBound(lambda: self.user_contact_old2_struct()),
            0xd10d979a: LazyBound(lambda: self.user_layer65_struct()),
            0xd6016d7a: LazyBound(lambda: self.user_deleted_old2_struct()),
            0xd9ccc4ef: LazyBound(lambda: self.user_request_old2_struct()),
            0xf2fb8319: LazyBound(lambda: self.user_contact_old_struct()),
            0x075cf7a8: LazyBound(lambda: self.user_foreign_old2_struct()),
            0x1c60e608: LazyBound(lambda: self.user_self_old3_struct()),
            0x200250ba: LazyBound(lambda: self.user_empty_struct()),
            0x22e49072: LazyBound(lambda: self.user_old_struct()),
            0x22e8ceb0: LazyBound(lambda: self.user_request_old_struct()),
            0x5214c89d: LazyBound(lambda: self.user_foreign_old_struct()),
            0x7007b451: LazyBound(lambda: self.user_self_old2_struct()),
            0x720535ec: LazyBound(lambda: self.user_self_old_struct())
        }
        return 'user_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def user_profile_photo_empty_struct(self):
        return Struct('sname' / Computed('user_profile_photo_empty'),
                      'signature' / Hex(Const(0x4f11bae1, Int32ul)))

    def user_profile_photo_layer97_struct(self):
        return Struct(
            'sname' / Computed('user_profile_photo_layer97'),
            'signature' / Hex(Const(0xd559d8c8, Int32ul)),
            'photo_id' / Int64ul,
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'))

    def user_profile_photo_old_struct(self):
        return Struct(
            'sname' / Computed('user_profile_photo_old'),
            'signature' / Hex(Const(0x990d1493, Int32ul)),
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'))

    def user_profile_photo_layer115_struct(self):
        return Struct(
            'sname' / Computed('user_profile_photo_layer115'),
            'signature' / Hex(Const(0xecd75d8c, Int32ul)),
            'photo_id' / Int64ul,
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'),
            'dc_id' / Int32ul)

    def user_profile_photo_struct(self):
        return Struct(
            'sname' / Computed('user_profile_photo'),
            'signature' / Hex(Const(0x69d3ab26, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_video=1),
            'photo_id' / Int64ul,
            'photo_small' / self.file_location_structures('photo_small'),
            'photo_big' / self.file_location_structures('photo_big'),
            'dc_id' / Int32ul)

    def user_profile_photo_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x69d3ab26: LazyBound(lambda: self.user_profile_photo_struct()),
            0xecd75d8c: LazyBound(lambda: self.user_profile_photo_layer115_struct()),
            0xd559d8c8: LazyBound(lambda: self.user_profile_photo_layer97_struct()),
            0x4f11bae1: LazyBound(lambda: self.user_profile_photo_empty_struct()),
            0x990d1493: LazyBound(lambda: self.user_profile_photo_old_struct())
        }
        return 'user_profile_photo_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def user_status_recently_struct(self):
        return Struct(
            'sname' / Computed('user_status_recently'),
            'signature' / Hex(Const(0xe26f42f1, Int32ul)))

    def user_status_online_struct(self):
        return Struct(
            'sname' / Computed('user_status_online'),
            'signature' / Hex(Const(0xedb93949, Int32ul)),
            'expires' / Int32ul)

    def user_status_offline_struct(self):
        return Struct(
            'sname' / Computed('user_status_offline'),
            'signature' / Hex(Const(0x008c703f, Int32ul)),
            'expires' / Int32ul)

    def user_status_last_week_struct(self):
        return Struct(
            'sname' / Computed('user_status_last_week'),
            'signature' / Hex(Const(0x07bf09fc, Int32ul)))

    def user_status_last_month_struct(self):
        return Struct(
            'sname' / Computed('user_status_last_month'),
            'signature' / Hex(Const(0x77ebc742, Int32ul)))

    def user_status_empty_struct(self):
        return Struct(
            'sname' / Computed('user_status_empty'),
            'signature' / Hex(Const(0x09d05049, Int32ul)))

    def user_status_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xe26f42f1: LazyBound(lambda: self.user_status_recently_struct()),
            0xedb93949: LazyBound(lambda: self.user_status_online_struct()),
            0x008c703f: LazyBound(lambda: self.user_status_offline_struct()),
            0x07bf09fc: LazyBound(lambda: self.user_status_last_week_struct()),
            0x09d05049: LazyBound(lambda: self.user_status_empty_struct()),
            0x77ebc742: LazyBound(lambda: self.user_status_last_month_struct())
        }
        return 'user_status_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def video_empty_layer45_struct(self):
        return Struct(
            'sname' / Computed('video_empty_layer45'),
            'signature' / Hex(Const(0xc10658a8, Int32ul)),
            'id' / Int64ul)

    def video_old3_struct(self):
        return Struct(
            'sname' / Computed('video_old3'),
            'signature' / Hex(Const(0xee9f4a4d, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def video_layer45_struct(self):
        return Struct(
            'sname' / Computed('video_layer45'),
            'signature' / Hex(Const(0xf72887d3, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'date' / self.ttimestamp_struct,
            'duration' / Int32ul,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def video_old2_struct(self):
        return Struct(
            'sname' / Computed('video_old2'),
            'signature' / Hex(Const(0x388fa391, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'caption' / self.tstring_struct,
            'duration' / Int32ul,
            'mime_type' / self.tstring_struct,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def video_encrypted_struct(self):
        return Struct(
            'sname' / Computed('video_encrypted'),
            'signature' / Hex(Const(0x55555553, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'caption' / self.tstring_struct,
            'duration' / Int32ul,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul,
            'key' / self.tbytes_struct,
            'iv' / self.tbytes_struct)

    def video_old_struct(self):
        return Struct(
            'sname' / Computed('video_old'),
            'signature' / Hex(Const(0x5a04a49f, Int32ul)),
            'id' / Int64ul,
            'access_hash' / Int64ul,
            'user_id' / Int32ul,
            'date' / self.ttimestamp_struct,
            'caption' / self.tstring_struct,
            'duration' / Int32ul,
            'size' / Int32ul,
            'thumb' / self.photo_size_structures('thumb'),
            'dc_id' / Int32ul,
            'w' / Int32ul,
            'h' / Int32ul)

    def video_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xc10658a8: LazyBound(lambda: self.video_empty_layer45_struct()),
            0xee9f4a4d: LazyBound(lambda: self.video_old3_struct()),
            0xf72887d3: LazyBound(lambda: self.video_layer45_struct()),
            0x388fa391: LazyBound(lambda: self.video_old2_struct()),
            0x55555553: LazyBound(lambda: self.video_encrypted_struct()),
            0x5a04a49f: LazyBound(lambda: self.video_old_struct())
        }
        return 'video_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def video_size_struct(self):
        return Struct(
            'sname' / Computed('video_size'),
            'signature' / Hex(Const(0xe831c556, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_video_start_ts=1),
            'type' / self.tstring_struct,
            'location' / self.file_location_structures('location'),
            'w' / Int32ul,
            'h' / Int32ul,
            'size' / Int32ul,
            'video_start_ts' / If(this.flags.has_video_start_ts, Double))

    def video_size_layer115_struct(self):
        return Struct(
            'sname' / Computed('video_size_layer115'),
            'signature' / Hex(Const(0x435bb987, Int32ul)),
            'type' / self.tstring_struct,
            'location' / self.file_location_structures('location'),
            'w' / Int32ul,
            'h' / Int32ul,
            'size' / Int32ul)

    def video_size_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xe831c556: LazyBound(lambda: self.video_size_struct()),
            0x435bb987: LazyBound(lambda: self.video_size_layer115_struct())
        }
        return 'video_size_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def wall_paper_settings_layer106_struct(self):
        return Struct(
            'sname' / Computed('wall_paper_settings_layer106'),
            'signature' / Hex(Const(0xa12f40b8, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_background_color=1,
                                is_blur=2,
                                is_motion=4,
                                has_intensity=8),
            'background_color' / If(this.flags.has_background_color, Int32ul),
            'intensity' / If(this.flags.has_intensity, Int32ul))

    def wall_paper_settings_struct(self):
        return Struct(
            'sname' / Computed('wall_paper_settings'),
            'signature' / Hex(Const(0x05086cf8, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_background_color=1,
                                is_blur=2,
                                is_motion=4,
                                has_intensity=8,
                                has_second_background_color=16),
            'background_color' / If(this.flags.has_background_color, Int32ul),
            'second_background_color' / If(
                this.flags.has_second_background_color, Int32ul),
            'intensity' / If(this.flags.has_intensity, Int32ul),
            'rotation' / If(this.flags.has_second_background_color, Int32ul))

    def wall_paper_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xa12f40b8: LazyBound(lambda: self.wall_paper_settings_layer106_struct()),
            0x05086cf8: LazyBound(lambda: self.wall_paper_settings_struct())
        }
        return 'wall_paper_settings_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def wall_paper_no_file_struct(self):
        return Struct(
            'sname' / Computed('wall_paper_no_file'),
            'signature' / Hex(Const(0x8af40b25, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                is_default=2,
                                has_wallpaper_settings=4,
                                is_dark=16),
            'wallpaper_settings' / If(
                this.flags.has_wallpaper_settings,
                self.wall_paper_settings_structures('wall_paper_settings')))

    def wall_paper_layer94_struct(self):
        return Struct(
            'sname' / Computed('wall_paper_layer94'),
            'signature' / Hex(Const(0xf04f91ec, Int32ul)),
            'id' / Int64ul,
            'flags' / FlagsEnum(Int32ul,
                                is_creator=1,
                                is_default=2),
            'access_hash' / Int64ul,
            'slug' / self.tstring_struct,
            'document' / self.document_structures('document'))

    def wall_paper_struct(self):
        return Struct(
            'sname' / Computed('wall_paper'),
            'signature' / Hex(Const(0xa437c3ed, Int32ul)),
            'id' / Int64ul,
            'flags' / FlagsEnum(Int32ul,
                                creator=1,
                                default=2,
                                wallpaper_settings=4,
                                pattern=8,
                                dark=16),
            'access_hash' / Int64ul,
            'slug' / self.tstring_struct,
            'document' / self.document_structures('document'),
            'wallpaper_settings' / If(
                this.flags.wallpaper_settings,
                self.wall_paper_settings_structures('wall_paper_settings')))

    def wall_paper_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xa437c3ed: LazyBound(lambda: self.wall_paper_struct()),
            0x8af40b25: LazyBound(lambda: self.wall_paper_no_file_struct()),
            0xf04f91ec: LazyBound(lambda: self.wall_paper_layer94_struct())
        }
        return 'wall_paper_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def web_document_layer81_struct(self):
        return Struct(
            'sname' / Computed('web_document_layer81'),
            'signature' / Hex(Const(0xc61acbd8, Int32ul)),
            'url' / self.tstring_struct,
            'access_hash' / Int64ul,
            'size' / Int32ul,
            'mime_type' / self.tstring_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document_attribute')))

    def web_document_no_proxy_struct(self):
        return Struct(
            'sname' / Computed('web_document_no_proxy'),
            'signature' / Hex(Const(0xf9c8bcc6, Int32ul)),
            'url' / self.tstring_struct,
            'size' / Int32ul,
            'mime_type' / self.tstring_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document_attribute')))

    def web_document_struct(self):
        return Struct(
            'sname' / Computed('web_document'),
            'signature' / Hex(Const(0x1c570ed1, Int32ul)),
            'url' / self.tstring_struct,
            'access_hash' / Int64ul,
            'size' / Int32ul,
            'mime_type' / self.tstring_struct,
            '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
            'document_attributes_num' / Int32ul,
            'document_attributes' / Array(
                this.document_attributes_num,
                self.document_attribute_structures('document_attribute')))

    def web_document_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xc61acbd8: LazyBound(lambda: self.web_document_layer81_struct()),
            0xf9c8bcc6: LazyBound(lambda: self.web_document_no_proxy_struct()),
            0x1c570ed1: LazyBound(lambda: self.web_document_struct())
        }
        return 'web_document_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------

    def web_page_attribute_theme_struct(self):
        return Struct(
            'sname' / Computed('web_page_attribute_theme'),
            'signature' / Hex(Const(0x54b56617, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_documents=1,
                                has_theme_settings=2),
            'documents' / If(this.flags.has_documents, Struct(
                '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                'documents_num' / Int32ul,
                'documents_array' / Array(
                    this.documents_num,
                    self.document_structures('document')))),
            'theme_settings' / If(this.flags.has_theme_settings,
                                  self.theme_settings_struct()))

    #--------------------------------------------------------------------------

    def web_page_not_modified_struct(self):
        return Struct(
            'sname' / Computed('web_page_not_modified'),
            'signature' / Hex(Const(0x7311ca11, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_cached_page_views=1),
            'cached_page_views' / If(this.flags.has_cached_page_views, Int32ul))

    def web_page_not_modified_layer110_struct(self):
        return Struct(
            'sname' / Computed('web_page_not_modified_layer110'),
            'signature' / Hex(Const(0x85849473, Int32ul)))

    def web_page_old_struct(self):
        return Struct(
            'sname' / Computed('web_page_old'),
            'signature' / Hex(Const(0xa31ea0b5, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_type=1,
                                has_site_name=2,
                                has_title=4,
                                has_description=8,
                                has_photo=16,
                                has_embed_url=32,
                                has_embed_media=64,
                                has_duration=128,
                                has_author=256),
            'id' / Int64ul,
            'url' / self.tstring_struct,
            'display_url' / self.tstring_struct,
            'type' / If(this.flags.has_type, self.tstring_struct),
            'site_name' / If(this.flags.has_site_name, self.tstring_struct),
            'title' / If(this.flags.has_title, self.tstring_struct),
            'description' / If(this.flags.has_description, self.tstring_struct),
            'photo' / If(this.flags.has_photo, self.photo_structures('photo')),
            'embed_url' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_type' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_width' / If(this.flags.has_embed_media, Int32ul),
            'embed_height' / If(this.flags.has_embed_media, Int32ul),
            'duration' / If(this.flags.has_duration, Int32ul),
            'author' / If(this.flags.has_author, self.tstring_struct))

    def web_page_pending_struct(self):
        return Struct(
            'sname' / Computed('web_page_pending'),
            'signature' / Hex(Const(0xc586da1c, Int32ul)),
            'id' / Int64ul,
            'date' / Int32ul)

    def web_page_layer58_struct(self):
        return Struct(
            'sname' / Computed('web_page_layer58'),
            'signature' / Hex(Const(0xca820ed7, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_type=1,
                                has_site_name=2,
                                has_title=4,
                                has_description=8,
                                has_photo=16,
                                has_embed_url=32,
                                has_embed_media=64,
                                has_duration=128,
                                has_author=256,
                                has_document=512),
            'id' / Int64ul,
            'url' / self.tstring_struct,
            'display_url' / self.tstring_struct,
            'type' / If(this.flags.has_type, self.tstring_struct),
            'site_name' / If(this.flags.has_site_name, self.tstring_struct),
            'title' / If(this.flags.has_title, self.tstring_struct),
            'description' / If(this.flags.has_description, self.tstring_struct),
            'photo' / If(this.flags.has_photo, self.photo_structures('photo')),
            'embed_url' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_type' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_width' / If(this.flags.has_embed_media, Int32ul),
            'embed_height' / If(this.flags.has_embed_media, Int32ul),
            'duration' / If(this.flags.has_duration, Int32ul),
            'author' / If(this.flags.has_author, self.tstring_struct),
            'document' / If(this.flags.has_document,
                            self.document_structures('document')))

    def web_page_url_pending_struct(self):
        return Struct(
            'sname' / Computed('web_page_url_pending'),
            'signature' / Hex(Const(0xd41a5167, Int32ul)),
            'url' / self.tstring_struct)

    def web_page_empty_struct(self):
        return Struct(
            'sname' / Computed('web_page_empty'),
            'signature' / Hex(Const(0xeb1477e8, Int32ul)),
            'id' / Int64ul)

    def web_page_layer104_struct(self):
        return Struct(
            'sname' / Computed('web_page_layer104'),
            'signature' / Hex(Const(0x5f07b4bc, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                has_type=1,
                                has_site_name=2,
                                has_title=4,
                                has_description=8,
                                has_photo=16,
                                has_embed_url=32,
                                has_embed_media=64,
                                has_duration=128,
                                has_author=256,
                                has_document=512,
                                is_cached=1024),
            'id' / Int64ul,
            'url' / self.tstring_struct,
            'display_url' / self.tstring_struct,
            'hash' / Int32ul,
            'type' / If(this.flags.has_type, self.tstring_struct),
            'site_name' / If(this.flags.has_site_name, self.tstring_struct),
            'title' / If(this.flags.has_title, self.tstring_struct),
            'description' / If(this.flags.has_description, self.tstring_struct),
            'photo' / If(this.flags.has_photo, self.photo_structures('photo')),
            'embed_url' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_type' / If(this.flags.has_embed_url, self.tstring_struct),
            'embed_width' / If(this.flags.has_embed_media, Int32ul),
            'embed_height' / If(this.flags.has_embed_media, Int32ul),
            'duration' / If(this.flags.has_duration, Int32ul),
            'author' / If(this.flags.has_author, self.tstring_struct),
            'document' / If(this.flags.has_document,
                            self.document_structures('document')),
            'cached_page' / If(this.flags.is_cached,
                               self.page_structures('cached_page')))

    def web_page_layer107_struct(self):
        return Struct(
            'sname' / Computed('web_page_layer107'),
            'signature' / Hex(Const(0xfa64e172, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                type=1,
                                site_name=2,
                                title=4,
                                description=8,
                                photo=16,
                                embed_url=32,
                                embed_media=64,
                                duration=128,
                                author=256,
                                document=512,
                                cached=1024,
                                has_webpage_attr_theme=2048),
            'id' / Int64ul,
            'url' / self.tstring_struct,
            'display_url' / self.tstring_struct,
            'hash' / Int32ul,
            'type' / If(this.flags.type, self.tstring_struct),
            'site_name' / If(this.flags.site_name, self.tstring_struct),
            'title' / If(this.flags.title, self.tstring_struct),
            'description' / If(this.flags.description, self.tstring_struct),
            'photo' / If(this.flags.photo, self.photo_structures('photo')),
            'embed_url' / If(this.flags.embed_url, self.tstring_struct),
            'embed_type' / If(this.flags.embed_url, self.tstring_struct),
            'embed_width' / If(this.flags.embed_media, Int32ul),
            'embed_height' / If(this.flags.embed_media, Int32ul),
            'duration' / If(this.flags.duration, Int32ul),
            'author' / If(this.flags.author, self.tstring_struct),
            'document' / If(this.flags.document,
                            self.document_structures('document')),
            'webpage_attribute_theme' / If(
                this.flags.has_webpage_attr_theme,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'documents_num' / Int32ul,
                    'documents_array' / Array(
                        this.documents_num,
                        self.document_structures('document')))),
            'cached_page' / If(this.flags.cached,
                               self.page_structures('cached_page')))

    def web_page_struct(self):
        return Struct(
            'sname' / Computed('web_page'),
            'signature' / Hex(Const(0xe89c45b2, Int32ul)),
            'flags' / FlagsEnum(Int32ul,
                                type=1,
                                site_name=2,
                                title=4,
                                description=8,
                                photo=16,
                                embed_url=32,
                                embed_media=64,
                                duration=128,
                                author=256,
                                document=512,
                                cached=1024,
                                webpage_attr_theme=4096),
            'id' / Int64ul,
            'url' / self.tstring_struct,
            'display_url' / self.tstring_struct,
            'hash' / Int32ul,
            'type' / If(this.flags.type, self.tstring_struct),
            'site_name' / If(this.flags.site_name, self.tstring_struct),
            'title' / If(this.flags.title, self.tstring_struct),
            'description' / If(this.flags.description, self.tstring_struct),
            'photo' / If(this.flags.photo, self.photo_structures('photo')),
            'embed_url' / If(this.flags.embed_url, self.tstring_struct),
            'embed_type' / If(this.flags.embed_url, self.tstring_struct),
            'embed_width' / If(this.flags.embed_media, Int32ul),
            'embed_height' / If(this.flags.embed_media, Int32ul),
            'duration' / If(this.flags.duration, Int32ul),
            'author' / If(this.flags.author, self.tstring_struct),
            'document' / If(this.flags.document,
                            self.document_structures('document')),
            'cached_page' / If(this.flags.cached,
                               self.page_structures('cached_page')),
            'webpage_attribute_theme' / If(
                this.flags.webpage_attr_theme,
                Struct(
                    '_vector_sig' / Hex(Const(0x1cb5c415, Int32ul)),
                    'webpage_attribute_num' / Int32ul,
                    'webpage_attribute_array' / Array(
                        this.webpage_attribute_num,
                        self.web_page_attribute_theme_struct()))))

    def web_page_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xe89c45b2: LazyBound(lambda: self.web_page_struct()),
            0x5f07b4bc: LazyBound(lambda: self.web_page_layer104_struct()),
            0xfa64e172: LazyBound(lambda: self.web_page_layer107_struct()),
            0xd41a5167: LazyBound(lambda: self.web_page_url_pending_struct()),
            0xca820ed7: LazyBound(lambda: self.web_page_layer58_struct()),
            0xc586da1c: LazyBound(lambda: self.web_page_pending_struct()),
            0xa31ea0b5: LazyBound(lambda: self.web_page_old_struct()),
            0x7311ca11: LazyBound(lambda: self.web_page_not_modified_struct()),
            0x85849473: LazyBound(lambda: self.web_page_not_modified_layer110_struct()),
            0xeb1477e8: LazyBound(lambda: self.web_page_empty_struct())
        }
        return 'web_page_structures' / Struct(
            '_signature' / Peek(Int32ul),
            name / Switch(this._signature, tag_map))

    #--------------------------------------------------------------------------
    # Telegram TDSs definitions
    # Actual version created mixing versions: 0.1.137, 5.5.0, 5.6.2
    #--------------------------------------------------------------------------

    tdss_callbacks = {
        # pylint: disable=C0301
        0xb8d0afdf: (None, 'account_days_ttl', None),  # -1194283041
        0xe7027c94: (None, 'account_accept_authorization', None),  # -419267436
        0xad2e1cd8: (None, 'account_authorization_form', None),  # -1389486888
        0x1250abde: (None, 'account_authorizations', None),  # 307276766
        0x63cacf26: (None, 'account_auto_download_settings', None),  # 1674235686
        0xc1cbd5b6: (None, 'account_cancel_password_email', None),  # -1043606090
        0x70c32edb: (None, 'account_change_phone', None),  # 1891839707
        0x2714d86c: (None, 'account_check_username', None),  # 655677548
        0x8fdf1920: (None, 'account_confirm_password_email', None),  # -1881204448
        0x5f2178c3: (None, 'account_confirm_phone', None),  # 1596029123
        0x8432c21f: (None, 'account_create_theme', None), # -2077048289
        0x418d4e0b: (None, 'account_delete_account', None),  # 1099779595
        0xb880bc4b: (None, 'account_delete_secure_value', None),  # -1199522741
        0x08fc711d: (None, 'account_get_account_ttl', None),  # 150761757
        0xb288bc7d: (None, 'account_get_all_secure_values', None),  # -1299661699
        0xb86ba8e1: (None, 'account_get_authorization_form', None),  # -1200903967
        0xe320c158: (None, 'account_get_authorizations', None),  # -484392616
        0x56da0b3f: (None, 'account_get_auto_download_settings', None),  # 1457130303
        0x9f07c728: (None, 'account_get_contact_sign_up_notification', None),  # -1626880216
        0xeb2b4cf6: (None, 'account_get_global_privacy_settings', None), # -349483786
        0x65ad71dc: (None, 'account_get_multi_wall_papers', None), # 1705865692
        0x53577479: (None, 'account_get_notify_exceptions', None),  # 1398240377
        0x12b3ad31: (None, 'account_get_notify_settings', None),  # 313765169
        0x548a30f5: (None, 'account_get_password', None),  # 1418342645
        0x9cd4eaf9: (None, 'account_get_password_settings', None),  # -1663767815
        0xdadbc950: (None, 'account_get_privacy', None),  # -623130288
        0x73665bc2: (None, 'account_get_secure_value', None),  # 1936088002
        0x8d9d742b: (None, 'account_get_theme', None), # -1919060949
        0x285946f8: (None, 'account_get_themes', None), # 676939512
        0x449e0b51: (None, 'account_get_tmp_password', None),  # 1151208273
        0xfc8ddbea: (None, 'account_get_wall_paper', None),  # -57811990
        0xaabb1763: (None, 'account_get_wall_papers', None),  # -1430579357
        0xc04cfac2: (None, 'account_get_wall_papers_v_0_1_317'),  # -1068696894
        0x182e6d6f: (None, 'account_get_web_authorizations', None),  # 405695855
        0x7ae43737: (None, 'account_install_theme', None), # 2061776695
        0xfeed5769: (None, 'account_install_wall_paper', None),  # -18000023
        0xad2641f8: (None, 'account_password', None),  # -1390001672
        0xc23727c9: (None, 'account_password_input_settings', None),  # -1036572727
        0x9a5c33e5: (None, 'account_password_settings', None),  # -1705233435
        0x50a04e45: (None, 'account_privacy_rules', None), # 1352683077
        0x68976c6f: (None, 'account_register_device', None), # 1754754159
        0x554abb6f: (None, 'account_privacy_rules_v_5_6_2', None), # 1430961007
        0x446c712c: (None, 'account_register_device_v_0_1_317', None), # 1147957548
        0x5cbea590: (None, 'account_register_device_v_5_6_2', None), # 1555998096
        0xae189d5f: (None, 'account_report_peer', None),  # -1374118561
        0x7a7f2a15: (None, 'account_resend_password_email', None),  # 2055154197
        0xdf77f3bc: (None, 'account_reset_authorization', None),  # -545786948
        0xdb7e1747: (None, 'account_reset_notify_settings', None),  # -612493497
        0xbb3b9804: (None, 'account_reset_wall_papers', None),  # -1153722364
        0x2d01b9ef: (None, 'account_reset_web_authorization', None),  # 755087855
        0x682d2594: (None, 'account_reset_web_authorizations', None),  # 1747789204
        0x76f36233: (None, 'account_save_auto_download_settings', None),  # 1995661875
        0x899fe31d: (None, 'account_save_secure_value', None),  # -1986010339
        0xf257106c: (None, 'account_save_theme', None), # -229175188
        0x6c5a5b37: (None, 'account_save_wall_paper', None),  # 1817860919
        0x82574ae5: (None, 'account_send_change_phone_code', None),  # -2108208411
        0x1b3faa88: (None, 'account_send_confirm_phone_code', None),  # 457157256
        0x7011509f: (None, 'account_send_verify_email_code', None),  # 1880182943
        0xa5a356f9: (None, 'account_send_verify_phone_code', None),  # -1516022023
        0x811f854f: (None, 'account_sent_email_code', None),  # -2128640689
        0x2442485e: (None, 'account_set_account_ttl', None),  # 608323678
        0xcff43f61: (None, 'account_set_contact_sign_up_notification', None),  # -806076575
        0x1edaaac2: (None, 'account_set_global_privacy_settings', None), # 517647042
        0xc9f81ce8: (None, 'account_set_privacy', None),  # -906486552
        0x7f676421: (None, 'account_themes', None), # 2137482273
        0xf41eb622: (None, 'account_themes_not_modified', None), # -199313886
        0xdb64fd34: (None, 'account_tmp_password', None),  # -614138572
        0x3076c4bf: (None, 'account_unregister_device', None),  # 813089983
        0x65c55b40: (None, 'account_unregister_device_v_0_1_317'),  # 1707432768
        0x38df3532: (None, 'account_update_device_locked', None),  # 954152242
        0x84be5b93: (None, 'account_update_notify_settings', None),  # -2067899501
        0xa59b102f: (None, 'account_update_password_settings', None),  # -1516564433
        0x78515775: (None, 'account_update_profile', None),  # 2018596725
        0xf0888d68: (None, 'account_update_profile_v_0_1_317'),  # -259486360
        0x6628562c: (None, 'account_update_status', None),  # 1713919532
        0x5cb367d5: (None, 'account_update_theme', None), # 1555261397
        0x3e0bdd7c: (None, 'account_update_username', None),  # 1040964988
        0x1c3db333: (None, 'account_upload_theme', None), # 473805619
        0xdd853661: (None, 'account_upload_wall_paper', None),  # -578472351
        0xecba39db: (None, 'account_verify_email', None),  # -323339813
        0x4dd3a7f6: (None, 'account_verify_phone', None),  # 1305716726
        0x702b65a9: (None, 'account_wall_papers', None),  # 1881892265
        0x1c199183: (None, 'account_wall_papers_not_modified', None),  # 471437699
        0xed56c9fc: (None, 'account_web_authorizations', None),  # -313079300
        0x586988d8: (audio_empty_layer45_struct, 'audio_empty_layer45', None),  # 1483311320
        0x555555f6: (audio_encrypted_struct, 'audio_encrypted', None),  # 1431655926
        0xf9e35055: (audio_layer45_struct, 'audio_layer45', None),  # -102543275
        0x427425e7: (audio_old_struct, 'audio_old', None),  # 1114908135
        0xc7ac6496: (audio_old2_struct, 'audio_old2', None),  # -945003370
        0xe894ad4d: (None, 'auth_accept_login_token', None), # -392909491
        0xcd050916: (None, 'auth_authorization', None),  # -855308010
        0x44747e9a: (None, 'auth_authorization_sign_up_required', None), # 1148485274
        0xf6b673a4: (None, 'auth_authorization_v_0_1_317'),  # -155815004
        0x1f040578: (None, 'auth_cancel_code', None),  # 520357240
        0xd18b4d16: (None, 'auth_check_password', None),  # -779399914
        0x6fe51dfb: (None, 'auth_check_phone_v_5_6_2', None),  # 1877286395
        0x811ea28e: (None, 'auth_checked_phone_v_5_6_2', None),  # -2128698738
        0xe300cc3b: (None, 'auth_checked_phone_v_0_1_317'),  # -486486981
        0x741cd3e3: (None, 'auth_code_type_call', None),  # 1948046307
        0x226ccefb: (None, 'auth_code_type_flash_call', None),  # 577556219
        0x72a3158c: (None, 'auth_code_type_sms', None),  # 1923290508
        0xe5bfffcd: (None, 'auth_export_authorization', None),  # -440401971
        0xdf969c2d: (None, 'auth_exported_authorization', None),  # -543777747
        0xb1b41517: (None, 'auth_export_login_token', None), # -1313598185
        0xe3ef9613: (None, 'auth_import_authorization', None),  # -470837741
        0x95ac5ce4: (None, 'auth_import_login_token', None), # -1783866140
        0x5717da40: (None, 'auth_log_out', None),  # 1461180992
        0x629f1980: (None, 'auth_login_token', None), # 1654593920
        0x068e9916: (None, 'auth_login_token_migrate_to', None), # 110008598
        0x390d5c5e: (None, 'auth_login_token_success', None), # 957176926
        0x137948a5: (None, 'auth_password_recovery', None),  # 326715557
        0x4ea56e92: (None, 'auth_recover_password', None),  # 1319464594
        0xd897bc66: (None, 'auth_request_password_recovery', None),  # -661144474
        0x3ef1a9bf: (None, 'auth_resend_code', None),  # 1056025023
        0x9fab0d1a: (None, 'auth_reset_authorizations', None),  # -1616179942
        0x03c51564: (None, 'auth_send_call_v_0_1_317'),  # 63247716
        0xa677244f: (None, 'auth_send_code', None),  # -1502141361
        0x768d5f4d: (None, 'auth_send_code_v_0_1_317'),  # 1988976461
        0x771c1d97: (None, 'auth_send_invites_v_0_1_317'),  # 1998331287
        0x5e002502: (None, 'auth_sent_code', None), # 1577067778
        0x38faab5f: (None, 'auth_sent_code_v_5_6_2', None),  # 955951967
        0x2215bcbd: (None, 'auth_sent_code_v_0_1_317'),  # 571849917
        0x3dbb5986: (None, 'auth_sent_code_type_app', None),  # 1035688326
        0x5353e5a7: (None, 'auth_sent_code_type_call', None),  # 1398007207
        0xab03c6d9: (None, 'auth_sent_code_type_flash_call', None),  # -1425815847
        0xc000bba2: (None, 'auth_sent_code_type_sms', None),  # -1073693790
        0xbcd51581: (None, 'auth_sign_in', None),  # -1126886015
        0x80eee427: (None, 'auth_sign_up', None), # -2131827673
        0x1b067634: (None, 'auth_sign_up_v_5_6_2', None),  # 453408308
        0xad01d61d: (None, 'authorization', None),  # -1392388579
        0xe04232f3: (None, 'auto_download_settings', None), # -532532493
        0xd246fd47: (None, 'auto_download_settings_v_5_6_2', None),  # -767099577
        0xa7eff811: (None, 'bad_msg_notification_v_0_1_317'),  # -1477445615
        0xedab447b: (None, 'bad_server_salt_v_0_1_317'),  # -307542917
        0xf568028a: (None, 'bank_card_open_url', None), # -177732982
        0x5b11125a: (base_theme_arctic_struct, 'base_theme_arctic', None), # 1527845466
        0xc3a12462: (base_theme_classic_struct, 'base_theme_classic', None), # -1012849566
        0xfbd81688: (base_theme_day_struct, 'base_theme_day', None), # -69724536
        0xb7b31ea8: (base_theme_night_struct, 'base_theme_night', None), # -1212997976
        0x6d5f77ee: (base_theme_tinted_struct, 'base_theme_tinted', None), # 1834973166
        0xbc799737: (None, 'bool_false', None),  # -1132882121 [implemented]
        0x997275b5: (None, 'bool_true', None),  # -1720552011 [implemented]
        0xc27ac8c7: (bot_command_struct, 'bot_command', None),  # -1032140601
        0x98e81d3a: (bot_info_struct, 'bot_info', None),  # -1729618630
        0xbb2e37ce: (bot_info_empty_layer48_struct, 'bot_info_empty_layer48', None),  # -1154598962
        0x09cf585d: (bot_info_layer48_struct, 'bot_info_layer48', None),  # 164583517
        0x17db940b: (None, 'bot_inline_media_result', None),  # 400266251
        0x764cf810: (None, 'bot_inline_message_media_auto', None),  # 1984755728
        0x0a74b15b: (None, 'bot_inline_message_media_auto_layer74', None),  # 175419739
        0x18d1cdc2: (None, 'bot_inline_message_media_contact', None),  # 416402882
        0x35edb4d4: (None, 'bot_inline_message_media_contact_layer81', None),  # 904770772
        0xb722de65: (None, 'bot_inline_message_media_geo', None),  # -1222451611
        0x3a8fd8b8: (None, 'bot_inline_message_media_geo_layer71', None),  # 982505656
        0x8a86659c: (None, 'bot_inline_message_media_venue', None),  # -1970903652
        0x4366232e: (None, 'bot_inline_message_media_venue_layer77', None),  # 1130767150
        0x8c7f65e2: (None, 'bot_inline_message_text', None),  # -1937807902
        0x11965f3a: (None, 'bot_inline_result', None),  # 295067450
        0xd31a961e: (channel_struct, 'channel', None), # -753232354
        0x3b5a3e40: (None, 'channel_admin_log_event', None),  # 995769920
        0x55188a2e: (None, 'channel_admin_log_event_action_change_about', None),  # 1427671598
        0xa26f881b: (None, 'channel_admin_log_event_action_change_linked_chat', None), # -1569748965
        0x0e6b76ae: (None, 'channel_admin_log_event_action_change_location', None), # 241923758
        0x434bd2af: (None, 'channel_admin_log_event_action_change_photo'),  # 1129042607
        0xb82f55c3: (None, 'channel_admin_log_event_action_change_photo_v_5_5_0', None),  # -1204857405
        0xb1c3caa7: (None, 'channel_admin_log_event_action_change_sticker_set', None),  # -1312568665
        0xe6dfb825: (None, 'channel_admin_log_event_action_change_title', None),  # -421545947
        0x6a4afc38: (None, 'channel_admin_log_event_action_change_username', None),  # 1783299128
        0x2df5fc0a: (None, 'channel_admin_log_event_action_default_banned_rights', None),  # 771095562
        0x42e047bb: (None, 'channel_admin_log_event_action_delete_message', None),  # 1121994683
        0x709b2405: (None, 'channel_admin_log_event_action_edit_message', None),  # 1889215493
        0xe31c34d8: (None, 'channel_admin_log_event_action_participant_invite', None),  # -484690728
        0x183040d3: (None, 'channel_admin_log_event_action_participant_join', None),  # 405815507
        0xf89777f2: (None, 'channel_admin_log_event_action_participant_leave', None),  # -124291086
        0xd5676710: (None, 'channel_admin_log_event_action_participant_toggle_admin', None),  # -714643696
        0xe6d83d7e: (None, 'channel_admin_log_event_action_participant_toggle_ban', None),  # -422036098
        0x8f079643: (None, 'channel_admin_log_event_action_stop_poll', None),  # -1895328189
        0x1b7907ae: (None, 'channel_admin_log_event_action_toggle_invites', None),  # 460916654
        0x5f5c95f1: (None, 'channel_admin_log_event_action_toggle_pre_history_hidden', None),  # 1599903217
        0x26ae0971: (None, 'channel_admin_log_event_action_toggle_signatures', None),  # 648939889
        0x53909779: (None, 'channel_admin_log_event_action_toggle_slow_mode', None), # 1401984889
        0xe9e82c18: (None, 'channel_admin_log_event_action_update_pinned', None),  # -370660328
        0xea107ae4: (None, 'channel_admin_log_events_filter', None),  # -368018716
        0x5d7ceba5: (channel_admin_rights_layer92_struct, 'channel_admin_rights_layer92', None),  # 1568467877
        0x58cf4249: (channel_banned_rights_layer92_struct, 'channel_banned_rights_layer92', None),  # 1489977929
        0x289da732: (channel_forbidden_struct, 'channel_forbidden', None),  # 681420594
        0x2d85832c: (channel_forbidden_layer52_struct, 'channel_forbidden_layer52', None),  # 763724588
        0x8537784f: (channel_forbidden_layer67_struct, 'channel_forbidden_layer67', None),  # -2059962289
        0xf0e6672a: (None, 'channel_full', None), # -253335766
        0x9e341ddf: (None, 'channel_full_layer48', None),  # -1640751649
        0x97bee562: (None, 'channel_full_layer52', None),  # -1749097118
        0xc3d5512f: (None, 'channel_full_layer67', None),  # -1009430225
        0x95cb5f57: (None, 'channel_full_layer70', None),  # -1781833897
        0x17f45fcf: (None, 'channel_full_layer71', None),  # 401891279
        0x76af5481: (None, 'channel_full_layer72', None),  # 1991201921
        0xcbb62890: (None, 'channel_full_layer89', None),  # -877254512
        0x1c87a71a: (None, 'channel_full_layer98', None),  # 478652186
        0x03648977: (None, 'channel_full_layer99', None),  # 56920439
        0x9882e516: (None, 'channel_full_layer101', None), # -1736252138
        0x10916653: (None, 'channel_full_layer103', None), # 277964371
        0x2d895c74: (None, 'channel_full_layer110', None), # 763976820
        0xfab31aa3: (None, 'channel_full_old', None),  # -88925533
        0x209b82db: (None, 'channel_location', None), # 547062491
        0xbfb5ad8b: (None, 'channel_location_empty', None), # -1078612597
        0x630e61be: (None, 'chat_full_v_0_1_317'),  # 1661886910
        0xcd77d957: (None, 'channel_messages_filter', None),  # -847783593
        0x94d42ee7: (None, 'channel_messages_filter_empty', None),  # -1798033689
        0x15ebac1d: (None, 'channel_participant', None),  # 367766557
        0xccbebbaf: (None, 'channel_participant_admin', None), # -859915345
        0x5daa6e23: (None, 'channel_participant_admin_layer103', None), # 1571450403
        0xa82fa898: (None, 'channel_participant_admin_layer92', None),  # -1473271656
        0x1c0facaf: (None, 'channel_participant_banned', None),  # 470789295
        0x222c1886: (None, 'channel_participant_banned_layer92', None),  # 573315206
        0x808d15a4: (None, 'channel_participant_creator', None), # -2138237532
        0xe3e2e1f9: (None, 'channel_participant_creator_layer103', None), # -471670279
        0x98192d61: (None, 'channel_participant_editor_layer67', None),  # -1743180447
        0x8cc5e69a: (None, 'channel_participant_kicked_layer67', None),  # -1933187430
        0x91057fef: (None, 'channel_participant_moderator_layer67', None),  # -1861910545
        0xa3289a6d: (None, 'channel_participant_self', None),  # -1557620115
        0xb4608969: (None, 'channel_participants_admins', None),  # -1268741783
        0x1427a5e1: (None, 'channel_participants_banned', None),  # 338142689
        0xb0d1865b: (None, 'channel_participants_bots', None),  # -1328445861
        0xbb6ae88d: (None, 'channel_participants_contacts', None),  # -1150621555
        0xa3b54985: (None, 'channel_participants_kicked', None),  # -1548400251
        0xde3f3c79: (None, 'channel_participants_recent', None),  # -566281095
        0x0656ac4b: (None, 'channel_participants_search', None),  # 106343499
        0x4df30834: (channel_layer104_struct, 'channel_layer104', None),  # 1307772980
        0x4b1b7506: (channel_layer48_struct, 'channel_layer48', None),  # 1260090630
        0xa14dca52: (channel_layer67_struct, 'channel_layer67', None),  # -1588737454
        0x0cb44b1c: (channel_layer72_struct, 'channel_layer72', None),  # 213142300
        0x450b7115: (channel_layer77_struct, 'channel_layer77', None),  # 1158377749
        0xc88974ac: (channel_layer92_struct, 'channel_layer92', None),  # -930515796
        0x678e9587: (channel_old_struct, 'channel_old', None),  # 1737397639
        0xed8af74d: (None, 'channels_admin_log_results', None),  # -309659827
        0xd0d9b163: (None, 'channels_channel_participant', None),  # -791039645
        0xf56ee2a8: (None, 'channels_channel_participants', None),  # -177282392
        0xf0173fe9: (None, 'channels_channel_participants_not_modified', None),  # -266911767
        0x10e6bd2c: (None, 'channels_check_username', None),  # 283557164
        0x3d5fb10f: (None, 'channels_create_channel', None), # 1029681423
        0xf4893d7f: (None, 'channels_create_channel_v_5_6_2', None),  # -192332417
        0xc0111fe3: (None, 'channels_delete_channel', None),  # -1072619549
        0xaf369d42: (None, 'channels_delete_history', None),  # -1355375294
        0x84c1fd4e: (None, 'channels_delete_messages', None),  # -2067661490
        0xd10dd71b: (None, 'channels_delete_user_history', None),  # -787622117
        0xd33c8902: (None, 'channels_edit_admin', None), # -751007486
        0x70f893ba: (None, 'channels_edit_admin_v_5_6_2', None),  # 1895338938
        0x72796912: (None, 'channels_edit_banned', None),  # 1920559378
        0x8f38cd1f: (None, 'channels_edit_creator', None), # -1892102881
        0x58e63f6d: (None, 'channels_edit_location', None), # 1491484525
        0xf12e57c9: (None, 'channels_edit_photo', None),  # -248621111
        0x566decd0: (None, 'channels_edit_title', None),  # 1450044624
        0xc846d22d: (None, 'channels_export_message_link', None),  # -934882771
        0x33ddf480: (None, 'channels_get_admin_log', None),  # 870184064
        0xf8b036af: (None, 'channels_get_admined_public_channels', None), # -122669393
        0x8d8d82d7: (None, 'channels_get_admined_public_channels_v_5_6_2', None),  # -1920105769
        0x0a7f6bbb: (None, 'channels_get_channels', None),  # 176122811
        0x08736a09: (None, 'channels_get_full_channel', None),  # 141781513
        0xf5dad378: (None, 'channels_get_groups_for_discussion', None), # -170208392
        0x11e831ee: (None, 'channels_get_inactive_channels', None), # 300429806
        0x93d7b347: (None, 'channels_get_messages', None),  # -1814580409
        0x546dd7a6: (None, 'channels_get_participant', None),  # 1416484774
        0x123e05e9: (None, 'channels_get_participants', None),  # 306054633
        0x199f3a6c: (None, 'channels_invite_to_channel', None),  # 429865580
        0x24b524c5: (None, 'channels_join_channel', None),  # 615851205
        0xf836aa95: (None, 'channels_leave_channel', None),  # -130635115
        0xcc104937: (None, 'channels_read_history', None),  # -871347913
        0xeab5dc38: (None, 'channels_read_message_contents', None),  # -357180360
        0xfe087810: (None, 'channels_report_spam', None),  # -32999408
        0x43a0a7e2: (None, 'channels_search_posts', None), # 1134602210
        0x40582bb2: (None, 'channels_set_discussion_group', None), # 1079520178
        0xea8ca4f9: (None, 'channels_set_stickers', None),  # -359881479
        0xeabbb94c: (None, 'channels_toggle_pre_history_hidden', None),  # -356796084
        0x1f69b606: (None, 'channels_toggle_signatures', None),  # 527021574
        0xedd49ef0: (None, 'channels_toggle_slow_mode', None), # -304832784
        0x3514b3de: (None, 'channels_update_username', None),  # 890549214
        0x3bda1bde: (chat_struct, 'chat', None),  # 1004149726
        0x5fb224d5: (chat_admin_rights_struct, 'chat_admin_rights', None),  # 1605510357
        0x9f120418: (chat_banned_rights_struct, 'chat_banned_rights', None),  # -1626209256
        #0xc8d7493e: (None, 'chat_channel_participant', None),  # -925415106
        0x9ba2d800: (chat_empty_struct, 'chat_empty', None),  # -1683826688
        0x07328bdb: (chat_forbidden_struct, 'chat_forbidden', None),  # 120753115
        0xfb0ccc41: (chat_forbidden_old_struct, 'chat_forbidden_old', None),  # -83047359
        0x1b7c9db3: (None, 'chat_full', None),  # 461151667
        0x2e02a614: (None, 'chat_full_layer87', None),  # 771925524
        0xedd2a791: (None, 'chat_full_layer92', None),  # -304961647
        0x22a235da: (None, 'chat_full_layer98', None),  # 581055962
        0xdfc2f58e: (None, 'chat_invite', None),  # -540871282
        0x5a686d7c: (None, 'chat_invite_already', None),  # 1516793212
        0x69df3769: (None, 'chat_invite_empty', None),  # 1776236393
        0xfc2e05bc: (None, 'chat_invite_exported', None),  # -64092740
        0x61695cb0: (None, 'chat_invite_peek', None), # 1634294960
        0xdb74f558: (None, 'chat_invite_v_5_5_0', None),  # -613092008
        0xd91cdd54: (chat_layer92_struct, 'chat_layer92', None),  # -652419756
        0x3631cf4c: (None, 'chat_located', None),  # 909233996
        0xf041e250: (None, 'chat_onlines', None),  # -264117680
        # Note the very same signature means 'chat_channel_participant' too.
        0xc8d7493e: (None, 'chat_participant', None),  # -925415106
        0xe2d6e436: (None, 'chat_participant_admin', None),  # -489233354
        0xda13538a: (None, 'chat_participant_creator', None),  # -636267638
        0x3f460fed: (None, 'chat_participants', None),  # 1061556205
        0xfc900c2b: (None, 'chat_participants_forbidden', None),  # -57668565
        0x0fd2bb8a: (None, 'chat_participants_forbidden_old', None),  # 265468810
        0x7841b415: (None, 'chat_participants_old', None),  # 2017571861
        0xd20b9f3c: (chat_photo_struct, 'chat_photo', None), # -770990276
        0x475cdbd5: (chat_photo_layer115_struct, 'chat_photo_layer115'),  # 1197267925
        0x6153276a: (chat_photo_layer97_struct, 'chat_photo_layer97', None),  # 1632839530
        0x37c1011c: (chat_photo_empty_struct, 'chat_photo_empty', None),  # 935395612
        0x6e9c9bc7: (chat_old_struct, 'chat_old', None),  # 1855757255
        0x7312bc48: (chat_old2_struct, 'chat_old2', None),  # 1930607688
        0x6643b654: (None, 'client_dh_inner_data_v_0_1_317'),  # 1715713620
        0xdebebe83: (None, 'code_settings', None), # -557924733
        0x302f59f3: (None, 'code_settings_v_5_6_2', None),  # 808409587
        0x330b4067: (None, 'config', None),  # 856375399
        0x232d5905: (None, 'config_v_0_1_317'),  # 590174469
        0xe6ca25f6: (None, 'config_v_5_5_0', None),  # -422959626
        0xf911c994: (None, 'contact', None),  # -116274796
        0x561bc879: (None, 'contact_blocked', None),  # 1444661369
        0xea879f95: (None, 'contact_found', None),  # -360210539
        0xd502c2d0: (contact_link_contact_struct, 'contact_link_contact', None),  # -721239344
        0x268f3f59: (contact_link_has_phone_struct, 'contact_link_has_phone', None),  # 646922073
        0xfeedd3ad: (contact_link_none_struct, 'contact_link_none', None),  # -17968211
        0x5f4f9247: (contact_link_unknown_struct, 'contact_link_unknown', None),  # 1599050311
        0xd3680c61: (None, 'contact_status', None),  # -748155807
        0xaa77b873: (None, 'contact_status_v_0_1_317'),  # -1434994573
        0x3de191a1: (None, 'contact_suggested_v_0_1_317'),  # 1038193057
        0xf831a20f: (None, 'contacts_accept_contact', None), # -130964977
        0xe8f463d0: (None, 'contacts_add_contact', None), # -386636848
        0x332b49fc: (None, 'contacts_block', None),  # 858475004
        0x1c138d15: (None, 'contacts_blocked', None),  # 471043349
        0x900802a1: (None, 'contacts_blocked_slice', None),  # -1878523231
        0xeae87e42: (None, 'contacts_contacts', None),  # -353862078
        0x6f8b8cb2: (None, 'contacts_contacts_v_0_1_317'),  # 1871416498
        0xb74ba9d2: (None, 'contacts_contacts_not_modified', None),  # -1219778094
        0x1013fd9e: (None, 'contacts_delete_by_phones', None),  # 269745566
        0x8e953744: (None, 'contacts_delete_contact', None),  # -1902823612
        0x096a0e00: (None, 'contacts_delete_contacts', None), # 157945344
        0x59ab389e: (None, 'contacts_delete_contacts_v_5_6_2', None),  # 1504393374
        0x84e53737: (None, 'contacts_export_card', None),  # -2065352905
        0x1bea8ce1: (None, 'contacts_foreign_link_mutual_v_0_1_317'),  # 468356321
        0xa7801f47: (None, 'contacts_foreign_link_requested_v_0_1_317'),  # -1484775609
        0x133421f8: (None, 'contacts_foreign_link_unknown_v_0_1_317'),  # 322183672
        0xb3134d9d: (None, 'contacts_found', None),  # -1290580579
        0x0566000e: (None, 'contacts_found_v_0_1_317'),  # 90570766
        0xf57c350f: (None, 'contacts_get_blocked', None),  # -176409329
        0xc023849f: (None, 'contacts_get_contacts', None),  # -1071414113
        0x22c6aa08: (None, 'contacts_get_contacts_v_0_1_317'),  # 583445000
        0xd348bc44: (None, 'contacts_get_located', None), # -750207932
        0xc4a353ee: (None, 'contacts_get_statuses', None),  # -995929106
        0xcd773428: (None, 'contacts_get_suggested_v_0_1_317'),  # -847825880
        0xd4982db5: (None, 'contacts_get_top_peers', None),  # -728224331
        0x4fe196fe: (None, 'contacts_import_card', None),  # 1340184318
        0x2c800be5: (None, 'contacts_import_contacts', None),  # 746589157
        0xda30b32d: (None, 'contacts_import_contacts_v_0_1_317'),  # -634342611
        0x77d01c3b: (None, 'contacts_imported_contacts', None),  # 2010127419
        0xd1cd0a4c: (None, 'contacts_imported_contacts_v_0_1_317'),  # -775091636
        0x3ace484c: (contacts_link_layer101_struct, 'contacts_link_layer101', None),  # 986597452
        0xeccea3f5: (None, 'contacts_link_v_0_317'),  # -322001931
        0xc240ebd9: (None, 'contacts_my_link_contact_v_0_1_317'),  # -1035932711
        0xd22a1c60: (None, 'contacts_my_link_empty_v_0_1_317'),  # -768992160
        0x6c69efee: (None, 'contacts_my_link_requested_v_0_1_317'),  # 1818882030
        0x879537f1: (None, 'contacts_reset_saved', None),  # -2020263951
        0x1ae373ac: (None, 'contacts_reset_top_peer_rating', None),  # 451113900
        0xf93ccba3: (None, 'contacts_resolve_username', None),  # -113456221
        0x7f077ad9: (None, 'contacts_resolved_peer', None),  # 2131196633
        0x11f812d8: (None, 'contacts_search', None),  # 301470424
        0x5649dcc5: (None, 'contacts_suggested_v_0_1_317'),  # 1447681221
        0x8514bdda: (None, 'contacts_toggle_top_peers', None),  # -2062238246
        0x70b772a8: (None, 'contacts_top_peers', None),  # 1891070632
        0xb52c939d: (None, 'contacts_top_peers_disabled', None),  # -1255369827
        0xde266ef5: (None, 'contacts_top_peers_not_modified', None),  # -567906571
        0xe54100bd: (None, 'contacts_unblock', None),  # -448724803
        0x7d748d04: (None, 'data_json', None),  # 2104790276
        0x18b7a10d: (None, 'dc_option', None),  # 414687501
        0x2ec2a43c: (None, 'dc_option_v_0_1_317'),  # 784507964
        0x91cc4674: (None, 'decrypted_message', None),  # -1848883596
        0xdd05ec6b: (decrypted_message_action_abort_key_struct, 'decrypted_message_action_abort_key', None),  # -586814357
        0x6fe1735b: (decrypted_message_action_accept_key_struct, 'decrypted_message_action_accept_key', None),  # 1877046107
        0xec2e0b9b: (decrypted_message_action_commit_key_struct, 'decrypted_message_action_commit_key', None),  # -332526693
        0x65614304: (decrypted_message_action_delete_messages_struct, 'decrypted_message_action_delete_messages', None),  # 1700872964
        0x6719e45c: (decrypted_message_action_flush_history_struct, 'decrypted_message_action_flush_history', None),  # 1729750108
        0xa82fdd63: (decrypted_message_action_noop_struct, 'decrypted_message_action_noop', None),  # -1473258141
        0xf3048883: (decrypted_message_action_notify_layer_struct, 'decrypted_message_action_notify_layer', None),  # -217806717
        0x0c4f40be: (decrypted_message_action_read_messages_struct, 'decrypted_message_action_read_messages', None),  # 206520510
        0xf3c9611b: (decrypted_message_action_request_key_struct, 'decrypted_message_action_request_key', None),  # -204906213
        0x511110b0: (decrypted_message_action_resend_struct, 'decrypted_message_action_resend', None),  # 1360072880
        0x8ac1f475: (decrypted_message_action_screenshot_messages_struct, 'decrypted_message_action_screenshot_messages', None),  # -1967000459
        0xa1733aec: (decrypted_message_action_set_message_ttl_struct, 'decrypted_message_action_set_message_ttl', None),  # -1586283796
        0xccb27641: (decrypted_message_action_typing_struct, 'decrypted_message_action_typing', None),  # -860719551
        0x1be31789: (None, 'decrypted_message_layer', None),  # 467867529
        0x99a438cf: (None, 'decrypted_message_layer_v_0_1_317'),  # -1717290801
        0x57e0a9cb: (None, 'decrypted_message_media_audio', None),  # 1474341323
        0x6080758f: (None, 'decrypted_message_media_audio_layer8', None),  # 1619031439
        0x588a0a97: (None, 'decrypted_message_media_contact', None),  # 1485441687
        0x7afe8ae2: (None, 'decrypted_message_media_document', None),  # 2063502050
        0xb095434b: (None, 'decrypted_message_media_document_layer8', None),  # -1332395189
        0x089f5c4a: (None, 'decrypted_message_media_empty', None),  # 144661578
        0xfa95b0dd: (None, 'decrypted_message_media_external_document', None),  # -90853155
        0x35480a59: (None, 'decrypted_message_media_geo_point', None),  # 893913689
        0xf1fa8d78: (None, 'decrypted_message_media_photo', None),  # -235238024
        0x32798a8c: (None, 'decrypted_message_media_photo_layer8', None),  # 846826124
        0x8a0df56f: (None, 'decrypted_message_media_venue', None),  # -1978796689
        0x970c8c0e: (None, 'decrypted_message_media_video', None),  # -1760785394
        0x524a415d: (None, 'decrypted_message_media_video_layer17', None),  # 1380598109
        0x4cee6ef3: (None, 'decrypted_message_media_video_layer8', None),  # 1290694387
        0xe50511d8: (None, 'decrypted_message_media_web_page', None),  # -452652584
        0x73164160: (None, 'decrypted_message_service', None),  # 1930838368
        0xaa48327d: (None, 'decrypted_message_service_layer8', None),  # -1438109059
        0x204d3878: (None, 'decrypted_message_layer17', None),  # 541931640
        0x36b091de: (None, 'decrypted_message_layer45', None),  # 917541342
        0x1f814f1f: (None, 'decrypted_message_layer8', None),  # 528568095
        0xe7512126: (None, 'destroy_session_v_0_1_317'),  # -414113498
        0xa13dc52f: (None, 'destroy_sessions_v_0_1_317'),  # -1589787345
        0x62d350c9: (None, 'destroy_session_none_v_0_1_317'),  # 1658015945
        0xe22045fc: (None, 'destroy_session_ok_v_0_1_317'),  # -501201412
        0xfb95abcd: (None, 'destroy_sessions_res_v_0_1_317'),  # -74077235
        0xa69dae02: (None, 'dh_gen_fail_v_0_1_317'),  # -1499615742
        0x3bcbf734: (None, 'dh_gen_ok_v_0_1_317'),  # 1003222836
        0x46dc1fb9: (None, 'dh_gen_retry_v_0_1_317'),  # 1188831161
        0x2c171f72: (None, 'dialog', None),  # 739712882
        0x7438f7e8: (None, 'dialog_filter', None), # 1949890536
        0x77744d4a: (None, 'dialog_filter_suggested', None), # 2004110666
        0x14f9162c: (None, 'dialog_filter_v_5_15_0', None), # 351868460
        0x71bd134c: (None, 'dialog_folder', None),  # 1908216652
        0x214a8cdf: (None, 'dialog_v_0_1_317'),  # 558533855
        0xe4def5db: (None, 'dialog_v_5_5_0', None),  # -45515011
        0xe56dbf05: (None, 'dialog_peer', None),  # -445792507
        0xda429411: (None, 'dialog_peer_feed_v_5_5_0', None),  # -633170927
        0x514519e2: (None, 'dialog_peer_folder', None),  # 1363483106
        0x1e87342b: (document_struct, 'document', None), # 512177195
        0x11b58939: (document_attribute_animated_struct, 'document_attribute_animated', None),  # 297109817
        0x9852f9c6: (document_attribute_audio_struct, 'document_attribute_audio', None),  # -1739392570
        0xded218e0: (document_attribute_audio_layer45_struct, 'document_attribute_audio_layer45', None),  # -556656416
        0x051448e5: (document_attribute_audio_old_struct, 'document_attribute_audio_old', None),  # 85215461
        0x15590068: (document_attribute_filename_struct, 'document_attribute_filename', None),  # 358154344
        0x9801d2f7: (document_attribute_has_stickers_struct, 'document_attribute_has_stickers', None),  # -1744710921
        0x6c37c15c: (document_attribute_image_size_struct, 'document_attribute_image_size', None),  # 1815593308
        0x6319d612: (document_attribute_sticker_struct, 'document_attribute_sticker', None),  # 1662637586
        0x3a556302: (document_attribute_sticker_layer55_struct, 'document_attribute_sticker_layer55', None),  # 978674434
        0xfb0a5727: (document_attribute_sticker_old_struct, 'document_attribute_sticker_old', None),  # -83208409
        0x994c9882: (document_attribute_sticker_old2_struct, 'document_attribute_sticker_old2', None),  # -1723033470
        0x0ef02ce6: (document_attribute_video_struct, 'document_attribute_video', None),  # 250621158
        0x5910cccb: (document_attribute_video_layer65_struct, 'document_attribute_video_layer65', None),  # 1494273227
        0x36f8c871: (document_empty_struct, 'document_empty', None),  # 922273905
        0x55555558: (document_encrypted_struct, 'document_encrypted', None),  # 1431655768
        0x55555556: (document_encrypted_old_struct, 'document_encrypted_old', None),  # 1431655766
        0x9ba29cc1: (document_layer113_struct, 'document_layer113', None),  # -1683841855
        0xf9a39f4f: (document_layer53_struct, 'document_layer53', None),  # -106717361
        0x87232bc7: (document_layer82_struct, 'document_layer82', None),  # -2027738169
        0x59534e4c: (document_layer92_struct, 'document_layer92', None),  # 1498631756
        0x9efc6326: (document_old_struct, 'document_old', None),  # -1627626714
        0xfd8e711f: (None, 'draft_message', None),  # -40996577
        0x1b0c841a: (None, 'draft_message_empty', None),  # 453805082
        0xba4baec5: (None, 'draft_message_empty_layer81', None),  # -1169445179
        0xd5b3b9f9: (None, 'emoji_keyword', None),  # -709641735
        0x236df622: (None, 'emoji_keyword_deleted', None),  # 594408994
        0x5cc761bd: (None, 'emoji_keywords_difference', None),  # 1556570557
        0xb3fb5361: (None, 'emoji_language', None),  # -1275374751
        0xa575739d: (None, 'emoji_url', None),  # -1519029347
        0xfa56ce36: (encrypted_chat_struct, 'encrypted_chat', None),  # -94974410
        0x13d6dd27: (encrypted_chat_discarded_struct, 'encrypted_chat_discarded', None),  # 332848423
        0xab7ec0a0: (encrypted_chat_empty_struct, 'encrypted_chat_empty', None),  # -1417756512
        0x62718a82: (encrypted_chat_requested_struct, 'encrypted_chat_requested', None), # 1651608194
        0xc878527e: (encrypted_chat_requested_layer115_struct, 'encrypted_chat_requested_layer115', None),  # -931638658
        0xfda9a7b7: (encrypted_chat_requested_old_struct, 'encrypted_chat_requested_old', None),  # -39213129
        0x3bf703dc: (encrypted_chat_waiting_struct, 'encrypted_chat_waiting', None),  # 1006044124
        0x6601d14f: (encrypted_chat_old_struct, 'encrypted_chat_old', None),  # 1711395151
        0x4a70994c: (None, 'encrypted_file', None),  # 1248893260
        0xc21f497e: (None, 'encrypted_file_empty', None),  # -1038136962
        0xed18c118: (None, 'encrypted_message', None),  # -317144808
        0x23734b06: (None, 'encrypted_message_service', None),  # 594758406
        0xc4b9f9bb: (None, 'error', None),  # -994444869
        0x5dab1af4: (None, 'exported_message_link', None),  # 1571494644
        0x55555554: (file_encrypted_location_struct, 'file_encrypted_location', None),  # 1431655764
        0x6242c773: (None, 'file_hash', None),  # 1648543603
        0xbc7fc6cd: (file_location_to_be_deprecated_struct, 'file_location_to_be_deprecated', None),  # -1132476723
        0x53d69076: (file_location_layer82_struct, 'file_location_layer82', None),  # 1406570614
        0x091d11eb: (file_location_layer97_struct, 'file_location_layer97', None),  # 152900075
        0x7c596b46: (file_location_unavailable_struct, 'file_location_unavailable', None),  # 2086234950
        0xff544e65: (None, 'folder', None),  # -11252123
        0xe9baa668: (None, 'folder_peer', None),  # -373643672
        0x1c295881: (None, 'folders_delete_folder', None),  # 472471681
        0x6847d0ab: (None, 'folders_edit_peer_folders', None),  # 1749536939
        0x162ecc1f: (None, 'found_gif', None),  # 372165663
        0x9c750409: (None, 'found_gif_cached', None),  # -1670052855
        0x0949d9dc: (None, 'future_salt_v_0_1_317'),  # 155834844
        0xae500895: (None, 'futuresalts_v_0_1_317'),  # -1370486635
        0xbdf9653b: (game_struct, 'game', None),  # -1107729093
        0x75eaea5a: (None, 'geo_chat_v_0_1_317'),  # 1978329690
        0x4505f8e1: (None, 'geo_chat_message_v_0_1_317'),  # 1158019297
        0x60311a9b: (None, 'geo_chat_message_empty_v_0_1_317'),  # 1613830811
        0xd34fa24e: (None, 'geo_chat_message_service_v_0_1_317'),  # -749755826
        0x0296f104: (geo_point_struct, 'geo_point', None),  # 43446532
        0x1117dd5f: (geo_point_empty_struct, 'geo_point_empty', None),  # 286776671
        0x2049d70c: (geo_point_layer81_struct, 'geo_point_layer81', None),  # 541710092
        0x55b3e8fb: (None, 'geochats_checkin_v_0_1_317'),  # 1437853947
        0x0e092e16: (None, 'geochats_create_geo_chat_v_0_1_317'),  # 235482646
        0x35d81a95: (None, 'geochats_edit_chat_photo_v_0_1_317'),  # 903355029
        0x4c8e2273: (None, 'geochats_edit_chat_title_v_0_1_317'),  # 1284383347
        0x6722dd6f: (None, 'geochats_get_full_chat_v_0_1_317'),  # 1730338159
        0xb53f7a68: (None, 'geochats_get_history_v_0_1_317'),  # -1254131096
        0x7f192d8f: (None, 'geochats_get_located_v_0_1_317'),  # 2132356495
        0xe1427e6f: (None, 'geochats_get_recents_v_0_1_317'),  # -515735953
        0x48feb267: (None, 'geochats_located_v_0_1_317'),  # 1224651367
        0xd1526db1: (None, 'geochats_messages_v_0_1_317'),  # -783127119
        0xbc5863e8: (None, 'geochats_messages_slice_v_0_1_317'),  # -1135057944
        0xcfcdc44d: (None, 'geochats_search_v_0_1_317'),  # -808598451
        0xb8f0deff: (None, 'geochats_send_media_v_0_1_317'),  # -1192173825
        0x061b0044: (None, 'geochats_send_message_v_0_1_317'),  # 102432836
        0x08b8a729: (None, 'geochats_set_typing_v_0_1_317'),  # 146319145
        0x17b1578b: (None, 'geochats_stated_message_v_0_1_317'),  # 397498251
        0xb921bd04: (None, 'get_future_salts_v_0_1_317'),  # -1188971260
        0xbea2f424: (None, 'global_privacy_settings', None), # -1096616924
        0x0a8f1624: (None, 'group_call', None),  # 177149476
        0x40732163: (None, 'group_call_connection', None),  # 1081287011
        0x7780bcb4: (None, 'group_call_discarded', None),  # 2004925620
        0x589db397: (None, 'group_call_participant', None),  # 1486730135
        0x4f0b39b8: (None, 'group_call_participant_admin', None),  # 1326135736
        0x377496f0: (None, 'group_call_participant_invited', None),  # 930387696
        0x419b0df2: (None, 'group_call_participant_left', None),  # 1100680690
        0x6d0b1604: (None, 'group_call_private', None),  # 1829443076
        0x3072cfa1: (None, 'gzip_packed_v_0_1_317'),  # 812830625
        0xee72f79a: (None, 'help_accept_terms_of_service', None),  # -294455398
        0x1da7158f: (None, 'help_app_update', None),  # 497489295
        0x8987f311: (None, 'help_app_update_v_0_1_317'),  # -1987579119
        0xc812ac7e: (None, 'help_get_app_update_v_0_1_317'),  # -938300290
        0x6a4ee832: (None, 'help_deep_link_info', None),  # 1783556146
        0x66afa166: (None, 'help_deep_link_info_empty', None),  # 1722786150
        0x077fa99f: (None, 'help_dismiss_suggestion', None), # 125807007
        0x66b91b70: (None, 'help_edit_user_info', None),  # 1723407216
        0x9010ef6f: (None, 'help_get_app_changelog', None),  # -1877938321
        0x98914110: (None, 'help_get_app_config', None),  # -1735311088
        0x522d5a7d: (None, 'help_get_app_update', None),  # 1378703997
        0xc4f9186b: (None, 'help_get_config', None),  # -990308245
        0x3fedc75f: (None, 'help_get_deep_link_info', None),  # 1072547679
        0x4d392343: (None, 'help_get_invite_text', None),  # 1295590211
        0xa4a95186: (None, 'help_get_invite_text_v_0_1_317'),  # -1532407418
        0x1fb33026: (None, 'help_get_nearest_dc', None),  # 531836966
        0xc661ad08: (None, 'help_get_passport_config', None),  # -966677240
        0xc0977421: (None, 'help_get_promo_data', None), # -1063816159
        0x3d7758e1: (None, 'help_get_proxy_data', None),  # 1031231713
        0x3dc0f114: (None, 'help_get_recent_me_urls', None),  # 1036054804
        0x9cdf08cd: (None, 'help_get_support', None),  # -1663104819
        0xd360e72c: (None, 'help_get_support_name', None),  # -748624084
        0x2ca51fd1: (None, 'help_get_terms_of_service_update', None),  # 749019089
        0x038a08d3: (None, 'help_get_user_info', None),  # 59377875
        0x1e251c95: (None, 'help_hide_promo_data', None), # 505748629
        0x18cb9f78: (None, 'help_invite_text', None),  # 415997816
        0xc45a6536: (None, 'help_no_app_update', None),  # -1000708810
        0xa098d6af: (None, 'help_passport_config', None),  # -1600596305
        0xbfb9f457: (None, 'help_passport_config_not_modified', None),  # -1078332329
        0x98f6ac75: (None, 'help_promo_data_empty', None), # -1728664459
        0x8c39793f: (None, 'help_promo_data', None), # -1942390465
        0xe09e1fb8: (None, 'help_proxy_data_empty', None),  # -526508104
        0x2bf7ee23: (None, 'help_proxy_data_promo', None),  # 737668643
        0x0e0310d7: (None, 'help_recent_me_urls', None),  # 235081943
        0x6f02f748: (None, 'help_save_app_log', None),  # 1862465352
        0xec22cfcd: (None, 'help_set_bot_updates_status', None),  # -333262899
        0x17c6b5f6: (None, 'help_support', None),  # 398898678
        0x8c05f1c9: (None, 'help_support_name', None),  # -1945767479
        0x780a0310: (None, 'help_terms_of_service', None),  # 2013922064
        0x28ecf961: (None, 'help_terms_of_service_update', None),  # 686618977
        0xe3309f7f: (None, 'help_terms_of_service_update_empty', None),  # -483352705
        0x01eb3758: (None, 'help_user_info', None),  # 32192344
        0xf3ae2eed: (None, 'help_user_info_empty', None),  # -206688531
        0x58fffcd0: (None, 'high_score', None),  # 1493171408
        0x9299359f: (None, 'http_wait_v_0_1_317'),  # -1835453025
        0xd0028438: (None, 'imported_contact', None),  # -805141448
        0x69796de9: (None, 'init_connection_v_0_1_317'),  # 1769565673
        0x3c20629f: (None, 'inline_bot_switch_p_m', None),  # 1008755359
        0x1d1b1245: (None, 'input_app_event', None),  # 488313413
        0x770656a8: (None, 'input_app_event_v_0_1_317'),  # 1996904104
        0x77d440ff: (None, 'input_audio_v_0_1_317'),  # 2010398975
        0xd95adc84: (None, 'input_audio_empty_v_0_1_317'),  # -648356732
        0x74dc404d: (None, 'input_audio_file_location_v_0_1_317'),  # 1960591437
        0x890c3d89: (None, 'input_bot_inline_message_id', None),  # -1995686519
        0xafeb712e: (input_channel_struct, 'input_channel', None),  # -1343524562
        0xee8c1e86: (input_channel_empty_struct, 'input_channel_empty', None),  # -292807034
        0x2a286531: (None, 'input_channel_from_message', None), # 707290417
        0x8953ad37: (None, 'input_chat_photo', None),  # -1991004873
        0xb2e1bf08: (None, 'input_chat_photo_v_0_1_317'),  # -1293828344
        0x1ca48f57: (None, 'input_chat_photo_empty', None),  # 480546647
        0xc642724e: (None, 'input_chat_uploaded_photo', None), # -968723890
        0x927c55b4: (None, 'input_chat_uploaded_photo_v_5_15_0', None),  # -1837345356
        0x94254732: (None, 'input_chat_uploaded_photo_v_0_1_317'),  # -1809496270
        0x9880f658: (None, 'input_check_password_empty', None),  # -1736378792
        0xd27ff082: (None, 'input_check_password_s_r_p', None),  # -763367294
        0xfcaafeb7: (None, 'input_dialog_peer', None),  # -55902537
        0x2c38b8cf: (None, 'input_dialog_peer_feed_v_5_5_0', None),  # 741914831
        0x64600527: (None, 'input_dialog_peer_folder', None),  # 1684014375
        0x1abfb575: (None, 'input_document', None),  # 448771445
        0x72f0eaae: (None, 'input_document_empty', None),  # 1928391342
        0xbad07584: (None, 'input_document_file_location', None),  # -1160743548
        0x4e45abe9: (None, 'input_document_file_location_v_0_1_317'),  # 1313188841
        0x196683d9: (None, 'input_document_file_location_v_5_5_0', None),  # 426148825
        0x18798952: (None, 'input_document_v_0_1_317'),  # 410618194
        0xf141b5e1: (None, 'input_encrypted_chat', None),  # -247351839
        0x5a17b5e5: (None, 'input_encrypted_file', None),  # 1511503333
        0x2dc173c8: (None, 'input_encrypted_file_big_uploaded', None),  # 767652808
        0x1837c364: (None, 'input_encrypted_file_empty', None),  # 406307684
        0xf5235d55: (None, 'input_encrypted_file_location', None),  # -182231723
        0x64bd0306: (None, 'input_encrypted_file_uploaded', None),  # 1690108678
        0xf52ff27f: (None, 'input_file', None),  # -181407105
        0xfa4f0bb5: (None, 'input_file_big', None),  # -95482955
        0xdfdaabe1: (None, 'input_file_location', None),  # -539317279
        0x14637196: (None, 'input_file_location_v_0_1_317'),  # 342061462
        0xfbd2c296: (None, 'input_folder_peer', None),  # -70073706
        0x032c3e77: (None, 'input_game_id', None),  # 53231223
        0xc331e80a: (None, 'input_game_short_name', None),  # -1020139510
        0x74d456fa: (None, 'input_geo_chat_v_0_1_317'),  # 1960072954
        0xf3b7acc9: (None, 'input_geo_point', None),  # -206066487
        0xe4c123d6: (None, 'input_geo_point_empty', None),  # -457104426
        0xd8aa840f: (input_group_call_struct, 'input_group_call', None),  # -659913713
        0xd02e7fd4: (None, 'input_keyboard_button_url_auth', None), # -802258988
        0x89938781: (None, 'input_media_audio_v_0_1_317'),  # -1986820223
        0xf8ab7dfb: (None, 'input_media_contact', None),  # -122978821
        0xa6e45987: (None, 'input_media_contact_v_0_1_317'),  # -1494984313
        0xe66fbf7b: (None, 'input_media_dice', None), # -428884101
        0x23ab23d2: (None, 'input_media_document', None),  # 598418386
        0xfb52dc99: (None, 'input_media_document_external', None),  # -78455655
        0xd184e841: (None, 'input_media_document_v_0_1_317'),  # -779818943
        0x9664f57f: (None, 'input_media_empty', None),  # -1771768449
        0xd33f43f3: (None, 'input_media_game', None),  # -750828557
        0xce4e82fd: (None, 'input_media_geo_live', None),  # -833715459
        0xf9c44144: (None, 'input_media_geo_point', None),  # -104578748
        0x4843b0fd: (None, 'input_media_gif_external', None),  # 1212395773
        0xb3ba0635: (None, 'input_media_photo', None),  # -1279654347
        0xe5bbfe1a: (None, 'input_media_photo_external', None),  # -440664550
        0x8f2ab2ec: (None, 'input_media_photo_v_0_1_317'),  # -1893027092
        0x0f94e5f1: (None, 'input_media_poll', None), # 261416433
        0xabe9ca25: (None, 'input_media_poll_v_5_15_0', None), # -1410741723
        0x06b3765b: (None, 'input_media_poll_v_5_6_2', None),  # 112424539
        0x61a6d436: (None, 'input_media_uploaded_audio_v_0_1_317'),  # 1638323254
        0x5b38c6c1: (None, 'input_media_uploaded_document', None),  # 1530447553
        0x34e794bd: (None, 'input_media_uploaded_document_v_0_1_317'),  # 887592125
        0x1e287d04: (None, 'input_media_uploaded_photo', None),  # 505969924
        0x2dc53a7d: (None, 'input_media_uploaded_photo_v_0_1_317'),  # 767900285
        0x3e46de5d: (None, 'input_media_uploaded_thumb_document_v_0_1_317'),  # 1044831837
        0xe628a145: (None, 'input_media_uploaded_thumb_video_v_0_1_317'),  # -433544891
        0x4847d92a: (None, 'input_media_uploaded_video_v_0_1_317'),  # 1212668202
        0xc13d1c11: (None, 'input_media_venue', None),  # -1052959727
        0x7f023ae6: (None, 'input_media_video_v_0_1_317'),  # 2130852582
        0x208e68c9: (input_message_entity_mention_name_struct, 'input_message_entity_mention_name', None),  # 546203849
        0x3a20ecb8: (None, 'input_messages_filter_chat_photos', None),  # 975236280
        0xe062db83: (None, 'input_messages_filter_contacts', None),  # -530392189
        0x9eddf188: (None, 'input_messages_filter_document', None),  # -1629621880
        0x57e2f66c: (None, 'input_messages_filter_empty', None),  # 1474492012
        0xe7026d0d: (None, 'input_messages_filter_geo', None),  # -419271411
        0xffc86587: (None, 'input_messages_filter_gif', None),  # -3644025
        0x3751b49e: (None, 'input_messages_filter_music', None),  # 928101534
        0xc1f8e69a: (None, 'input_messages_filter_my_mentions', None),  # -1040652646
        0x80c99768: (None, 'input_messages_filter_phone_calls', None),  # -2134272152
        0x56e9f0e4: (None, 'input_messages_filter_photo_video', None),  # 1458172132
        0xd95e73bb: (None, 'input_messages_filter_photo_video_documents', None),  # -648121413
        0x9609a51c: (None, 'input_messages_filter_photos', None),  # -1777752804
        0xb549da53: (None, 'input_messages_filter_round_video', None),  # -1253451181
        0x7a7c17a4: (None, 'input_messages_filter_round_voice', None),  # 2054952868
        0x7ef0dd87: (None, 'input_messages_filter_url', None),  # 2129714567
        0x9fc00e65: (None, 'input_messages_filter_video', None),  # -1614803355
        0x50f5c392: (None, 'input_messages_filter_voice', None),  # 1358283666
        0xa429b886: (None, 'input_notify_all_v_0_1_317'),  # -1540769658
        0xb1db7c7e: (None, 'input_notify_broadcasts', None),  # -1311015810
        0x4a95e84e: (None, 'input_notify_chats', None),  # 1251338318
        0x4d8ddec8: (None, 'input_notify_geo_chat_peer_v_0_1_317'),  # 1301143240
        0xb8bc5b0c: (None, 'input_notify_peer', None),  # -1195615476
        0x193b4417: (None, 'input_notify_users', None),  # 423314455
        0x3417d728: (None, 'input_payment_credentials', None),  # 873977640
        0xca05d50e: (None, 'input_payment_credentials_android_pay', None),  # -905587442
        0xc10eb2cf: (None, 'input_payment_credentials_saved', None),  # -1056001329
        0x20adaef8: (None, 'input_peer_channel', None),  # 548253432
        0x9c95f7bb: (None, 'input_peer_channel_from_message', None), # -1667893317
        0x179be863: (None, 'input_peer_chat', None),  # 396093539
        0x1023dbe8: (None, 'input_peer_contact_v_0_1_317'),  # 270785512
        0x7f3b18ea: (None, 'input_peer_empty', None),  # 2134579434
        0x9b447325: (None, 'input_peer_foreign_v_0_1_317'),  # -1690012891
        0xe86a2c74: (None, 'input_peer_notify_events_all_v_0_1_317'),  # -395694988
        0xf03064d8: (None, 'input_peer_notify_events_empty_v_0_1_317'),  # -265263912
        0x9c3d198e: (None, 'input_peer_notify_settings', None),  # -1673717362
        0x46a2ce98: (None, 'input_peer_notify_settings_v_0_1_317'),  # 1185074840
        0x27d69997: (None, 'input_peer_photo_file_location', None),  # 668375447
        0x7da07ec9: (None, 'input_peer_self', None),  # 2107670217
        0x7b8e7de6: (None, 'input_peer_user', None),  # 2072935910
        0x17bae2e6: (None, 'input_peer_user_from_message', None), # 398123750
        0x1e36fded: (None, 'input_phone_call', None),  # 506920429
        0xf392b7f4: (None, 'input_phone_contact', None),  # -208488460
        0x3bb3b94a: (None, 'input_photo', None),  # 1001634122
        0xd9915325: (None, 'input_photo_crop_v_0_1_317'),  # -644787419
        0xade6b004: (None, 'input_photo_crop_auto_v_0_1_317'),  # -1377390588
        0x1cd7bf0d: (None, 'input_photo_empty', None),  # 483901197
        0x40181ffe: (None, 'input_photo_file_location', None),  # 1075322878
        0xfb95c6c4: (None, 'input_photo_v_0_1_317'),  # -74070332
        0xd1219bdd: (None, 'input_privacy_key_added_by_phone', None), # -786326563
        0xbdfb0426: (None, 'input_privacy_key_chat_invite', None),  # -1107622874
        0xa4dd4c08: (None, 'input_privacy_key_forwards', None),  # -1529000952
        0xfabadc5f: (None, 'input_privacy_key_phone_call', None),  # -88417185
        0x0352dafa: (None, 'input_privacy_key_phone_number', None), # 55761658
        0xdb9e70d2: (None, 'input_privacy_key_phone_p2_p', None),  # -610373422
        0x5719bacc: (None, 'input_privacy_key_profile_photo', None),  # 1461304012
        0x4f96cb18: (None, 'input_privacy_key_status_timestamp', None),  # 1335282456
        0x184b35ce: (None, 'input_privacy_value_allow_all', None),  # 407582158
        0x4c81c1ba: (None, 'input_privacy_value_allow_chat_participants', None), # 1283572154
        0x0d09e07b: (None, 'input_privacy_value_allow_contacts', None),  # 218751099
        0x131cc67f: (None, 'input_privacy_value_allow_users', None),  # 320652927
        0xd66b66c9: (None, 'input_privacy_value_disallow_all', None),  # -697604407
        0xd82363af: (None, 'input_privacy_value_disallow_chat_participants', None), # -668769361
        0x0ba52007: (None, 'input_privacy_value_disallow_contacts', None),  # 195371015
        0x90110467: (None, 'input_privacy_value_disallow_users', None),  # -1877932953
        0xadf44ee3: (None, 'input_report_reason_child_abuse', None),  # -1376497949
        0x9b89f93a: (None, 'input_report_reason_copyright', None),  # -1685456582
        0xdbd4feed: (None, 'input_report_reason_geo_irrelevant', None), # -606798099
        0xe1746d0a: (None, 'input_report_reason_other', None),  # -512463606
        0x2e59d922: (None, 'input_report_reason_pornography', None),  # 777640226
        0x58dbcab8: (None, 'input_report_reason_spam', None),  # 1490799288
        0x1e22c78d: (None, 'input_report_reason_violence', None),  # 505595789
        0x5367e5be: (None, 'input_secure_file', None),  # 1399317950
        0xcbc7ee28: (None, 'input_secure_file_location', None),  # -876089816
        0x3334b0f0: (None, 'input_secure_file_uploaded', None),  # 859091184
        0xdb21d0a7: (None, 'input_secure_value', None),  # -618540889
        0x1cc6e91f: (None, 'input_single_media', None),  # 482797855
        0x028703c8: (input_sticker_set_animated_emoji_struct, 'input_sticker_set_animated_emoji', None), # 42402760
        0xe67f520e: (input_sticker_set_dice_struct, 'input_sticker_set_dice', None), # -427863538
        0xffb62b95: (input_sticker_set_empty_struct, 'input_sticker_set_empty', None),  # -4838507
        0x9de7a269: (input_sticker_set_id_struct, 'input_sticker_set_id', None),  # -1645763991
        0x861cc8a0: (input_sticker_set_short_name_struct, 'input_sticker_set_short_name', None),  # -2044933984
        0x0dbaeae9: (None, 'input_sticker_set_thumb', None),  # 230353641
        0x0438865b: (None, 'input_stickered_media_document', None),  # 70813275
        0x4a992157: (None, 'input_stickered_media_photo', None),  # 1251549527
        0x3c5693e9: (None, 'input_theme', None), # 1012306921
        0xbd507cd1: (None, 'input_theme_settings', None), # -1118798639
        0xf5890df1: (None, 'input_theme_slug', None), # -175567375
        0xd8292816: (input_user_struct, 'input_user', None),  # -668391402
        0x86e94f65: (None, 'input_user_contact_v_0_1_317'),  # -2031530139
        0xb98886cf: (input_user_empty_struct, 'input_user_empty', None),  # -1182234929
        0x655e74ff: (None, 'input_user_foreign_v_0_1_317'),  # 1700689151
        0x2d117597: (None, 'input_user_from_message', None), # 756118935
        0xf7c1b13f: (None, 'input_user_self', None),  # -138301121
        0xee579652: (None, 'input_video_v_0_1_317'),  # -296249774
        0x5508ec75: (None, 'input_video_empty_v_0_1_317'),  # 1426648181
        0x3d0364ec: (None, 'input_video_file_location_v_0_1_317'),  # 1023632620
        0xe630b979: (None, 'input_wall_paper', None),  # -433014407
        0x8427bbac: (None, 'input_wall_paper_no_file', None), # -2077770836
        0x72091c80: (None, 'input_wall_paper_slug', None),  # 1913199744
        0x9bed434d: (None, 'input_web_document', None),  # -1678949555
        0x9f2221c9: (None, 'input_web_file_geo_point_location', None),  # -1625153079
        0xc239d686: (None, 'input_web_file_location', None),  # -1036396922
        0xc30aa358: (None, 'invoice', None),  # -1022713000
        0xcb9f372d: (None, 'invoke_after_msg_v_0_1_317'),  # -878758099
        0xa6b88fdf: (None, 'invoke_with_layer11_v_0_1_317'),  # -1497853985
        0xf7444763: (None, 'json_array', None),  # -146520221
        0xc7345e6a: (None, 'json_bool', None),  # -952869270
        0x3f6d7b68: (None, 'json_null', None),  # 1064139624
        0x2be0dfa4: (None, 'json_number', None),  # 736157604
        0x99c1d49d: (None, 'json_object', None),  # -1715350371
        0xc0de1bd9: (None, 'json_object_value', None),  # -1059185703
        0xb71e767a: (None, 'json_string', None),  # -1222740358
        0xa2fa4880: (keyboard_button_struct, 'keyboard_button', None),  # -1560655744
        0xafd93fbb: (keyboard_button_buy_struct, 'keyboard_button_buy', None),  # -1344716869
        0x683a5e46: (keyboard_button_callback_struct, 'keyboard_button_callback', None),  # 1748655686
        0x50f41ccf: (keyboard_button_game_struct, 'keyboard_button_game', None),  # 1358175439
        0xfc796b3f: (keyboard_button_request_geo_location_struct, 'keyboard_button_request_geo_location', None),  # -59151553
        0xb16a6c29: (keyboard_button_request_phone_struct, 'keyboard_button_request_phone', None),  # -1318425559
        0xbbc7515d: (keyboard_button_request_poll_struct, 'keyboard_button_request_poll', None), # -1144565411
        0x77608b83: (keyboard_button_row_struct, 'keyboard_button_row', None),  # 2002815875
        0x0568a748: (keyboard_button_switch_inline_struct, 'keyboard_button_switch_inline', None),  # 90744648
        0x258aff05: (keyboard_button_url_struct, 'keyboard_button_url', None),  # 629866245
        0x10b78d29: (keyboard_button_url_auth_struct, 'keyboard_button_url_auth', None), # 280464681
        0xcb296bf8: (None, 'labeled_price', None),  # -886477832
        0xf385c1f6: (None, 'lang_pack_difference', None),  # -209337866
        0xeeca5ce3: (None, 'lang_pack_language', None),  # -288727837
        0xcad181f6: (None, 'lang_pack_string', None),  # -892239370
        0x2979eeb2: (None, 'lang_pack_string_deleted', None),  # 695856818
        0x6c47ac9f: (None, 'lang_pack_string_pluralized', None),  # 1816636575
        0xcd984aa5: (None, 'langpack_get_difference', None),  # -845657435
        0x9ab5c58e: (None, 'langpack_get_lang_pack', None),  # -1699363442
        0x6a596502: (None, 'langpack_get_language', None),  # 1784243458
        0x800fd57d: (None, 'langpack_get_languages', None),  # -2146445955
        0x2e1ee318: (None, 'langpack_get_strings', None),  # 773776152
        0xaed6dbb2: (mask_coords_struct, 'mask_coords', None),  # -1361650766
        0x452c0e65: (message_struct, 'message', None), # 1160515173
        0xabe9affe: (message_action_bot_allowed_struct, 'message_action_bot_allowed', None),  # -1410748418
        0x95d2ac92: (message_action_channel_create_struct, 'message_action_channel_create', None),  # -1781355374
        0xb055eaee: (message_action_channel_migrate_from_struct, 'message_action_channel_migrate_from', None),  # -1336546578
        0x488a7337: (message_action_chat_add_user_struct, 'message_action_chat_add_user', None),  # 1217033015
        0x5e3cfc4b: (message_action_chat_add_user_old_struct, 'message_action_chat_add_user_old', None),  # 1581055051
        0xa6638b9a: (message_action_chat_create_struct, 'message_action_chat_create', None),  # -1503425638
        0xb2ae9b0c: (message_action_chat_delete_user_struct, 'message_action_chat_delete_user', None),  # -1297179892
        0x95e3fbef: (message_action_chat_delete_photo_struct, 'message_action_chat_delete_photo', None),  # -1780220945
        0x7fcb13a8: (message_action_chat_edit_photo_struct, 'message_action_chat_edit_photo', None),  # 2144015272
        0xb5a1ce5a: (message_action_chat_edit_title_struct, 'message_action_chat_edit_title', None),  # -1247687078
        0xf89cf5e8: (message_action_chat_joined_by_link_struct, 'message_action_chat_joined_by_link', None),  # -123931160
        0x51bdb021: (message_action_chat_migrate_to_struct, 'message_action_chat_migrate_to', None),  # 1371385889
        0xf3f25f76: (message_action_contact_sign_up_struct, 'message_action_contact_sign_up', None),  # -202219658
        0x55555557: (message_action_created_broadcast_list_struct, 'message_action_created_broadcast_list', None),  # 1431655767
        0xfae69f56: (message_action_custom_action_struct, 'message_action_custom_action', None),  # -85549226
        0xb6aef7b0: (message_action_empty_struct, 'message_action_empty', None),  # -1230047312
        0x92a72876: (message_action_game_score_struct, 'message_action_game_score', None),  # -1834538890
        0x0c7d53de: (None, 'message_action_geo_chat_checkin_v_0_1_317'),  # 209540062
        0x6f038ebc: (None, 'message_action_geo_chat_create_v_0_1_317'),  # 1862504124
        0x7a0d7f42: (message_action_group_call_struct, 'message_action_group_call', None),  # 2047704898
        0x9fbab604: (message_action_history_clear_struct, 'message_action_history_clear', None),  # -1615153660
        0x555555f5: (message_action_login_unknown_location_struct, 'message_action_login_unknown_location', None),  # 1431655925
        0x40699cd0: (message_action_payment_sent_struct, 'message_action_payment_sent', None),  # 1080663248
        0x80e11a7f: (message_action_phone_call_struct, 'message_action_phone_call', None),  # -2132731265
        0x94bd38ed: (message_action_pin_message_struct, 'message_action_pin_message', None),  # -1799538451
        0x4792929b: (message_action_screenshot_taken_struct, 'message_action_screenshot_taken', None),  # 1200788123
        0xd95c6154: (message_action_secure_values_sent_struct, 'message_action_secure_values_sent', None),  # -648257196
        0x55555552: (message_action_ttl_change_struct, 'message_action_ttl_change', None),  # 1431655762
        0x55555550: (message_action_user_joined_struct, 'message_action_user_joined', None),  # 1431655760
        0x55555551: (message_action_user_updated_photo_struct, 'message_action_user_updated_photo', None),  # 1431655761
        0x83e5de54: (message_empty_struct, 'message_empty', None),  # -2082087340
        0x555555f7: (message_encrypted_action_struct, 'message_encrypted_action', None),  # 1431655927
        0x761e6af4: (message_entity_bank_card_struct, 'message_entity_bank_card', None), # 1981704948
        0x020df5d0: (message_entity_blockquote_struct, 'message_entity_blockquote', None), # 34469328
        0xbd610bc9: (message_entity_bold_struct, 'message_entity_bold', None),  # -1117713463
        0x6cef8ac7: (message_entity_bot_command_struct, 'message_entity_bot_command', None),  # 1827637959
        0x4c4e743f: (message_entity_cashtag_struct, 'message_entity_cashtag', None),  # 1280209983
        0x28a20571: (message_entity_code_struct, 'message_entity_code', None),  # 681706865
        0x64e475c2: (message_entity_email_struct, 'message_entity_email', None),  # 1692693954
        0x6f635b0d: (message_entity_hashtag_struct, 'message_entity_hashtag', None),  # 1868782349
        0x826f8b60: (message_entity_italic_struct, 'message_entity_italic', None),  # -2106619040
        0xfa04579d: (message_entity_mention_struct, 'message_entity_mention', None),  # -100378723
        0x352dca58: (message_entity_mention_name_struct, 'message_entity_mention_name', None),  # 892193368
        0x9b69e34b: (message_entity_phone_struct, 'message_entity_phone', None),  # -1687559349
        0x73924be0: (message_entity_pre_struct, 'message_entity_pre', None),  # 1938967520
        0xbf0693d4: (message_entity_strike_struct, 'message_entity_strike', None), # -1090087980
        0x76a6d327: (message_entity_text_url_struct, 'message_entity_text_url', None),  # 1990644519
        0x9c4e7e8b: (message_entity_underline_struct, 'message_entity_underline', None), # -1672577397
        0xbb92ba95: (message_entity_unknown_struct, 'message_entity_unknown', None),  # -1148011883
        0x6ed02538: (message_entity_url_struct, 'message_entity_url', None),  # 1859134776
        0x05f46804: (message_forwarded_old_struct, 'message_forwarded_old', None),  # 99903492
        0xa367e716: (message_forwarded_old2_struct, 'message_forwarded_old2', None),  # -1553471722
        0x353a686b: (message_fwd_header_struct, 'message_fwd_header', None), # 893020267
        0xec338270: (message_fwd_header_layer112_struct, 'message_fwd_header_layer112', None),  # -332168592
        0xc786ddcb: (message_fwd_header_layer68_struct, 'message_fwd_header_layer68', None),  # -947462709
        0xfadff4ac: (message_fwd_header_layer72_struct, 'message_fwd_header_layer72', None),  # -85986132
        0x559ebe6d: (message_fwd_header_layer96_struct, 'message_fwd_header_layer96', None),  # 1436466797
        0xad4fc9bd: (None, 'message_interaction_counters', None), # -1387279939
        0xc6b68300: (message_media_audio_layer45_struct, 'message_media_audio_layer45', None),  # -961117440
        0xcbf24940: (message_media_contact_struct, 'message_media_contact', None),  # -873313984
        0x5e7d2f39: (message_media_contact_layer81_struct, 'message_media_contact_layer81', None),  # 1585262393
        0x3f7ee58b: (message_media_dice_struct, 'message_media_dice', None), # 1065280907
        0x638fe46b: (message_media_dice_layer111_struct, 'message_media_dice_layer111', None), # 1670374507
        0x9cb070d7: (message_media_document_struct, 'message_media_document', None),  # -1666158377
        0xf3e02ea8: (message_media_document_layer68_struct, 'message_media_document_layer68', None),  # -203411800
        0x7c4414d3: (message_media_document_layer74_struct, 'message_media_document_layer74', None),  # 2084836563
        0x2fda2204: (message_media_document_old_struct, 'message_media_document_old', None),  # 802824708
        0x3ded6320: (message_media_empty_struct, 'message_media_empty', None),  # 1038967584
        0xfdb19008: (message_media_game_struct, 'message_media_game', None),  # -38694904
        0x56e0d474: (message_media_geo_struct, 'message_media_geo', None),  # 1457575028
        0x7c3c2609: (message_media_geo_live_struct, 'message_media_geo_live', None),  # 2084316681
        0x84551347: (message_media_invoice_struct, 'message_media_invoice', None),  # -2074799289
        0x695150d7: (message_media_photo_struct, 'message_media_photo', None),  # 1766936791
        0x3d8ce53d: (message_media_photo_layer68_struct, 'message_media_photo_layer68', None),  # 1032643901
        0xb5223b0f: (message_media_photo_layer74_struct, 'message_media_photo_layer74', None),  # -1256047857
        0xc8c45a2a: (message_media_photo_old_struct, 'message_media_photo_old', None),  # -926655958
        0x4bd6e798: (message_media_poll_struct, 'message_media_poll', None),  # 1272375192
        0x9f84f49e: (message_media_unsupported_struct, 'message_media_unsupported', None),  # -1618676578
        0x29632a36: (message_media_unsupported_old_struct, 'message_media_unsupported_old', None),  # 694364726
        0x2ec0533f: (message_media_venue_struct, 'message_media_venue', None),  # 784356159
        0x7912b71f: (message_media_venue_layer71_struct, 'message_media_venue_layer71', None),  # 2031269663
        0x5bcf1675: (message_media_video_layer45_struct, 'message_media_video_layer45', None),  # 1540298357
        0xa2d24290: (message_media_video_old_struct, 'message_media_video_old', None),  # -1563278704
        0xa32dd600: (message_media_web_page_struct, 'message_media_web_page', None),  # -1557277184
        0x0ae30253: (None, 'message_range', None),  # 182649427
        0xb87a24d1: (message_reactions_struct, 'message_reactions', None), # -1199954735
        0xe3ae6108: (None, 'message_reactions_list', None), # -475111160
        0x9e19a1f6: (message_service_struct, 'message_service', None),  # -1642487306
        0xc06b9607: (message_service_layer48_struct, 'message_service_layer48', None),  # -1066691065
        0x9f8d60bb: (message_service_old_struct, 'message_service_old', None),  # -1618124613
        0x1d86f70e: (None, 'message_service_old2', None),  # 495384334
        0xd267dcbc: (None, 'message_user_reaction', None), # -764945220
        0xa28e5559: (None, 'message_user_vote', None), # -1567730343
        0x36377430: (None, 'message_user_vote_input_option', None), # 909603888
        0x0e8fe0de: (None, 'message_user_vote_multiple', None), # 244310238
        0x44f9b43d: (message_layer104_struct, 'message_layer104', None),  # 1157215293
        0x1c9b1027: (message_layer104_2_struct, 'message_layer104_2', None), # 479924263
        0x9789dac4: (message_layer104_3_struct, 'message_layer104_3', None), # -1752573244
        0xc992e15c: (None, 'message_layer47', None),  # -913120932
        0xc09be45f: (message_layer68_struct, 'message_layer68', None),  # -1063525281
        0x90dddc11: (message_layer72_struct, 'message_layer72', None),  # -1864508399
        0x22eb6aba: (None, 'message_old', None),  # 585853626
        0x567699b3: (None, 'message_old2', None),  # 1450613171
        0xa7ab1991: (message_old3_struct, 'message_old3', None),  # -1481959023
        0xc3060325: (message_old4_struct, 'message_old4', None),  # -1023016155
        0xf07814c8: (message_old5_struct, 'message_old5', None),  # -260565816
        0x2bebfa86: (None, 'message_old6', None),  # 736885382
        0x5ba66c13: (None, 'message_old7', None),  # 1537633299
        0x555555fa: (message_secret_struct, 'message_secret', None),  # 1431655930
        0x555555f9: (None, 'message_secret_layer72', None),  # 1431655929
        0x555555f8: (None, 'message_secret_old', None),  # 1431655928
        0x3dbc0415: (None, 'messages_accept_encryption', None),  # 1035731989
        0xf729ea98: (None, 'messages_accept_url_auth', None), # -148247912
        0xf9a0aa09: (None, 'messages_add_chat_user', None),  # -106911223
        0x2ee9ee9e: (None, 'messages_add_chat_user_v_0_1_317'),  # 787082910
        0xb45c69d1: (None, 'messages_affected_history', None),  # -1269012015
        0xb7de36f2: (None, 'messages_affected_history_v_0_1_317'),  # -1210173710
        0x84d19185: (None, 'messages_affected_messages', None),  # -2066640507
        0xedfd405f: (None, 'messages_all_stickers', None),  # -302170017
        0xe86602c3: (None, 'messages_all_stickers_not_modified', None),  # -395967805
        0x4fcba9c8: (None, 'messages_archived_stickers', None),  # 1338747336
        0x36585ea4: (None, 'messages_bot_callback_answer', None),  # 911761060
        0x947ca848: (None, 'messages_bot_results', None),  # -1803769784
        0xccd3563d: (None, 'messages_bot_results_layer71', None),  # -858565059
        0x99262e37: (None, 'messages_channel_messages', None),  # -1725551049
        0x40e9002a: (None, 'messages_chat_v_0_1_317'),  # 1089011754
        0xe5d7d19c: (None, 'messages_chat_full', None),  # -438840932
        0x64ff9fd5: (None, 'messages_chats', None),  # 1694474197
        0x8150cbd8: (None, 'messages_chats_v_0_1_317'),  # -2125411368
        0x9cd81144: (None, 'messages_chats_slice', None),  # -1663561404
        0x3eadb1bb: (None, 'messages_check_chat_invite', None),  # 1051570619
        0x7e58ee9c: (None, 'messages_clear_all_drafts', None),  # 2119757468
        0x8999602d: (None, 'messages_clear_recent_stickers', None),  # -1986437075
        0x09cb126e: (None, 'messages_create_chat', None),  # 164303470
        0x419d9aee: (None, 'messages_create_chat_v_0_1_317'),  # 1100847854
        0xe0611f16: (None, 'messages_delete_chat_user', None),  # -530505962
        0xc3c5cd23: (None, 'messages_delete_chat_user_v_0_1_317'),  # -1010447069
        0x1c015b09: (None, 'messages_delete_history', None),  # 469850889
        0xf4f8fb61: (None, 'messages_delete_history_v_0_1_317'),  # -185009311
        0xe58e95d2: (None, 'messages_delete_messages', None),  # -443640366
        0x59ae2b16: (None, 'messages_delete_scheduled_messages', None), # 1504586518
        0x14f2dd0a: (None, 'messages_delete_messages_v_0_1_317'),  # 351460618
        0x2c221edd: (None, 'messages_dh_config', None),  # 740433629
        0xc0e24635: (None, 'messages_dh_config_not_modified', None),  # -1058912715
        0x15ba6c40: (None, 'messages_dialogs', None),  # 364538944
        0xf0e3e596: (None, 'messages_dialogs_not_modified', None),  # -253500010
        0x71e094f3: (None, 'messages_dialogs_slice', None),  # 1910543603
        0xedd923c5: (None, 'messages_discard_encryption', None),  # -304536635
        0xdef60797: (None, 'messages_edit_chat_about', None),  # -554301545
        0xa9e69f2e: (None, 'messages_edit_chat_admin', None),  # -1444503762
        0xa5866b41: (None, 'messages_edit_chat_default_banned_rights', None),  # -1517917375
        0xca4c79d8: (None, 'messages_edit_chat_photo', None),  # -900957736
        0xd881821d: (None, 'messages_edit_chat_photo_v_0_1_317'),  # -662601187
        0xdc452855: (None, 'messages_edit_chat_title', None),  # -599447467
        0xb4bc68b5: (None, 'messages_edit_chat_title_v_0_1_317'),  # -1262720843
        0x48f71778: (None, 'messages_edit_message', None), # 1224152952
        0xd116f31e: (None, 'messages_edit_message_v_5_6_2', None),  # -787025122
        0x0df7534c: (None, 'messages_export_chat_invite', None),  # 234312524
        0xb9ffc55b: (None, 'messages_fave_sticker', None),  # -1174420133
        0xf37f2f16: (None, 'messages_faved_stickers', None),  # -209768682
        0x9e8fa6d3: (None, 'messages_faved_stickers_not_modified', None),  # -1634752813
        0xb6abc341: (None, 'messages_featured_stickers', None), # -1230257343
        0xc6dc0c66: (None, 'messages_featured_stickers_not_modified', None), # -958657434
        0xf89d88e5: (None, 'messages_featured_stickers_v_5_15_0', None),  # -123893531
        0x04ede3cf: (None, 'messages_featured_stickers_not_modified_v_5_15_0', None),  # 82699215
        0x33963bf9: (None, 'messages_forward_message', None),  # 865483769
        0x03f3f4f2: (None, 'messages_forward_message_v_0_1_317'),  # 66319602
        0xd9fee60e: (None, 'messages_forward_messages', None), # -637606386
        0x514cd10f: (None, 'messages_forward_messages_v_0_1_317'),  # 1363988751
        0x708e0195: (None, 'messages_forward_messages_v_5_6_2', None),  # 1888354709
        0x450a1c0a: (None, 'messages_found_gifs', None),  # 1158290442
        0x5108d648: (None, 'messages_found_sticker_sets', None),  # 1359533640
        0x0d54b65d: (None, 'messages_found_sticker_sets_not_modified', None),  # 223655517
        0xeba80ff0: (None, 'messages_get_all_chats', None),  # -341307408
        0x6a3f8d65: (None, 'messages_get_all_drafts', None),  # 1782549861
        0x1c9618b1: (None, 'messages_get_all_stickers', None),  # 479598769
        0x57f17692: (None, 'messages_get_archived_stickers', None),  # 1475442322
        0xcc5b67cc: (None, 'messages_get_attached_stickers', None),  # -866424884
        0x810a9fec: (None, 'messages_get_bot_callback_answer', None),  # -2130010132
        0x3c6aa187: (None, 'messages_get_chats', None),  # 1013621127
        0x0d0a48c4: (None, 'messages_get_common_chats', None),  # 218777796
        0x26cf8950: (None, 'messages_get_dh_config', None),  # 651135312
        0xf19ed96d: (None, 'messages_get_dialog_filters', None), # -241247891
        0x22e24e22: (None, 'messages_get_dialog_unread_marks', None),  # 585256482
        0xa0ee3b73: (None, 'messages_get_dialogs', None),  # -1594999949
        0xb098aee6: (None, 'messages_get_dialogs_v_5_5_0', None),  # -1332171034
        0xeccf1df6: (None, 'messages_get_dialogs_v_0_1_317'),  # -321970698
        0x338e2464: (None, 'messages_get_document_by_hash', None),  # 864953444
        0x35a0e062: (None, 'messages_get_emoji_keywords', None),  # 899735650
        0x1508b6af: (None, 'messages_get_emoji_keywords_difference', None),  # 352892591
        0x4e9963b2: (None, 'messages_get_emoji_keywords_languages', None),  # 1318675378
        0xd5b10c26: (None, 'messages_get_emoji_url', None),  # -709817306
        0x21ce0b0e: (None, 'messages_get_faved_stickers', None),  # 567151374
        0x2dacca4f: (None, 'messages_get_featured_stickers', None),  # 766298703
        0x3b831c66: (None, 'messages_get_full_chat', None),  # 998448230
        0xe822649d: (None, 'messages_get_game_high_scores', None),  # -400399203
        0xafa92846: (None, 'messages_get_history', None),  # -1347868602
        0x92a1df2f: (None, 'messages_get_history_v_0_1_317'),  # -1834885329
        0x514e999d: (None, 'messages_get_inline_bot_results', None),  # 1364105629
        0x0f635e1b: (None, 'messages_get_inline_game_high_scores', None),  # 258170395
        0x65b8c79f: (None, 'messages_get_mask_stickers', None),  # 1706608543
        0xfda68d36: (None, 'messages_get_message_edit_data', None),  # -39416522
        0x15b1376a: (None, 'messages_get_message_reactions_list', None), # 363935594
        0x4222fa74: (None, 'messages_get_messages', None),  # 1109588596
        0x8bba90e6: (None, 'messages_get_messages_reactions', None), # -1950707482
        0xc4c8a55d: (None, 'messages_get_messages_views', None),  # -993483427
        0x5fe7025b: (None, 'messages_get_old_featured_stickers', None), # 1608974939
        0x6e2be050: (None, 'messages_get_onlines', None),  # 1848369232
        0xe470bcfd: (None, 'messages_get_peer_dialogs', None),  # -462373635
        0x3672e09c: (None, 'messages_get_peer_settings', None),  # 913498268
        0xd6b94df2: (None, 'messages_get_pinned_dialogs', None),  # -692498958
        0xe254d64e: (None, 'messages_get_pinned_dialogs_v_5_5_0', None),  # -497756594
        0x73bb643b: (None, 'messages_get_poll_results', None),  # 1941660731
        0xb86e380e: (None, 'messages_get_poll_votes', None), # -1200736242
        0xbbc45b09: (None, 'messages_get_recent_locations', None),  # -1144759543
        0x5ea192c9: (None, 'messages_get_recent_stickers', None),  # 1587647177
        0x83bf3d52: (None, 'messages_get_saved_gifs', None),  # -2084618926
        0xe2c2685b: (None, 'messages_get_scheduled_history', None), # -490575781
        0xbdbb0464: (None, 'messages_get_scheduled_messages', None), # -1111817116
        0x732eef00: (None, 'messages_get_search_counters', None), # 1932455680
        0x812c2ae6: (None, 'messages_get_stats_url', None),  # -2127811866
        0x2619a90e: (None, 'messages_get_sticker_set', None),  # 639215886
        0x043d4f2c: (None, 'messages_get_stickers', None),  # 71126828
        0xa29cd42c: (None, 'messages_get_suggested_dialog_filters', None), # -1566780372
        0x46578472: (None, 'messages_get_unread_mentions', None),  # 1180140658
        0x32ca8f91: (None, 'messages_get_web_page', None),  # 852135825
        0x8b68b0cc: (None, 'messages_get_web_page_preview', None),  # -1956073268
        0x4facb138: (None, 'messages_hide_peer_settings_bar', None), # 1336717624
        0xa8f1709b: (None, 'messages_hide_report_spam_v_5_6_2', None),  # -1460572005
        0x9a3bfd99: (None, 'messages_high_scores', None),  # -1707344487
        0x6c50051c: (None, 'messages_import_chat_invite', None),  # 1817183516
        0xa927fec5: (None, 'messages_inactive_chats', None), # -1456996667
        0xc78fe460: (None, 'messages_install_sticker_set', None),  # -946871200
        0xc286d98f: (None, 'messages_mark_dialog_unread', None),  # -1031349873
        0x26b5dde6: (None, 'messages_message_edit_data', None),  # 649453030
        0x3f4e0648: (None, 'messages_message_empty', None),  # 1062078024
        0xff90c417: (None, 'messages_message_v_0_1_317'),  # -7289833
        0x8c718e87: (None, 'messages_messages', None),  # -1938715001
        0x74535f21: (None, 'messages_messages_not_modified', None), # 1951620897
        0xc8edce1e: (None, 'messages_messages_slice', None), # -923939298
        0x0b446ae3: (None, 'messages_messages_slice_v_0_1_317'),  # 189033187
        0xa6c47aaa: (None, 'messages_messages_slice_v_5_6_2', None),  # -1497072982
        0x15a3b8e3: (None, 'messages_migrate_chat', None),  # 363051235
        0x3371c354: (None, 'messages_peer_dialogs', None),  # 863093588
        0x7f4b690a: (None, 'messages_read_encrypted_history', None),  # 2135648522
        0x5b118126: (None, 'messages_read_featured_stickers', None),  # 1527873830
        0x0e306d3a: (None, 'messages_read_history', None),  # 238054714
        0xb04f2510: (None, 'messages_read_history_v_0_1_317'),  # -1336990448
        0x0f0189d3: (None, 'messages_read_mentions', None),  # 251759059
        0x36a73f77: (None, 'messages_read_message_contents', None),  # 916930423
        0x05a954c0: (None, 'messages_received_messages', None),  # 94983360
        0x28abcb68: (None, 'messages_received_messages_v_0_1_317'),  # 682347368
        0x55a5bb66: (None, 'messages_received_queue', None),  # 1436924774
        0x22f3afb3: (None, 'messages_recent_stickers', None),  # 586395571
        0x0b17f890: (None, 'messages_recent_stickers_not_modified', None),  # 186120336
        0x3b1adf37: (None, 'messages_reorder_pinned_dialogs', None),  # 991616823
        0x5b51d63f: (None, 'messages_reorder_pinned_dialogs_v_5_5_0', None),  # 1532089919
        0x78337739: (None, 'messages_reorder_sticker_sets', None),  # 2016638777
        0xbd82b658: (None, 'messages_report', None),  # -1115507112
        0x4b0c8c0f: (None, 'messages_report_encrypted_spam', None),  # 1259113487
        0xcf1592db: (None, 'messages_report_spam', None),  # -820669733
        0xf64daf43: (None, 'messages_request_encryption', None),  # -162681021
        0xe33f5613: (None, 'messages_request_url_auth', None), # -482388461
        0x395f9d7e: (None, 'messages_restore_messages_v_0_1_317'),  # 962567550
        0xbc39e14b: (None, 'messages_save_draft', None),  # -1137057461
        0x327a30cb: (None, 'messages_save_gif', None),  # 846868683
        0x392718f8: (None, 'messages_save_recent_sticker', None),  # 958863608
        0x2e0709a5: (None, 'messages_saved_gifs', None),  # 772213157
        0xe8025ca2: (None, 'messages_saved_gifs_not_modified', None),  # -402498398
        0x8614ef68: (None, 'messages_search', None),  # -2045448344
        0xe844ebff: (None, 'messages_search_counter', None), # -398136321
        0x07e9f2ab: (None, 'messages_search_v_0_1_317'),  # 132772523
        0xbf9a776b: (None, 'messages_search_gifs', None),  # -1080395925
        0xbf7225a4: (None, 'messages_search_global', None), # -1083038300
        0x9e3cacb0: (None, 'messages_search_global_v_5_6_2', None),  # -1640190800
        0xc2b7d08b: (None, 'messages_search_sticker_sets', None),  # -1028140917
        0xbf73f4da: (None, 'messages_send_broadcast_v_5_6_2', None),  # -1082919718
        0x41bb0972: (None, 'messages_send_broadcast_v_0_1_317'),  # 1102776690
        0xa9776773: (None, 'messages_send_encrypted', None),  # -1451792525
        0x9a901b66: (None, 'messages_send_encrypted_file', None),  # -1701831834
        0xcacacaca: (None, 'messages_send_encrypted_multi_media', None),  # -892679478
        0x32d439a4: (None, 'messages_send_encrypted_service', None),  # 852769188
        0x220815b0: (None, 'messages_send_inline_bot_result', None), # 570955184
        0xb16e06fe: (None, 'messages_send_inline_bot_result_v_5_6_2', None),  # -1318189314
        0x3491eba9: (None, 'messages_send_media', None), # 881978281
        0xa3c85d76: (None, 'messages_send_media_v_0_1_317'),  # -1547149962
        0xb8d1262b: (None, 'messages_send_media_v_5_6_2', None),  # -1194252757
        0x520c3870: (None, 'messages_send_message', None), # 1376532592
        0x4cde0aab: (None, 'messages_send_message_v_0_1_317'),  # 1289620139
        0xfa88427a: (None, 'messages_send_message_v_5_6_2', None),  # -91733382
        0x2095512f: (None, 'messages_send_multi_media_v_5_6_2', None),  # 546656559
        0x25690ce4: (None, 'messages_send_reaction', None), # 627641572
        0xbd38850a: (None, 'messages_send_scheduled_messages', None), # -1120369398
        0xc97df020: (None, 'messages_send_screenshot_notification', None),  # -914493408
        0x10ea6184: (None, 'messages_send_vote', None),  # 283795844
        0xd1f4d35c: (None, 'messages_sent_message_v_0_1_317'),  # -772484260
        0xe9db4a3f: (None, 'messages_sent_message_link_v_0_1_317'),  # -371504577
        0x9493ff32: (None, 'messages_sent_encrypted_file', None),  # -1802240206
        0x560f8935: (None, 'messages_sent_encrypted_message', None),  # 1443858741
        0xd58f130a: (None, 'messages_set_bot_callback_answer', None),  # -712043766
        0x791451ed: (None, 'messages_set_encrypted_typing', None),  # 2031374829
        0x8ef8ecc0: (None, 'messages_set_game_score', None),  # -1896289088
        0x15ad9f64: (None, 'messages_set_inline_game_score', None),  # 363700068
        0xa3825e50: (None, 'messages_set_typing', None),  # -1551737264
        0x719839e9: (None, 'messages_set_typing_v_0_1_317'),  # 1905801705
        0xe6df7378: (None, 'messages_start_bot', None),  # -421563528
        0xd07ae726: (None, 'messages_stated_message_v_0_1_317'),  # -797251802
        0xa9af2881: (None, 'messages_stated_message_link_v_0_1_317'),  # -1448138623
        0x969478bb: (None, 'messages_stated_messages_v_0_1_317'),  # -1768654661
        0x3e74f5c6: (None, 'messages_stated_messages_links_v_0_1_317'),  # 1047852486
        0xb60a24a6: (None, 'messages_sticker_set', None),  # -1240849242
        0x35e410a8: (None, 'messages_sticker_set_install_result_archive', None),  # 904138920
        0x38641628: (None, 'messages_sticker_set_install_result_success', None),  # 946083368
        0xe4599bbd: (None, 'messages_stickers', None),  # -463889475
        0xf1749a22: (None, 'messages_stickers_not_modified', None),  # -244016606
        0xa731e257: (None, 'messages_toggle_dialog_pin', None),  # -1489903017
        0xb5052fea: (None, 'messages_toggle_sticker_sets', None), # -1257951254
        0xf96e55de: (None, 'messages_uninstall_sticker_set', None),  # -110209570
        0x1ad4a04a: (None, 'messages_update_dialog_filter', None), # 450142282
        0xc563c1e4: (None, 'messages_update_dialog_filters_order', None), # -983318044
        0xd2aaf7ec: (None, 'messages_update_pinned_message', None),  # -760547348
        0x5057c497: (None, 'messages_upload_encrypted_file', None),  # 1347929239
        0x519bc2b1: (None, 'messages_upload_media', None),  # 1369162417
        0x0823f649: (None, 'messages_votes_list', None), # 136574537
        0x73f1f8dc: (None, 'msg_container_v_0_1_317'),  # 1945237724
        0xe06046b2: (None, 'msg_copy_v_0_1_317'),  # -530561358
        0x276d3ec6: (None, 'msg_detailed_info_v_0_1_317'),  # 661470918
        0x809db6df: (None, 'msg_new_detailed_info_v_0_1_317'),  # -2137147681
        0x7d861a08: (None, 'msg_resend_req_v_0_1_317'),  # 2105940488
        0x62d6b459: (None, 'msgs_ack_v_0_1_317'),  # 1658238041
        0x8cc0d131: (None, 'msgs_all_info_v_0_1_317'),  # -1933520591
        0x04deb57d: (None, 'msgs_state_info_v_0_1_317'),  # 81704317
        0xda69fb52: (None, 'msgs_state_req_v_0_1_317'),  # -630588590
        0x8e1a1775: (None, 'nearest_dc', None),  # -1910892683
        0x9ec20908: (None, 'new_session_created_v_0_1_317'),  # -1631450872
        0xd612e8ef: (None, 'notify_broadcasts', None),  # -703403793
        0xc007cec3: (None, 'notify_chats', None),  # -1073230141
        0x9fd40bd8: (None, 'notify_peer', None),  # -1613493288
        0xb4c83b4c: (None, 'notify_users', None),  # -1261946036
        0x56730bcc: (None, 'null', None),  # 1450380236
        0x83c95aec: (None, 'p_q_inner_data_v_0_1_317'),  # -2083955988
        0x98657f0d: (page_struct, 'page', None), # -1738178803
        0xce0d37b0: (page_block_anchor_struct, 'page_block_anchor', None),  # -837994576
        0x804361ea: (page_block_audio_struct, 'page_block_audio', None),  # -2143067670
        0x31b81a7f: (page_block_audio_layer82_struct, 'page_block_audio_layer82', None),  # 834148991
        0xbaafe5e0: (page_block_author_date_struct, 'page_block_author_date', None),  # -1162877472
        0x3d5b64f2: (page_block_author_date_layer60_struct, 'page_block_author_date_layer60', None),  # 1029399794
        0x263d7c26: (page_block_blockquote_struct, 'page_block_blockquote', None),  # 641563686
        0xef1751b5: (page_block_channel_struct, 'page_block_channel', None),  # -283684427
        0x65a0fa4d: (page_block_collage_struct, 'page_block_collage', None),  # 1705048653
        0x08b31c4f: (page_block_collage_layer82_struct, 'page_block_collage_layer82', None),  # 145955919
        0x39f23300: (page_block_cover_struct, 'page_block_cover', None),  # 972174080
        0x76768bed: (page_block_details_struct, 'page_block_details', None),  # 1987480557
        0xdb20b188: (page_block_divider_struct, 'page_block_divider', None),  # -618614392
        0xa8718dc5: (page_block_embed_struct, 'page_block_embed', None),  # -1468953147
        0xf259a80b: (page_block_embed_post_struct, 'page_block_embed_post', None),  # -229005301
        0x292c7be9: (page_block_embed_post_layer82_struct, 'page_block_embed_post_layer82', None),  # 690781161
        0xd935d8fb: (page_block_embed_layer60_struct, 'page_block_embed_layer60', None),  # -650782469
        0xcde200d1: (page_block_embed_layer82_struct, 'page_block_embed_layer82', None),  # -840826671
        0x48870999: (page_block_footer_struct, 'page_block_footer', None),  # 1216809369
        0xbfd064ec: (page_block_header_struct, 'page_block_header', None),  # -1076861716
        0x1e148390: (page_block_kicker_struct, 'page_block_kicker', None),  # 504660880
        0xe4e88011: (page_block_list_struct, 'page_block_list', None),  # -454524911
        0x3a58c7f4: (page_block_list_layer82_struct, 'page_block_list_layer82', None),  # 978896884
        0xa44f3ef6: (page_block_map_struct, 'page_block_map', None),  # -1538310410
        0x9a8ae1e1: (page_block_ordered_list_struct, 'page_block_ordered_list', None),  # -1702174239
        0x467a0766: (page_block_paragraph_struct, 'page_block_paragraph', None),  # 1182402406
        0x1759c560: (page_block_photo_struct, 'page_block_photo', None),  # 391759200
        0xe9c69982: (page_block_photo_layer82_struct, 'page_block_photo_layer82', None),  # -372860542
        0xc070d93e: (page_block_preformatted_struct, 'page_block_preformatted', None),  # -1066346178
        0x4f4456d3: (page_block_pullquote_struct, 'page_block_pullquote', None),  # 1329878739
        0x16115a96: (page_block_related_articles_struct, 'page_block_related_articles', None),  # 370236054
        0x031f9590: (page_block_slideshow_struct, 'page_block_slideshow', None),  # 52401552
        0x130c8963: (page_block_slideshow_layer82_struct, 'page_block_slideshow_layer82', None),  # 319588707
        0xf12bb6e1: (page_block_subheader_struct, 'page_block_subheader', None),  # -248793375
        0x8ffa9a1f: (page_block_subtitle_struct, 'page_block_subtitle', None),  # -1879401953
        0xbf4dea82: (page_block_table_struct, 'page_block_table', None),  # -1085412734
        0x70abc3fd: (page_block_title_struct, 'page_block_title', None),  # 1890305021
        0x13567e8a: (page_block_unsupported_struct, 'page_block_unsupported', None),  # 324435594
        0x7c8fe7b6: (page_block_video_struct, 'page_block_video', None),  # 2089805750
        0xd9d71866: (page_block_video_layer82_struct, 'page_block_video_layer82', None),  # -640214938
        0x6f747657: (page_caption_struct, 'page_caption', None),  # 1869903447
        0xd7a19d69: (page_full_layer67_struct, 'page_full_layer67', None),  # -677274263
        0x556ec7aa: (page_full_layer82_struct, 'page_full_layer82', None),  # 1433323434
        0xae891bec: (page_layer110_struct, 'page_layer110', None),  # -1366746132
        0x25e073fc: (page_list_item_blocks_struct, 'page_list_item_blocks', None),  # 635466748
        0xb92fb6cd: (page_list_item_text_struct, 'page_list_item_text', None),  # -1188055347
        0x98dd8936: (page_list_ordered_item_blocks_struct, 'page_list_ordered_item_blocks', None),  # -1730311882
        0x5e068047: (page_list_ordered_item_text_struct, 'page_list_ordered_item_text', None),  # 1577484359
        0x8dee6c44: (page_part_layer67_struct, 'page_part_layer67', None),  # -1913754556
        0x8e3f9ebe: (page_part_layer82_struct, 'page_part_layer82', None),  # -1908433218
        0xb390dc08: (page_related_article_struct, 'page_related_article', None),  # -1282352120
        0x34566b6a: (page_table_cell_struct, 'page_table_cell', None),  # 878078826
        0xe0c0c5e5: (page_table_row_struct, 'page_table_row', None),  # -524237339
        0x3a912d4a: (None, 'password_kdf_algo_sha256_sha256_pbkdf2_hmac_sha512iter100000_sha256_mod_pow', None),  # 982592842
        0xd45ab096: (None, 'password_kdf_algo_unknown', None),  # -732254058
        0x909c3f94: (None, 'payment_requested_info', None),  # -1868808300
        0xcdc27a1f: (None, 'payment_saved_credentials_card', None),  # -842892769
        0x3e24e573: (None, 'payments_bank_card_data', None), # 1042605427
        0xd83d70c1: (None, 'payments_clear_saved_info', None),  # -667062079
        0x2e79d779: (None, 'payments_get_bank_card_data', None), # 779736953
        0x99f09745: (None, 'payments_get_payment_form', None),  # -1712285883
        0xa092a980: (None, 'payments_get_payment_receipt', None),  # -1601001088
        0x227d824b: (None, 'payments_get_saved_info', None),  # 578650699
        0x3f56aea3: (None, 'payments_payment_form', None),  # 1062645411
        0x500911e1: (None, 'payments_payment_receipt', None),  # 1342771681
        0x4e5f810d: (None, 'payments_payment_result', None),  # 1314881805
        0xd8411139: (None, 'payments_payment_verification_needed', None), # -666824391
        0x6b56b921: (None, 'payments_payment_verfication_needed_v_5_6_2', None),  # 1800845601
        0xfb8fe43c: (None, 'payments_saved_info', None),  # -74456004
        0x2b8879b3: (None, 'payments_send_payment_form', None),  # 730364339
        0x770a8e74: (None, 'payments_validate_requested_info', None),  # 1997180532
        0xd1451883: (None, 'payments_validated_requested_info', None),  # -784000893
        0xbddde532: (peer_channel_struct, 'peer_channel', None),  # -1109531342
        0xbad0e5bb: (peer_chat_struct, 'peer_chat', None),  # -1160714821
        0xca461b5d: (None, 'peer_located', None), # -901375139
        0x6d1ded88: (None, 'peer_notify_events_all_v_0_1_317'),  # 1830677896
        0xadd53cb3: (None, 'peer_notify_events_empty_v_0_1_317'),  # -1378534221
        0xaf509d20: (peer_notify_settings_struct, 'peer_notify_settings', None),  # -1353671392
        0x70a68512: (peer_notify_settings_empty_layer77_struct, 'peer_notify_settings_empty_layer77', None),  # 1889961234
        0x8d5e11ee: (peer_notify_settings_layer47_struct, 'peer_notify_settings_layer47', None),  # -1923214866
        0x9acda4c0: (peer_notify_settings_layer77_struct, 'peer_notify_settings_layer77', None),  # -1697798976
        0xf8ec284b: (None, 'peer_self_located', None), # -118740917
        0x733f2961: (peer_settings_struct, 'peer_settings', None), # 1933519201
        0x818426cd: (peer_settings_v_5_15_0_struct, 'peer_settings_v_5_15_0', None),  # -2122045747
        0x9db1bc6d: (peer_user_struct, 'peer_user', None),  # -1649296275
        0x8742ae7f: (None, 'phone_call', None),  # -2025673089
        0xe6f9ddf3: (None, 'phone_call_v_5_5_0', None),  # -419832333
        0x997c454a: (None, 'phone_call_accepted', None),  # -1719909046
        0x6d003d3f: (None, 'phone_call_accepted_v_5_5_0', None),  # 1828732223
        0xafe2b839: (phone_call_discard_reason_allow_group_call_struct, 'phone_call_discard_reason_allow_group_call', None),  # -1344096199
        0xfaf7e8c9: (phone_call_discard_reason_busy_struct, 'phone_call_discard_reason_busy', None),  # -84416311
        0xe095c1a0: (phone_call_discard_reason_disconnect_struct, 'phone_call_discard_reason_disconnect', None),  # -527056480
        0x57adc690: (phone_call_discard_reason_hangup_struct, 'phone_call_discard_reason_hangup', None),  # 1471006352
        0x85e42301: (phone_call_discard_reason_missed_struct, 'phone_call_discard_reason_missed', None),  # -2048646399
        0x50ca4de1: (phone_call_discarded_struct, 'phone_call_discarded', None),  # 1355435489
        0x5366c915: (None, 'phone_call_empty', None),  # 1399245077
        0xfc878fc8: (None, 'phone_call_protocol', None), # -58224696
        0xa2bb35cb: (None, 'phone_call_protocol_layer110', None),  # -1564789301
        0x87eabb53: (None, 'phone_call_requested', None),  # -2014659757
        0x83761ce4: (None, 'phone_call_requested_v_5_5_0', None),  # -2089411356
        0x1b8f4ad1: (None, 'phone_call_waiting', None),  # 462375633
        0xffe6ab67: (None, 'phone_call_layer86_v_5_5_0', None),  # -1660057
        0x9d4c17c0: (None, 'phone_connection', None),  # -1655957568
        0x3bd2b4a0: (None, 'phone_accept_call', None),  # 1003664544
        0x2efe1722: (None, 'phone_confirm_call', None),  # 788404002
        0x8504e5b6: (None, 'phone_create_group_call', None),  # -2063276618
        0xb2cbc1c0: (None, 'phone_discard_call', None),  # -1295269440
        0x78d413a6: (None, 'phone_discard_call_v_5_5_0', None),  # 2027164582
        0x7a777135: (None, 'phone_discard_group_call', None),  # 2054648117
        0x46659be4: (None, 'phone_edit_group_call_member', None),  # 1181064164
        0x8adb4f79: (None, 'phone_get_call', None),  # -1965338759
        0x55451fa9: (None, 'phone_get_call_config', None),  # 1430593449
        0x0c7cb017: (None, 'phone_get_group_call', None),  # 209498135
        0x6737ffb7: (None, 'phone_group_call', None),  # 1731723191
        0xcc92a6dc: (None, 'phone_invite_group_call_members', None),  # -862804260
        0x09db32d7: (None, 'phone_join_group_call', None),  # 165360343
        0x60e98e5f: (None, 'phone_leave_group_call', None),  # 1625919071
        0xec82e140: (None, 'phone_phone_call', None),  # -326966976
        0x17d54f61: (None, 'phone_received_call', None),  # 399855457
        0x42ff96ed: (None, 'phone_request_call', None),  # 1124046573
        0x5b95b3d4: (None, 'phone_request_call_v_5_5_0', None),  # 1536537556
        0x277add7e: (None, 'phone_save_call_debug', None),  # 662363518
        0x59ead627: (None, 'phone_set_call_rating', None),  # 1508562471
        0x1c536a34: (None, 'phone_set_call_rating_v_5_5_0', None),  # 475228724
        0x98e3cdba: (None, 'phone_upgrade_phone_call', None),  # -1729901126
        0xfb197a65: (photo_struct, 'photo', None), # -82216347
        0xe9a734fa: (photo_cached_size_struct, 'photo_cached_size', None),  # -374917894
        0x2331b22d: (photo_empty_struct, 'photo_empty', None),  # 590459437
        0xd07504a5: (photo_layer115_struct, 'photo_layer115', None),  # -797637467
        0x77bfb61b: (photo_size_struct, 'photo_size', None),  # 2009052699
        0x0e17e23c: (photo_size_empty_struct, 'photo_size_empty', None),  # 236446268
        0xcded42fe: (photo_layer55_struct, 'photo_layer55', None),  # -840088834
        0x9288dd29: (photo_layer82_struct, 'photo_layer82', None),  # -1836524247
        0x9c477dd8: (photo_layer97_struct, 'photo_layer97', None),  # -1673036328
        0x22b56751: (photo_old_struct, 'photo_old', None),  # 582313809
        0xc3838076: (photo_old2_struct, 'photo_old2', None),  # -1014792074
        0xe0b0bc2e: (photo_stripped_size_struct, 'photo_stripped_size', None),  # -525288402
        0x87cf7f2f: (None, 'photos_delete_photos', None),  # -2016444625
        0x91cd32a8: (None, 'photos_get_user_photos', None),  # -1848823128
        0xb7ee553c: (None, 'photos_get_user_photos_v_0_1_317'),  # -1209117380
        0x20212ca8: (None, 'photos_photo', None),  # 539045032
        0x8dca6aa5: (None, 'photos_photos', None),  # -1916114267
        0x15051f54: (None, 'photos_photos_slice', None),  # 352657236
        0x72d4742c: (None, 'photos_update_profile_photo', None), # 1926525996
        0xeef579a0: (None, 'photos_update_profile_photo_v_0_1_317'),  # -285902432
        0xf0bb5152: (None, 'photos_update_profile_photo_v_5_15_0', None),  # -256159406
        0x89f30f69: (None, 'photos_upload_profile_photo', None), # -1980559511
        0xd50f9c88: (None, 'photos_upload_profile_photo_v_0_1_317'),  # -720397176
        0x4f32c098: (None, 'photos_upload_profile_photo_v_5_15_0', None),  # 1328726168
        0x7abe77ec: (None, 'ping_v_0_1_317'),  # 2059302892
        0x86e18161: (poll_struct, 'poll', None), # -2032041631
        0x6ca9c2e9: (poll_answer_struct, 'poll_answer', None),  # 1823064809
        0x3b6ddad2: (poll_answer_voters_struct, 'poll_answer_voters', None),  # 997055186
        0xd5529d06: (poll_layer111_struct, 'poll_layer111', None),  # -716006138
        0xbadcc1a3: (poll_results_struct, 'poll_results', None), # -1159937629
        0x5755785a: (poll_results_layer108_struct, 'poll_results_layer108', None),  # 1465219162
        0xc87024a2: (poll_results_layer111_struct, 'poll_results_layer111', None), # -932174686
        0xaf746786: (poll_to_delete_struct, 'poll_to_delete', None), # -1351325818
        0x347773c5: (None, 'pong_v_0_1_317'),  # 880243653
        0x5ce14175: (None, 'popular_contact', None),  # 1558266229
        0x1e8caaeb: (None, 'post_address', None),  # 512535275
        0x42ffd42b: (None, 'privacy_key_added_by_phone', None), # 1124062251
        0x500e6dfa: (None, 'privacy_key_chat_invite', None),  # 1343122938
        0x69ec56a3: (None, 'privacy_key_forwards', None),  # 1777096355
        0x3d662b7b: (None, 'privacy_key_phone_call', None),  # 1030105979
        0xd19ae46d: (None, 'privacy_key_phone_number', None), # -778378131
        0x39491cc8: (None, 'privacy_key_phone_p2p', None),  # 961092808
        0x96151fed: (None, 'privacy_key_profile_photo', None),  # -1777000467
        0xbc2eab30: (None, 'privacy_key_status_timestamp', None),  # -1137792208
        0x65427b82: (None, 'privacy_value_allow_all', None),  # 1698855810
        0x18be796b: (None, 'privacy_value_allow_chat_participants', None), # 415136107
        0xfffe1bac: (None, 'privacy_value_allow_contacts', None),  # -123988
        0x4d5bbe0c: (None, 'privacy_value_allow_users', None),  # 1297858060
        0x8b73e763: (None, 'privacy_value_disallow_all', None),  # -1955338397
        0xacae0690: (None, 'privacy_value_disallow_chat_participants', None), # -1397881200
        0xf888fa1a: (None, 'privacy_value_disallow_contacts', None),  # -125240806
        0x0c7f49b7: (None, 'privacy_value_disallow_users', None),  # 209668535
        0x5bb8e511: (None, 'proto_message_v_0_1_317'),  # 1538843921
        0x6fb250d1: (reaction_count_struct, 'reaction_count', None), # 1873957073
        0xa384b779: (None, 'received_notify_message', None),  # -1551583367
        0xa01b22f9: (None, 'recent_me_url_chat', None),  # -1608834311
        0xeb49081d: (None, 'recent_me_url_chat_invite', None),  # -347535331
        0xbc0a57dc: (None, 'recent_me_url_sticker_set', None),  # -1140172836
        0x46e1d13d: (None, 'recent_me_url_unknown', None),  # 1189204285
        0x8dbc3336: (None, 'recent_me_url_user', None),  # -1917045962
        0x48a30254: (reply_inline_markup_struct, 'reply_inline_markup', None),  # 1218642516
        0xf4108aa0: (reply_keyboard_force_reply_struct, 'reply_keyboard_force_reply', None),  # -200242528
        0xa03e5b85: (reply_keyboard_hide_struct, 'reply_keyboard_hide', None),  # -1606526075
        0x3502758c: (reply_keyboard_markup_struct, 'reply_keyboard_markup', None),  # 889353612
        0xd712e4be: (None, 'req_dh_params_v_0_1_317'),  # -686627650
        0x60469778: (None, 'req_pq_v_0_1_317'),  # 1615239032
        0x05162463: (None, 'res_pq_v_0_1_317'),  # 85337187
        0xd072acb4: (restriction_reason_struct, 'restriction_reason', None), # -797791052
        0xa43ad8b7: (None, 'rpc_answer_dropped_v_0_1_317'),  # -1539647305
        0xcd78e586: (None, 'rpc_answer_dropped_running_v_0_1_317'),  # -847714938
        0x5e2ad36e: (None, 'rpc_answer_unknown_v_0_1_317'),  # 1579864942
        0x58e4a740: (None, 'rpc_drop_answer_v_0_1_317'),  # 1491380032
        0x2144ca19: (None, 'rpc_error_v_0_1_317'),  # 558156313
        0x7ae432f5: (None, 'rpc_req_error_v_0_1_317'),  # 2061775605
        0xf35c6d01: (None, 'rpc_result_v_0_1_317'),  # -212046591
        0x33f0ea47: (None, 'secure_credentials_encrypted', None),  # 871426631
        0x8aeabec3: (None, 'secure_data', None),  # -1964327229
        0xe0277a62: (None, 'secure_file', None),  # -534283678
        0x64199744: (None, 'secure_file_empty', None),  # 1679398724
        0xbbf2dda0: (None, 'secure_password_kdf_algo_pbkdf2_hmac_sha512_iter100000', None),  # -1141711456
        0x86471d92: (None, 'secure_password_kdf_algo_sha512', None),  # -2042159726
        0x004a8537: (None, 'secure_password_kdf_algo_unknown', None),  # 4883767
        0x21ec5a5f: (None, 'secure_plain_email', None),  # 569137759
        0x7d6099dd: (None, 'secure_plain_phone', None),  # 2103482845
        0x829d99da: (None, 'secure_required_type', None),  # -2103600678
        0x027477b4: (None, 'secure_required_type_one_of', None),  # 41187252
        0x1527bcac: (None, 'secure_secret_settings', None),  # 354925740
        0x187fa0ca: (None, 'secure_value', None),  # 411017418
        0x869d758f: (None, 'secure_value_error', None),  # -2036501105
        0xe8a40bd9: (None, 'secure_value_error_data', None),  # -391902247
        0x7a700873: (None, 'secure_value_error_file', None),  # 2054162547
        0x666220e9: (None, 'secure_value_error_files', None),  # 1717706985
        0x00be3dfa: (None, 'secure_value_error_front_side', None),  # 12467706
        0x868a2aa5: (None, 'secure_value_error_reverse_side', None),  # -2037765467
        0xe537ced6: (None, 'secure_value_error_selfie', None),  # -449327402
        0xa1144770: (None, 'secure_value_error_translation_file', None),  # -1592506512
        0x34636dd8: (None, 'secure_value_error_translation_files', None),  # 878931416
        0xed1ecdb0: (None, 'secure_value_hash', None),  # -316748368
        0xcbe31e26: (secure_value_type_address_struct, 'secure_value_type_address', None),  # -874308058
        0x89137c0d: (secure_value_type_bank_statement_struct, 'secure_value_type_bank_statement', None),  # -1995211763
        0x06e425c4: (secure_value_type_driver_license_struct, 'secure_value_type_driver_license', None),  # 115615172
        0x8e3ca7ee: (secure_value_type_email_struct, 'secure_value_type_email', None),  # -1908627474
        0xa0d0744b: (secure_value_type_identity_card_struct, 'secure_value_type_identity_card', None),  # -1596951477
        0x99a48f23: (secure_value_type_internal_passport_struct, 'secure_value_type_internal_passport', None),  # -1717268701
        0x3dac6a00: (secure_value_type_passport_struct, 'secure_value_type_passport', None),  # 1034709504
        0x99e3806a: (secure_value_type_passport_registration_struct, 'secure_value_type_passport_registration', None),  # -1713143702
        0x9d2a81e3: (secure_value_type_personal_details_struct, 'secure_value_type_personal_details', None),  # -1658158621
        0xb320aadb: (secure_value_type_phone_struct, 'secure_value_type_phone', None),  # -1289704741
        0x8b883488: (secure_value_type_rental_agreement_struct, 'secure_value_type_rental_agreement', None),  # -1954007928
        0xea02ec33: (secure_value_type_temporary_registration_struct, 'secure_value_type_temporary_registration', None),  # -368907213
        0xfc36954e: (secure_value_type_utility_bill_struct, 'secure_value_type_utility_bill', None),  # -63531698
        0xfd5ec8f5: (send_message_cancel_action_struct, 'send_message_cancel_action', None),  # -44119819
        0x628cbc6f: (send_message_choose_contact_action_struct, 'send_message_choose_contact_action', None),  # 1653390447
        0xdd6a8f48: (send_message_game_play_action_struct, 'send_message_game_play_action', None),  # -580219064
        0x176f8ba1: (send_message_geo_location_action_struct, 'send_message_geo_location_action', None),  # 393186209
        0xd52f73f7: (send_message_record_audio_action_struct, 'send_message_record_audio_action', None),  # -718310409
        0x88f27fbc: (send_message_record_round_action_struct, 'send_message_record_round_action', None),  # -1997373508
        0xa187d66f: (send_message_record_video_action_struct, 'send_message_record_video_action', None),  # -1584933265
        0x16bf744e: (send_message_typing_action_struct, 'send_message_typing_action', None),  # 381645902
        0xf351d7ab: (send_message_upload_audio_action_struct, 'send_message_upload_audio_action', None),  # -212740181
        0xe6ac8a6f: (send_message_upload_audio_action_old_struct, 'send_message_upload_audio_action_old', None),  # -424899985
        0xaa0cd9e4: (send_message_upload_document_action_struct, 'send_message_upload_document_action', None),  # -1441998364
        0x8faee98e: (send_message_upload_document_action_old_struct, 'send_message_upload_document_action_old', None),  # -1884362354
        0xd1d34a26: (send_message_upload_photo_action_struct, 'send_message_upload_photo_action', None),  # -774682074
        0x990a3c1a: (send_message_upload_photo_action_old_struct, 'send_message_upload_photo_action_old', None),  # -1727382502
        0x243e1c66: (send_message_upload_round_action_struct, 'send_message_upload_round_action', None),  # 608050278
        0xe9763aec: (send_message_upload_video_action_struct, 'send_message_upload_video_action', None),  # -378127636
        0x92042ff7: (send_message_upload_video_action_old_struct, 'send_message_upload_video_action_old', None),  # -1845219337
        0xb5890dba: (None, 'server_dh_inner_data_v_0_1_317'),  # -1249309254
        0x79cb045d: (None, 'server_dh_params_fail_v_0_1_317'),  # 2043348061
        0xd0e8075c: (None, 'server_dh_params_ok_v_0_1_317'),  # -790100132
        0xf5045f1f: (None, 'set_client_dh_params_v_0_1_317'),  # -184262881
        0xb6213cdf: (None, 'shipping_option', None),  # -1239335713
        0xcb43acde: (None, 'stats_abs_value_and_prev', None), # -884757282
        0xbdf78394: (None, 'stats_broadcast_stats', None), # -1107852396
        0xb637edaf: (None, 'stats_date_range_days', None), # -1237848657
        0xab42441a: (None, 'stats_get_broadcast_stats', None), # -1421720550
        0xdcdf8607: (None, 'stats_get_megagroup_stats', None), # -589330937
        0x4a27eb2d: (None, 'stats_graph_async', None), # 1244130093
        0xbedc9822: (None, 'stats_graph_error', None), # -1092839390
        0x8ea464b6: (None, 'stats_graph', None), # -1901828938
        0x6014f412: (None, 'stats_group_top_admin', None), # 1611985938
        0x31962a4c: (None, 'stats_group_top_inviter', None), # 831924812
        0x18f3d0f7: (None, 'stats_group_top_poster', None), # 418631927
        0x621d5fa0: (None, 'stats_load_async_graph', None), # 1646092192
        0xef7ff916: (None, 'stats_megagroup_stats', None), # -276825834
        0xcbce2fe0: (None, 'stats_percent_value', None), # -875679776
        0x47a971e0: (None, 'stats_url', None),  # 1202287072
        0x12b299d4: (None, 'sticker_pack', None),  # 313694676
        0xeeb46f27: (None, 'sticker_set', None),  # -290164953
        0x6410a5d2: (None, 'sticker_set_covered', None),  # 1678812626
        0x3407e51b: (None, 'sticker_set_multi_covered', None),  # 872932635
        0xcd303b41: (None, 'sticker_set_layer75', None),  # -852477119
        0x5585a139: (None, 'sticker_set_layer96', None),  # 1434820921
        0x6a90bcb7: (None, 'sticker_set_layer97', None),  # 1787870391
        0xa7a43b17: (None, 'sticker_set_old', None),  # -1482409193
        0xcae1aadf: (None, 'storage_file_gif', None),  # -891180321
        0x007efe0e: (None, 'storage_file_jpeg', None),  # 8322574
        0x4b09ebbc: (None, 'storage_file_mov', None),  # 1258941372
        0x528a0677: (None, 'storage_file_mp3', None),  # 1384777335
        0xb3cea0e4: (None, 'storage_file_mp4', None),  # -1278304028
        0x40bc6f52: (None, 'storage_file_partial', None),  # 1086091090
        0xae1e508d: (None, 'storage_file_pdf', None),  # -1373745011
        0x0a4f63c0: (None, 'storage_file_png', None),  # 172975040
        0xaa963b05: (None, 'storage_file_unknown', None),  # -1432995067
        0x1081464c: (None, 'storage_file_webp', None),  # 276907596
        0x35553762: (text_anchor_struct, 'text_anchor', None),  # 894777186
        0x6724abc4: (text_bold_struct, 'text_bold', None),  # 1730456516
        0x7e6260d7: (text_concat_struct, 'text_concat', None),  # 2120376535
        0xde5a0dd6: (text_email_struct, 'text_email', None),  # -564523562
        0xdc3d824f: (text_empty_struct, 'text_empty', None),  # -599948721
        0x6c3f19b9: (text_fixed_struct, 'text_fixed', None),  # 1816074681
        0x081ccf4f: (text_image_struct, 'text_image', None),  # 136105807
        0xd912a59c: (text_italic_struct, 'text_italic', None),  # -653089380
        0x034b8621: (text_marked_struct, 'text_marked', None),  # 55281185
        0x1ccb966a: (text_phone_struct, 'text_phone', None),  # 483104362
        0x744694e0: (text_plain_struct, 'text_plain', None),  # 1950782688
        0x9bf8bb95: (text_strike_struct, 'text_strike', None),  # -1678197867
        0xed6a8504: (text_subscript_struct, 'text_subscript', None),  # -311786236
        0xc7fb5e01: (text_superscript_struct, 'text_superscript', None),  # -939827711
        0xc12622c4: (text_underline_struct, 'text_underline', None),  # -1054465340
        0x3c2884c1: (text_url_struct, 'text_url', None),  # 1009288385
        0x028f1114: (None, 'theme', None), # 42930452
        0x483d270c: (None, 'theme_document_not_modified_layer106', None), # 1211967244
        0x9c14984a: (theme_settings_struct, 'theme_settings', None), # -1676371894
        0xf7d90ce0: (None, 'theme_layer106', None), # -136770336
        0xedcdc05b: (None, 'top_peer', None),  # -305282981
        0x148677e2: (None, 'top_peer_category_bots_inline', None),  # 344356834
        0xab661b5b: (None, 'top_peer_category_bots_p_m', None),  # -1419371685
        0x161d9628: (None, 'top_peer_category_channels', None),  # 371037736
        0x0637b7ed: (None, 'top_peer_category_correspondents', None),  # 104314861
        0xfbeec0f0: (None, 'top_peer_category_forward_chats', None), # -68239120
        0xa8406ca9: (None, 'top_peer_category_forward_users', None), # -1472172887
        0xbd17a14a: (None, 'top_peer_category_groups', None),  # -1122524854
        0xfb834291: (None, 'top_peer_category_peers', None),  # -75283823
        0x1e76a78c: (None, 'top_peer_category_phone_calls', None),  # 511092620
        0x6f690963: (None, 'update_activation_v_0_1_317'),  # 1869154659
        0xb6d45656: (None, 'update_channel', None),  # -1227598250
        0x70db6837: (None, 'update_channel_available_messages', None),  # 1893427255
        0x98a12b4b: (None, 'update_channel_message_views', None),  # -1734268085
        0x65d2b464: (None, 'update_channel_participant', None), # 1708307556
        0x98592475: (None, 'update_channel_pinned_message', None),  # -1738988427
        0x89893b45: (None, 'update_channel_read_messages_contents', None),  # -1987495099
        0xeb0467fb: (None, 'update_channel_too_long', None),  # -352032773
        0x40771900: (None, 'update_channel_web_page', None),  # 1081547008
        0x54c01850: (None, 'update_chat_default_banned_rights', None),  # 1421875280
        0xea4b0e5c: (None, 'update_chat_participant_add', None),  # -364179876
        0x3a0eeb22: (None, 'update_chat_participant_add_v_0_1_317'),  # 974056226
        0xb6901959: (None, 'update_chat_participant_admin', None),  # -1232070311
        0x6e5f8c22: (None, 'update_chat_participant_delete', None),  # 1851755554
        0x07761198: (None, 'update_chat_participants', None),  # 125178264
        0xe10db349: (None, 'update_chat_pinned_message', None),  # -519195831
        0x9a65ea1f: (None, 'update_chat_user_typing', None),  # -1704596961
        0x3c46cfe6: (None, 'update_chat_user_typing_v_0_1_317'),  # 1011273702
        0xa229dd06: (None, 'update_config', None),  # -1574314746
        0x9d2e67c5: (None, 'update_contact_link', None),  # -1657903163
        0x51a48a9a: (None, 'update_contact_link_v_0_1_317'),  # 1369737882
        0x2575bbb9: (None, 'update_contact_registered_v_0_1_317'),  # 628472761
        0x7084a7be: (None, 'update_contacts_reset', None),  # 1887741886
        0x8e5e9873: (None, 'update_dc_options', None),  # -1906403213
        0xc37521c9: (None, 'update_delete_channel_messages', None),  # -1015733815
        0xa20db0e5: (None, 'update_delete_messages', None),  # -1576161051
        0xa92bfe26: (None, 'update_delete_messages_v_0_1_317'),  # -1456734682
        0x90866cee: (None, 'update_delete_scheduled_messages', None), # -1870238482
        0x26ffde7d: (None, 'update_dialog_filter', None), # 654302845
        0xa5d72105: (None, 'update_dialog_filter_order', None), # -1512627963
        0x3504914f: (None, 'update_dialog_filters', None), # 889491791
        0x6e6fe51c: (None, 'update_dialog_pinned', None),  # 1852826908
        0x19d27f3c: (None, 'update_dialog_pinned_v_5_5_0', None),  # 433225532
        0xe16459c3: (None, 'update_dialog_unread_mark', None),  # -513517117
        0xee2bb969: (None, 'update_draft_message', None),  # -299124375
        0x1b3f4df7: (None, 'update_edit_channel_message', None),  # 457133559
        0xe40370a3: (None, 'update_edit_message', None),  # -469536605
        0x1710f156: (None, 'update_encrypted_chat_typing', None),  # 386986326
        0x38fe25b7: (None, 'update_encrypted_messages_read', None),  # 956179895
        0xb4a2e88d: (None, 'update_encryption', None),  # -1264392051
        0xe511996d: (None, 'update_faved_stickers', None),  # -451831443
        0x19360dc0: (None, 'update_folder_peers', None),  # 422972864
        0x871fb939: (None, 'update_geo_live_viewed', None), # -2027964103
        0x85fe86ed: (None, 'update_group_call', None),  # -2046916883
        0x057eaec8: (None, 'update_group_call_participant', None),  # 92188360
        0x56022f4d: (None, 'update_lang_pack', None),  # 1442983757
        0x46560264: (None, 'update_lang_pack_too_long', None),  # 1180041828
        0x564fe691: (None, 'update_login_token', None), # 1448076945
        0x4e90bfd6: (None, 'update_message_i_d', None),  # 1318109142
        0xaca1657b: (None, 'update_message_poll', None),  # -1398708869
        0x154798c3: (None, 'update_message_reactions', None), # 357013699
        0x8f06529a: (None, 'update_new_authorization_v_0_1_317'),  # -1895411046
        0x62ba04d9: (None, 'update_new_channel_message', None),  # 1656358105
        0x12bcbd9a: (None, 'update_new_encrypted_message', None),  # 314359194
        0x5a68e3f7: (None, 'update_new_geo_chat_message_v_0_1_317'),  # 1516823543
        0x1f2b0afd: (None, 'update_new_message', None),  # 522914557
        0x013abdb3: (None, 'update_new_message_v_0_1_317'),  # 20626867
        0x39a51dfb: (None, 'update_new_scheduled_message', None), # 967122427
        0x688a30aa: (None, 'update_new_sticker_set', None),  # 1753886890
        0xbec268ef: (None, 'update_notify_settings', None),  # -1094555409
        0xb4afcfb0: (None, 'update_peer_located', None), # -1263546448
        0x6a7e7366: (None, 'update_peer_settings', None), # 1786671974
        0xab0f6b1e: (None, 'update_phone_call', None),  # -1425052898
        0x2661bf09: (None, 'update_phone_call_signaling_data', None), # 643940105
        0xfa0f3ca2: (None, 'update_pinned_dialogs', None),  # -99664734
        0xea4cb65b: (None, 'update_pinned_dialogs_v_5_5_0', None),  # -364071333
        0xee3b272a: (None, 'update_privacy', None),  # -298113238
        0x330b5424: (None, 'update_read_channel_inbox', None),  # 856380452
        0x4214f37f: (None, 'update_read_channel_inbox_v_5_5_0', None),  # 1108669311
        0x25d6c9c7: (None, 'update_read_channel_outbox', None),  # 634833351
        0x571d2742: (None, 'update_read_featured_stickers', None),  # 1461528386
        0x9c974fdf: (None, 'update_read_history_inbox', None),  # -1667805217
        0x9961fd5c: (None, 'update_read_history_inbox_v_5_5_0', None),  # -1721631396
        0x2f2f21bf: (None, 'update_read_history_outbox', None),  # 791617983
        0x68c13933: (None, 'update_read_messages_contents', None),  # 1757493555
        0xc6649e31: (None, 'update_read_messages_v_0_1_317'),  # -966484431
        0x9a422c20: (None, 'update_recent_stickers', None),  # -1706939360
        0xd15de04d: (None, 'update_restore_messages_v_0_1_317'),  # -782376883
        0x9375341e: (None, 'update_saved_gifs', None),  # -1821035490
        0xebe46819: (None, 'update_service_notification', None),  # -337352679
        0x78d4dec1: (None, 'update_short', None),  # 2027216577
        0x16812688: (None, 'update_short_chat_message', None),  # 377562760
        0x2b2fbd4e: (None, 'update_short_chat_message_v_0_1_317'),  # 724548942
        0x914fbf11: (None, 'update_short_message', None),  # -1857044719
        0xd3f45784: (None, 'update_short_message_v_0_1_317'),  # -738961532
        0x11f1331c: (None, 'update_short_sent_message', None),  # 301019932
        0x43ae3dec: (None, 'update_sticker_sets', None),  # 1135492588
        0x0bb2d201: (None, 'update_sticker_sets_order', None),  # 196268545
        0x8216fba3: (None, 'update_theme', None), # -2112423005
        0x80ece81a: (None, 'update_user_blocked', None),  # -2131957734
        0xa7332b73: (None, 'update_user_name', None),  # -1489818765
        0xda22d9ad: (None, 'update_user_name_v_0_1_317'),  # -635250259
        0x12b9417b: (None, 'update_user_phone', None),  # 314130811
        0x95313b0c: (None, 'update_user_photo', None),  # -1791935732
        0x4c43da18: (None, 'update_user_pinned_message', None),  # 1279515160
        0x1bfbd823: (None, 'update_user_status', None),  # 469489699
        0x5c486927: (None, 'update_user_typing', None),  # 1548249383
        0x6baa8508: (None, 'update_user_typing_v_0_1_317'),  # 1806337288
        0x7f891213: (None, 'update_web_page', None),  # 2139689491
        0x74ae4240: (None, 'updates', None),  # 1957577280
        0x725b04c3: (None, 'updates_combined', None),  # 1918567619
        0xe317af7e: (None, 'updates_too_long', None),  # -484987010
        0x2064674e: (None, 'updates_channel_difference', None),  # 543450958
        0x3e11affb: (None, 'updates_channel_difference_empty', None),  # 1041346555
        0xa4bcc6fe: (None, 'updates_channel_difference_too_long', None),  # -1531132162
        0x6a9d7b35: (None, 'updates_channel_difference_too_long_v_5_5_0', None),  # 1788705589
        0x00f49ca0: (None, 'updates_difference', None),  # 16030880
        0x5d75a138: (None, 'updates_difference_empty', None),  # 1567990072
        0xa8fb1981: (None, 'updates_difference_slice', None),  # -1459938943
        0x4afe8f6d: (None, 'updates_difference_too_long', None),  # 1258196845
        0x03173d78: (None, 'updates_get_channel_difference', None),  # 51854712
        0x25939651: (None, 'updates_get_difference', None),  # 630429265
        0x0a041495: (None, 'updates_get_difference_v_0_1_317'),  # 168039573
        0xedd4882a: (None, 'updates_get_state', None),  # -304838614
        0xa56c2a3e: (None, 'updates_state', None),  # -1519637954
        0xa99fca4f: (None, 'upload_cdn_file', None),  # -1449145777
        0xeea8e46e: (None, 'upload_cdn_file_reupload_needed', None),  # -290921362
        0x096a18d5: (None, 'upload_file', None),  # 157948117
        0xf18cda44: (None, 'upload_file_cdn_redirect', None),  # -242427324
        0x2000bcc3: (None, 'upload_get_cdn_file', None),  # 536919235
        0x4da54231: (None, 'upload_get_cdn_file_hashes', None),  # 1302676017
        0xb15a9afc: (None, 'upload_get_file', None), # -1319462148
        0xe3a6cfb5: (None, 'upload_get_file_v_5_6_2', None),  # -475607115
        0xc7025931: (None, 'upload_get_file_hashes', None),  # -956147407
        0x24e6818d: (None, 'upload_get_web_file', None),  # 619086221
        0x9b2754a8: (None, 'upload_reupload_cdn_file', None),  # -1691921240
        0xde7b673d: (None, 'upload_save_big_file_part', None),  # -562337987
        0xb304a621: (None, 'upload_save_file_part', None),  # -1291540959
        0x21e753bc: (None, 'upload_web_file', None),  # 568808380
        0x8f8c0e4e: (None, 'url_auth_result_accepted', None), # -1886646706
        0xa9d6db1f: (None, 'url_auth_result_default', None), # -1445536993
        0x92d33a0e: (None, 'url_auth_result_request', None), # -1831650802
        0x938458c1: (user_struct, 'user', None), # -1820043071
        0xf2fb8319: (user_contact_old_struct, 'user_contact_old', None),  # -218397927
        0xcab35e18: (user_contact_old2_struct, 'user_contact_old2', None),  # -894214632
        0xb29ad7cc: (user_deleted_old_struct, 'user_deleted_old', None),  # -1298475060
        0xd6016d7a: (user_deleted_old2_struct, 'user_deleted_old2', None),  # -704549510
        0x200250ba: (user_empty_struct, 'user_empty', None),  # 537022650
        0x5214c89d: (user_foreign_old_struct, 'user_foreign_old', None),  # 1377093789
        0x075cf7a8: (user_foreign_old2_struct, 'user_foreign_old2', None),  # 123533224
        0xedf17c12: (user_full_struct, 'user_full', None), # -302941166
        0x745559cc: (user_full_layer101_struct, 'user_full_layer101', None),  # 1951750604
        0x8ea4a881: (user_full_layer98_struct, 'user_full_layer98', None),  # -1901811583
        0x771095da: (None, 'user_full_v_0_1_317'),  # 1997575642
        0x2e13f4c3: (user_layer104_struct, 'user_layer104', None),  # 773059779
        0xd10d979a: (user_layer65_struct, 'user_layer65', None),  # -787638374
        0x69d3ab26: (user_profile_photo_struct, 'user_profile_photo', None), # 1775479590
        0x4f11bae1: (user_profile_photo_empty_struct, 'user_profile_photo_empty', None),  # 1326562017
        0xd559d8c8: (user_profile_photo_layer97_struct, 'user_profile_photo_layer97', None),  # -715532088
        0xecd75d8c: (user_profile_photo_layer115_struct, 'user_profile_photo_layer115', None),  # -321430132
        0x990d1493: (user_profile_photo_old_struct, 'user_profile_photo_old', None),  # -1727196013
        0x22e8ceb0: (user_request_old_struct, 'user_request_old', None),  # 585682608
        0xd9ccc4ef: (user_request_old2_struct, 'user_request_old2', None),  # -640891665
        0x720535ec: (user_self_old_struct, 'user_self_old', None),  # 1912944108
        0x7007b451: (user_self_old2_struct, 'user_self_old2', None),  # 1879553105
        0x1c60e608: (user_self_old3_struct, 'user_self_old3', None),  # 476112392
        0x09d05049: (user_status_empty_struct, 'user_status_empty', None),  # 164646985
        0x77ebc742: (user_status_last_month_struct, 'user_status_last_month', None),  # 2011940674
        0x07bf09fc: (user_status_last_week_struct, 'user_status_last_week', None),  # 129960444
        0x008c703f: (user_status_offline_struct, 'user_status_offline', None),  # 9203775
        0xedb93949: (user_status_online_struct, 'user_status_online', None),  # -306628279
        0xe26f42f1: (user_status_recently_struct, 'user_status_recently', None),  # -496024847
        0x22e49072: (user_old_struct, 'user_old', None),  # 585404530
        0xca30a5b1: (None, 'users_get_full_user', None),  # -902781519
        0x0d91a548: (None, 'users_get_users', None),  # 227648840
        0xc10658a8: (video_empty_layer45_struct, 'video_empty_layer45', None),  # -1056548696
        0x55555553: (video_encrypted_struct, 'video_encrypted', None),  # 1431655763
        0xf72887d3: (video_layer45_struct, 'video_layer45', None),  # -148338733
        0x5a04a49f: (video_old_struct, 'video_old', None),  # 1510253727
        0x388fa391: (video_old2_struct, 'video_old2', None),  # 948937617
        0xee9f4a4d: (video_old3_struct, 'video_old3', None),  # -291550643
        0xe831c556: (video_size_struct, 'video_size', None), # -399391402
        0x435bb987: (video_size_layer115_struct, 'video_size_layer115', None), # 1130084743
        0xa437c3ed: (wall_paper_struct, 'wall_paper', None),  # -1539849235
        0xf04f91ec: (wall_paper_layer94_struct, 'wall_paper_layer94', None),  # -263220756
        0x8af40b25: (wall_paper_no_file_struct, 'wall_paper_no_file', None), # -1963717851
        0x05086cf8: (wall_paper_settings_struct, 'wall_paper_settings', None), # 84438264
        0xa12f40b8: (wall_paper_settings_layer106_struct, 'wall_paper_settings_layer106', None), # -1590738760
        0x63117f24: (None, 'wall_paper_solid_v_0_1_317'),  # 1662091044
        0xccb03657: (None, 'wall_paper_v_0_1_317'),  # -860866985
        0x0b57f346: (None, 'wallet_get_key_secret_salt', None), # 190313286
        0x764386d7: (None, 'wallet_lite_response', None), # 1984136919
        0xdd484d64: (None, 'wallet_secret_salt', None), # -582464156
        0xe2c9d33e: (None, 'wallet_send_lite_request', None), # -490089666
        0xcac943f2: (None, 'web_authorization', None),  # -892779534
        0x1c570ed1: (web_document_struct, 'web_document', None),  # 475467473
        0xf9c8bcc6: (web_document_no_proxy_struct, 'web_document_no_proxy', None),  # -104284986
        0xc61acbd8: (web_document_layer81_struct, 'web_document_layer81', None),  # -971322408
        0xe89c45b2: (web_page_struct, 'web_page', None), # -392411726
        0x54b56617: (web_page_attribute_theme_struct, 'web_page_attribute_theme', None), # 1421174295
        0xeb1477e8: (web_page_empty_struct, 'web_page_empty', None),  # -350980120
        0x5f07b4bc: (web_page_layer104_struct, 'web_page_layer104', None),  # 1594340540
        0xfa64e172: (web_page_layer107_struct, 'web_page_layer107', None), # -94051982
        0xca820ed7: (web_page_layer58_struct, 'web_page_layer58', None),  # -897446185
        0x7311ca11: (web_page_not_modified_struct, 'web_page_not_modified', None), # 1930545681
        0x85849473: (web_page_not_modified_layer110_struct, 'web_page_not_modified_layer110', None),  # -2054908813
        0xc586da1c: (web_page_pending_struct, 'web_page_pending', None),  # -981018084
        0xd41a5167: (web_page_url_pending_struct, 'web_page_url_pending', None),  # -736472729
        0xa31ea0b5: (web_page_old_struct, 'web_page_old', None),  # -1558273867
        0x1cb5c415: (None, '_vector', None),  # 481674261
    }

# -----------------------------------------------------------------------------
