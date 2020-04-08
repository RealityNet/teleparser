# teleparser
Telegram cache4.db parser.

*This script is introduced by the blog post at https://blog.digital-forensics.it/2020/04/teleparser.html*

`teleparser` is a Python3 script aimed to parse the **Telegram cache4.db database**. It's not for the _faint hearted_ and the expected user is a DFIR expert. As written in the blog post, the goal is not to miss the data and not to misinterpret it: the script should crash if what is parsing is not what is expected... if not, that's **A** bug.

It's assumed a bit of knowledge on how the cache4.db is organized and the specificity of its *blobs*.

### Current Telegram versions supported

* **<**: could work
* **5.5.0**: tested, expected to work
* **><**: could work
* **5.6.2**: tested, expected to work
* **>**: expected to fail

## Usage

```
usage: teleparser.py [-h] [-v] infilename outdirectory

Telegram parser version 20200406

positional arguments:
  infilename     input file cache4.db
  outdirectory   output directory, must exist

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  verbose level, -v to -vvv
```

### Example

```
meeh:~$ python3 teleparser.py ~/telegrammo/db/cache4.db ~/Documents/telegram_562/
```

It will create in the output folder (`~/Documents/telegram_562/`) the following files:

* `timeline.csv`: a comma separeted textual file with a **timeline** of messages/events
* `table_messages.txt`: table **messages** entries with blobs, human readable
* `table_user_settings.txt`: table **user_settings** entries with blobs, human readable
* `table_contacts.txt`: table **contacts** entries with blobs, human readable
* `table_users.txt`: table **users** entries with blobs, human readable
* `table_enc_chats.txt`: table **enc_chats** entries with blobs, human readable
* `table_dialogs.txt`: table **dialogs** entries with blobs, human readable
* `table_media_v2.txt`: table **media_v2** entries with blobs, human readable
* `table_chats.txt`: table **chats** entries with blobs, human readable
* `table_sent_files_v2.txt`: table **sent_files_v2** entries with blobs, human readable

### In case of _crash_

Please open a bug here and fill the bug template. Most likely the raw data will be needed: in case please be ready to provide a **testing cache4.db** that can be _privately_ shared. Most likely the script will crash due to new (from the script point of view, a.k.a. unmanaged) _blobs_.

