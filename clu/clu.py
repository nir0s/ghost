"""
import clu

CREDS = {'secret': '...', 'key': '...'}

clu.init(path='~/.clu/stash', phrase='P!3pimp5i31')
# if already initialized, fail
stash = clu.load(path='~/.clu/stash', phrase='P!3pimp5i31')
# if doesn't exist, fail
stash.put(key='aws', value=json.dumps(CREDS))
# if key exists, fail
creds = stash.get(key='aws')
# if key doesn't exist, fail
"""

import os
import uuid
import random
import string
import binascii

from tinydb import TinyDB, Query
from simplecrypt import encrypt, decrypt


def delete(path):
    path = os.path.expanduser(path)
    if os.path.basename(path) == 'stash.json':
        if os.path.isfile(path):
            os.remove(path)
    else:
        raise RuntimeError('Is not a stash file')


def init(path='~/.clu/stash.json', phrase=None, phrase_size=12):

    phrase = phrase or generate_passphrase(size=phrase_size)
    if not isinstance(phrase, bytes) or not phrase:
        raise RuntimeError('phrase must be a non-empty string')
    expanded_path = os.path.expanduser(path)
    if not os.path.isdir(expanded_path):
        os.makedirs(os.path.dirname(expanded_path))
    else:
        # TODO: allow to reset/delete a stash
        raise RuntimeError('Stash already initialized')

    stash = _TinyStash(expanded_path, phrase)
    stash.put(key='stored_phrase', value=phrase)
    return phrase


def load(phrase, path='~/.clu/stash.json'):
    expanded_path = os.path.expanduser(path)
    if not os.path.isfile(expanded_path):
        raise RuntimeError(
            'Stash does not exist. Please initialize a stash first.')
    stash = _TinyStash(expanded_path, phrase)
    stash.get('stored_phrase')
    return stash


class _TinyStash(object):
    def __init__(self, db_path, phrase=None):
        self.db_path = db_path
        self.db = TinyDB(
            self.db_path,
            indent=4,
            sort_keys=True,
            separators=(',', ': '))
        self.phrase = phrase

    def put(self, key, value):
        value = binascii.hexlify(encrypt(self.phrase, value.encode('utf8')))
        # TODO: Don't allow duplicates by name
        # TODO: Maybe we don't need the uuid
        record = dict(
            name=key,
            value=value,
            identifier=str(uuid.uuid4()))
        self.db.insert(record)

    def get(self, key):
        query = Query()
        result = self.db.search(query.name == key)
        # If multiple records found, will only return the first one.
        # Once we disallow duplicates, this will be good.
        value = binascii.unhexlify(result[0]['value'])
        return decrypt(self.phrase, value)

    def update(self, key, new_value):
        query = Query()
        self.db.update(new_value, query.name == key)


def generate_passphrase(size=12):
    chars = string.lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(size))
