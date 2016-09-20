# Copyright 2015,2016 Nir Cohen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TODO: Add categories
# TODO: Output phrase to file during `init`
# TODO: Output key to file during `get`


import os
import sys
import json
import time
import uuid
import base64
import random
import string
import logging
import binascii
import warnings
from datetime import datetime

import click
from tinydb import TinyDB, Query
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
try:
    from sqlalchemy import (Column,
                            Table,
                            MetaData,
                            String,
                            PickleType,
                            create_engine,
                            sql)
    SQLALCHEMY_EXISTS = True
except ImportError:
    SQLALCHEMY_EXISTS = False


GHOST_HOME = os.path.expanduser(os.path.join('~', '.ghost'))
DEFAULT_STASH_PATH = os.path.join(GHOST_HOME, 'stash.json')
DEFAULT_SQLITE_STASH_PATH = 'sqlite:///{0}/stash.sql'.format(GHOST_HOME)


def setup_logger():
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger = logging.getLogger('ghost')
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


logger = setup_logger()


class Stash(object):
    def __init__(self, storage, passphrase=None, passphrase_size=12):
        self._storage = storage
        self.passphrase = passphrase or generate_passphrase(passphrase_size)

    # TODO: Consider base64 encoding instead of hexlification
    _key = None

    @property
    def key(self):
        if self._key is None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt='ghost',
                iterations=1000000,
                backend=default_backend())
            self._key = base64.urlsafe_b64encode(kdf.derive(self.passphrase))
        return self._key

    @property
    def cipher(self):
        return Fernet(self.key)

    def _encrypt(self, value):
        """Turn a json serializable value into an jsonified, encrypted,
        hexa string.
        """
        value = json.dumps(value)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            encrypted_value = self.cipher.encrypt(value.encode('utf8'))
        hexified_value = binascii.hexlify(encrypted_value)
        return hexified_value

    def _decrypt(self, hexified_value):
        """The exact opposite of _encrypt
        """
        encrypted_value = binascii.unhexlify(hexified_value)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            jsonified_value = self.cipher.decrypt(encrypted_value)
        value = json.loads(jsonified_value)
        return value

    def _handle_existing_key(self, key_name, modify):
        existing_key = self._storage.get(key_name) or {}
        if existing_key and modify:
            self._storage.delete(key_name)
        elif existing_key:
            raise GhostError(
                'The key already exists. Use the modify flag to overwrite')
        elif modify:
            raise GhostError(
                "The key doesn't exist and therefore cannot be modified")
        return existing_key

    def init(self):
        if not isinstance(self.passphrase, basestring) or not self.passphrase:
            raise GhostError('passphrase must be a non-empty string')

        self._storage.init()
        self.put(
            name='stored_passphrase',
            value={'passphrase': self.passphrase})
        return self.passphrase

    def put(self,
            name,
            value=None,
            modify=False,
            metadata=None,
            description=''):
        """Put a key inside the stash

        if key exists and modify true: delete and create
        if key exists and modify false: fail
        if key doesn't exist and modify true: fail
        if key doesn't exist and modify false: create

        `name` is unique and cannot be changed.

        `value` must be provided if the key didn't already exist, otherwise,
        the previous value will be retained.

        `created_at` will be left unmodified if the key
        already existed. Otherwise, the current time will be used.

        `modified_at` will be changed to the current time
        if the field is being modified.

        `metadata` will be updated if provided. If it wasn't
        provided the field from the existing key will be used and the
        same goes for the `uid` which will be generated if it didn't
        previously exist.

        Returns the id of the key in the database
        """
        if value and not isinstance(value, dict):
            raise GhostError('Value must be of type dict')
        # `existing_key` will be an empty dict if it doesn't exist
        existing_key = self._handle_existing_key(name, modify)

        if not value and not existing_key.get('value'):
            raise GhostError('You must provide a value for new keys')
        # TODO: Treat a case in which we try to update an existing key
        # but don't provide a value in which nothing will happen.
        created_at = existing_key.get('created_at') or _get_current_time()
        uid = existing_key.get('uid') or str(uuid.uuid4())

        modified_at = _get_current_time()

        value = self._encrypt(value) or existing_key.get('value')
        description = description or existing_key.get('description')
        metadata = metadata or existing_key.get('metadata')

        return self._storage.put(dict(
            name=name,
            value=value,
            description=description,
            created_at=created_at,
            modified_at=modified_at,
            metadata=metadata,
            uid=uid))

    def get(self, key_name, decrypt=True, field=None):
        """Return a key with its parameters if it was found.
        """
        key = self._storage.get(key_name)
        if not key.get('value'):
            return None
        if decrypt:
            key['value'] = self._decrypt(key['value'])
        return key if not field else key.get()

    def delete(self, key_name):
        """Delete a key if it exists.
        """
        deleted = self._storage.delete(key_name)
        if not deleted:
            raise GhostError('Key {0} not found'.format(key_name))

    def list(self):
        """Return a list of all keys.
        """
        return [key['name'] for key in self._storage.list()
                if key['name'] != 'stored_passphrase']

    def load(self, keys=None, key_file=None):
        """Imports keys to the stash from either a list of keys or a file

        `keys` is a list of dictionaries created by `self.export`
        `stash_path` is a path to a file created by `self.export`
        """
        if not keys and not key_file or (keys and key_file):
            raise GhostError(
                'You must either provide a path to an exported stash file '
                'or a list of key dicts to import')
        if key_file:
            with open(key_file) as stash_file:
                keys = json.loads(stash_file.read())

        for key in keys:
            return self._storage.put(key)

    def export(self, output_path=None):
        """Exports all keys in the stash to a list or a file
        """
        all_key_names = self.list()
        all_keys = []
        for key in all_key_names:
            # We `dict` this as a precaution as tinydb returns
            # a tinydb.database.Element instead of a dictionary
            # and well.. I ain't taking no chances
            all_keys.append(dict(self.get(key, decrypt=False)))
        if all_keys:
            if output_path:
                with open(output_path, 'w') as output_file:
                    output_file.write(json.dumps(all_keys, indent=4))
            return all_keys
        else:
            raise GhostError('There are no keys to export')

    def purge(self, force=False):
        """Purges the stash from all keys
        """
        if not force:
            raise GhostError(
                "The `force` flag must be provided to perform a stash purge. "
                "I mean, you don't really want to just delete everything "
                "without precautionary measures eh?")
        for key_name in self.list():
            self.delete(key_name)


class TinyDBStorage(object):
    def __init__(self, db_path=DEFAULT_STASH_PATH):
        self.db_path = os.path.expanduser(db_path)
        self._db = None

    @property
    def db(self):
        if self._db is None:
            self._db = TinyDB(
                self.db_path,
                indent=4,
                sort_keys=True,
                separators=(',', ': '))
        return self._db

    def init(self):
        if not os.path.isdir(os.path.dirname(self.db_path)):
            os.makedirs(os.path.dirname(self.db_path))
        elif os.path.isfile(self.db_path):
            raise GhostError('Stash {0} already initialized'.format(
                self.db_path))

    def put(self, key_name):
        """
        `key` is the dictionary representing the key
        """
        return self.db.insert(key_name)

    def list(self):
        return self.db.search(Query().name.matches('.*'))

    def get(self, key_name):
        result = self.db.search(Query().name == key_name)
        if not result:
            return {}
        return result[0]

    def delete(self, key_name):
        return self.db.remove(Query().name == key_name)


class SQLAlchemyStorage(object):
    def __init__(self, db_path=DEFAULT_SQLITE_STASH_PATH):
        if not SQLALCHEMY_EXISTS:
            raise ImportError('SQLAlchemy must be installed first')
        self.db_path = db_path
        self.metadata = MetaData()

        self.keys = Table(
            'keys',
            self.metadata,
            Column('name', String, primary_key=True),
            Column('value', PickleType),
            Column('description', String),
            Column('metadata', PickleType),
            Column('modified_at', String),
            Column('created_at', String))

        self._db = None

    @property
    def db(self):
        if self._db is None:
            self._db = create_engine(self.db_path)
        return self._db

    def init(self):
        if 'sqlite://' in self.db_path:
            path = os.path.expanduser(self.db_path).split('://')[1]
            if not os.path.isdir(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            elif os.path.isfile(path):
                raise GhostError('Stash {0} already initialized'.format(
                    path))
        # More on connection strings for sqlalchemy:
        # http://docs.sqlalchemy.org/en/latest/core/engines.html
        self.metadata.bind = self.db
        self.metadata.create_all()

    def put(self, key):
        """
        `key` is the dictionary representing the key
        """
        return self.db.execute(self.keys.insert(), **key).lastrowid

    def list(self):
        return self.db.execute(sql.select([self.keys]))

    def get(self, key_name):
        results = self.db.execute(sql.select(
            [self.keys], self.keys.c.name == key_name))

        # Supposed to be only one key_values. There's a hidden assumption
        # (is the mother of all fuckups) that you can't insert more
        # than one record with the same `name` since it is verified
        # in `put`.
        key_values = None
        for result in results:
            key_values = result
        if not key_values:
            return {}
        key = {}
        for column, value in zip(self.keys.columns, key_values):
            key.update({column.name: value})
        return key

    def delete(self, key_name):
        result = self.db.execute(
            self.keys.delete().where(self.keys.c.name == key_name))
        return result.rowcount > 0


def _get_current_time():
    """Returns a human readable unix timestamp formatted string

    e.g. 2015-06-11 10:10:01
    """
    return datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')


def generate_passphrase(size=12):
    chars = string.lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(size))


class GhostError(Exception):
    pass


def _build_dict_from_key_value(keys_and_values):
    """Return a dict from a list of key=value pairs
    """
    key_dict = {}
    for key_value in keys_and_values:
        if '=' not in key_value:
            raise GhostError('Pair {0} is not of `key=value` format'.format(
                key_value))
        key, value = key_value.split('=', 1)
        key_dict.update({str(key): str(value)})
    return key_dict


def _prettify_dict(record):
    """Return a human readable format of a record (dict).

    Example:

    Description:   My Wonderful Key
    Uid:           a54d6de1-922a-4998-ad34-cb838646daaa
    Created_At:    2016-09-15T12:42:32
    Metadata:      owner=me;
    Modified_At:   2016-09-15T12:42:32
    Value:         secret_key=my_secret_key;access_key=my_access_key
    Name:          aws
    """
    pretty_record = ''
    for key, value in record.items():
        if isinstance(value, dict):
            pretty_value = ''
            for k, v in value.items():
                pretty_value += '{0}={1};'.format(k, v)
            value = pretty_value
        pretty_record += '{0:15}{1}\n'.format(key.title() + ':', value)
    return pretty_record


def _prettify_list(items):
    """Return a human readable format of a list.

    Example:

    Available Keys:
      - my_first_key
      - my_second_key
    """
    keys_list = 'Available Keys:'
    for item in items:
        keys_list += '\n  - {0}'.format(item)
    return keys_list


CLICK_CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help'],
    token_normalize_func=lambda param: param.lower())


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def main():
    """Ghost generates a secret-store in which you can
    keep your secrets encrypted. Ghost isn't real. It's just in your head.
    """
    pass


stash_option = click.option(
    '-s',
    '--stash',
    envvar='GHOST_STASH_PATH',
    required=True,
    help='Path to the stash (Can be set via the `GHOST_STASH_PATH` '
    'env var)')
passphrase_option = click.option(
    '-p',
    '--passphrase',
    envvar='GHOST_PASSPHRASE',
    required=True,
    type=click.UNPROCESSED,
    help='Stash Passphrase (Can be set via the `GHOST_PASSPHRASE` '
    'env var)')


@main.command(name='init', short_help='Init a stash')
@click.argument('STASH_PATH',
                required=False,
                default=DEFAULT_STASH_PATH)
@click.option('-p',
              '--passphrase',
              default=None,
              type=click.UNPROCESSED,
              help='Path to the stash')
@click.option('--passphrase-size',
              default=12)
def init_stash(stash_path, passphrase, passphrase_size):
    """Init a stash

    `STASH_PATH` is the path to the stash. If this isn't supplied,
    a default path will be used.

    After initializing a stash, don't forget you can set environment
    variables for both your stash's path and its passphrase.
    On Linux/OSx you can run:

    export GHOST_STASH_PATH='MY_PATH'

    export GHOST_PASSPHRASE='MY_PASSPHRASE'
    """
    logger.info('Initializing stash...')
    storage = TinyDBStorage(db_path=stash_path)
    stash = Stash(storage, passphrase=passphrase)
    try:
        passphrase = stash.init()
    except GhostError as ex:
        sys.exit(ex)
    logger.info('Initalized stash at: {0}'.format(stash_path))
    logger.info('Your passphrase is: {0}'.format(passphrase))
    logger.info('Make sure you save your passphrase somewhere safe. '
                'If lost, you will lose access to your stash.')


@main.command(name='put', short_help='Insert a key to the stash')
@click.argument('KEY_NAME')
@click.argument('VALUE', nargs=-1)
@click.option('-d',
              '--description',
              help="The key's description")
@click.option('--meta',
              multiple=True,
              help='`key=value` pairs to serve as metadata for the key '
              '(Can be used multiple times)')
@click.option('-m',
              '--modify',
              is_flag=True,
              help='Whether to modify an existing key if it exists')
@stash_option
@passphrase_option
def put_key(key_name,
            value,
            description,
            meta,
            modify,
            stash,
            passphrase):
    """Insert a key to the stash

    `KEY_NAME` is the name of the key to insert

    `VALUE` is a key=value argument which can be provided multiple times.
    it is the encrypted value of your key
    """
    logger.info('Stashing key...')
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.put(
            name=key_name,
            value=_build_dict_from_key_value(value),
            modify=modify,
            metadata=_build_dict_from_key_value(meta),
            description=description)
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='get', short_help='Retrieve a key from the stash')
@click.argument('KEY_NAME')
@click.option('-j',
              '--jsonify',
              is_flag=True,
              default=False,
              help='Output in JSON instead')
@stash_option
@passphrase_option
def get_key(key_name, jsonify, stash, passphrase):
    """Retrieve a key from the stash

    `KEY_NAME` is the name of the key to retrieve
    """
    if not jsonify:
        logger.info('Retrieving key...')
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    record = stash.get(key_name=key_name)
    if not record:
        sys.exit('Key {0} not found'.format(key_name))
    if jsonify:
        logger.info(json.dumps(record, indent=4, sort_keys=False))
    else:
        logger.info('\n' + _prettify_dict(record))


@main.command(name='delete', short_help='Delete a key from the stash')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
def delete_key(key_name, stash, passphrase):
    """Delete a key from the stash

    `KEY_NAME` is the name of the key to delete
    """
    logger.info('Deleting key...')
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.delete(key_name=key_name)
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='list')
@click.option('-j',
              '--jsonify',
              is_flag=True,
              default=False,
              help='Output in JSON instead')
@stash_option
@passphrase_option
def list_keys(jsonify, stash, passphrase):
    """List all keys in the stash
    """
    if not jsonify:
        logger.info('Listing all keys in {0}...'.format(stash))
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    keys = stash.list()
    if not keys:
        logger.info('The stash is empty. Go on, put some keys in there...')
        return
    if jsonify:
        logger.info(json.dumps(keys, indent=4, sort_keys=False))
    else:
        logger.info(_prettify_list(keys))


@main.command(name='purge')
@click.option('-f',
              '--force',
              required=True,
              is_flag=True,
              help='This flag is mandatory to perform a purge')
@stash_option
@passphrase_option
def purge_keys(force, stash, passphrase):
    """Purge the stash from all of its keys
    """
    logger.info('Purging stash {0}...'.format(stash))
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.purge(force)
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='export')
@click.option('-o',
              '--output-path',
              default='ghost-key-file.json',
              help='Save exported keys in a file')
@stash_option
@passphrase_option
def export_keys(output_path, stash, passphrase):
    """Export all keys to a file
    """
    logger.info('Exporting stash {0} to {1}...'.format(stash, output_path))
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.export(output_path=output_path)
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='load')
@click.argument('KEY_FILE')
@stash_option
@passphrase_option
def load_keys(key_file, stash, passphrase):
    """Loads all keys from an exported key file to the stash

    `KEY_FILE` is the exported stash file to load keys from
    """
    logger.info('Import all keys from {0} to {1}...'.format(key_file, stash))
    storage = TinyDBStorage(db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.load(key_file=key_file)
    except GhostError as ex:
        sys.exit(ex)
