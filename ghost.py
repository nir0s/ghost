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
# TODO: Add ghost backend which exports and loads stuff
# TODO: Document how to export a key to a file using bash redirection

import os
import sys
import json
import time
import uuid
import base64
import random
import string
import difflib
import logging
import binascii
import warnings
import tempfile
import subprocess
from datetime import datetime

try:
    from urllib.parse import urljoin, urlparse
except ImportError:
    from urlparse import urljoin, urlparse

import click

from tinydb import TinyDB, Query
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
try:
    from sqlalchemy import (Column,
                            Table,
                            MetaData,
                            String,
                            PickleType,
                            create_engine,
                            sql)
    from sqlalchemy_utils import database_exists, create_database
    SQLALCHEMY_EXISTS = True
except ImportError:
    SQLALCHEMY_EXISTS = False

try:
    import requests
    REQUESTS_EXISTS = True
except ImportError:
    REQUESTS_EXISTS = False

try:
    import hvac
    HVAC_EXISTS = True
except ImportError:
    HVAC_EXISTS = False

try:
    import elasticsearch
    ES_EXISTS = True
except ImportError:
    ES_EXISTS = False


GHOST_HOME = os.path.join(os.path.expanduser('~'), '.ghost')
STORAGE_DEFAULT_PATH_MAPPING = {
    'tinydb': os.path.join(GHOST_HOME, 'stash.json'),
    'sqlalchemy': os.path.join(GHOST_HOME, 'stash.sql'),
    'consul': 'http://127.0.0.1:8500',
    'vault': 'http://127.0.0.1:8200',
    'elasticsearch': 'http://127.0.0.1:9200'
}

AUDIT_LOG_FILE_PATH = os.environ.get(
    'GHOST_AUDIT_LOG', os.path.join(GHOST_HOME, 'audit.log'))

KEY_FIELD_SCHEMA = {
    'ssh': {
        'requires': ['conn'],
        'oneof': [['ssh_key_path', 'ssh_key']],
    },
    'secret': {
        'requires': [],
        'oneof': [[]],
        'optional': [],
        'optionaloneof': [[]]
    }
}

PASSPHRASE_FILENAME = 'passphrase.ghost'

POTENTIAL_PASSPHRASE_LOCATIONS = [
    os.path.abspath(PASSPHRASE_FILENAME),
    os.path.join(GHOST_HOME, PASSPHRASE_FILENAME),
]
if not os.name == 'nt':
    POTENTIAL_PASSPHRASE_LOCATIONS.append(
        os.path.join(os.sep, 'etc', 'ghost', PASSPHRASE_FILENAME))


# audit logger
def get_logger():
    handler = logging.FileHandler(AUDIT_LOG_FILE_PATH)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)
    logger = logging.getLogger(__file__)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def audit(storage, action, message):
    logger = get_logger()
    logger.info('[%s] [%s] - %s', storage, action, message)


def get_passphrase(passphrase=None):
    """Return a passphrase as found in a passphrase.ghost file

    Lookup is done in three locations on non-Windows systems and two on Windows
    All:
        `cwd/passphrase.ghost`
        `~/.ghost/passphrase.ghost`
    Only non-Windows:
        `/etc/ghost/passphrase.ghost`
    """
    for passphrase_file_path in POTENTIAL_PASSPHRASE_LOCATIONS:
        if os.path.isfile(passphrase_file_path):
            with open(passphrase_file_path) as passphrase_file:
                return passphrase_file.read()
    return passphrase


class Stash(object):
    def __init__(self,
                 storage,
                 passphrase=None,
                 passphrase_size=12,
                 iterations=1000000):
        self._storage = storage
        passphrase = passphrase or generate_passphrase(passphrase_size)
        self.passphrase = passphrase
        self._iterations = iterations

    # TODO: Consider base64 encoding instead of hexlification
    _key = None

    def init(self):
        # For the audit log
        if not os.path.isdir(GHOST_HOME):
            os.makedirs(GHOST_HOME)

        if self.is_initialized:
            return

        self._storage.init()
        self.put(
            name='stored_passphrase',
            value={'passphrase': self.passphrase},
            lock=True)
        return self.passphrase

    @property
    def is_initialized(self):
        if self._storage.is_initialized:
            self.passphrase = get_passphrase(self.passphrase)
            if self.get('stored_passphrase'):
                return True
        return False

    def _validate_key_schema(self, value, key_type):
        # TODO: Replace with normal, jsonschema style validation
        # 'ssh': {
        #     'requires': ['conn'],
        #     'oneof': [['ssh_key_path', 'ssh_key']]
        # }
        schema = KEY_FIELD_SCHEMA[key_type]

        def validate_single(list_of_keys, value):
            for key in list_of_keys:
                if key not in value.keys():
                    raise GhostError(
                        'Must provide value `{0}` for key of type {1}'
                        .format(key, key_type))

        def validate_oneof(key_sets, value):
            for key_set in key_sets:
                if key_set:
                    keys_exist = [k in value.keys() for k in key_set]
                    if not (any(keys_exist) and not all(keys_exist)):
                        raise GhostError(
                            'Must provide one of {0} for key of type {1}'
                            .format(key_set, key_type))

        validate_single(schema['requires'], value)
        validate_oneof(schema['oneof'], value)
        # validate_single(schema['optional'], value)
        # validate_oneof(schema['optionaloneof'], value)

    def put(self,
            name,
            value=None,
            modify=False,
            metadata=None,
            description='',
            encrypt=True,
            lock=False,
            key_type='secret',
            add=False):
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

        `lock` will lock the key to prevent it from being modified or deleted

        `add` allows to add values to an existing key instead of overwriting.

        Returns the id of the key in the database
        """
        def assert_key_is_unlocked(existing_key):
            if existing_key and existing_key.get('lock'):
                raise GhostError(
                    'Key `{0}` is locked and therefore cannot be modified. '
                    'Unlock the key and try again'.format(name))

        def assert_value_provided_for_new_key(value, existing_key):
            if not value and not existing_key.get('value'):
                raise GhostError('You must provide a value for new keys')

        self._assert_valid_stash()
        self._validate_key_schema(value, key_type)
        if value and encrypt and not isinstance(value, dict):
            raise GhostError('Value must be of type dict')

        # TODO: This should be refactored. `_handle_existing_key` deletes
        # the key rather implicitly. It shouldn't do that.
        # `existing_key` will be an empty dict if it doesn't exist
        key = self._handle_existing_key(name, modify or add)
        assert_key_is_unlocked(key)
        assert_value_provided_for_new_key(value, key)

        new_key = dict(name=name, lock=lock)
        if value:
            # TODO: fix edge case in which encrypt is false and yet we might
            # try to add to an existing key. encrypt=false is only used when
            # `load`ing into a new stash, but someone might use it directly
            # from the API.
            if add:
                value = self._update_existing_key(key, value)
            new_key['value'] = self._encrypt(value) if encrypt else value
        else:
            new_key['value'] = key.get('value')

        # TODO: Treat a case in which we try to update an existing key
        # but don't provide a value in which nothing will happen.
        new_key['description'] = description or key.get('description')
        new_key['created_at'] = key.get('created_at') or _get_current_time()
        new_key['modified_at'] = _get_current_time()
        new_key['metadata'] = metadata or key.get('metadata')
        new_key['uid'] = key.get('uid') or str(uuid.uuid4())
        new_key['type'] = key.get('type') or key_type

        key_id = self._storage.put(new_key)

        audit(
            storage=self._storage.db_path,
            action='MODIFY' if (modify or add) else 'PUT',
            message=json.dumps(dict(
                key_name=new_key['name'],
                value='HIDDEN',
                description=new_key['description'],
                uid=new_key['uid'],
                metadata=json.dumps(new_key['metadata']),
                lock=new_key['lock'],
                type=new_key['type'])))

        return key_id

    def _update_existing_key(self, existing_key, value):
        current_value = self._decrypt(existing_key.get('value')).copy()
        # We update current_value with value to overwrite
        # existing values if the user provided overriding values
        current_value.update(value)
        return current_value

    def _handle_existing_key(self, key_name, modify):
        existing_key = self._storage.get(key_name) or {}
        if existing_key and modify:
            # TODO: Consider replacing this with self.delete(key_name)
            if not existing_key['lock']:
                self._storage.delete(key_name)
        elif existing_key:
            raise GhostError(
                'Key `{0}` already exists. Use the modify flag to overwrite'
                .format(key_name))
        elif modify:
            raise GhostError(
                "Key `{0}` doesn't exist and therefore cannot be modified"
                .format(key_name))
        return existing_key

    def get(self, key_name, decrypt=True):
        """Return a key with its parameters if it was found.
        """
        self._assert_valid_stash()

        key = self._storage.get(key_name).copy()
        if not key.get('value'):
            return None
        if decrypt:
            key['value'] = self._decrypt(key['value'])

        audit(
            storage=self._storage.db_path,
            action='GET',
            message=json.dumps(dict(key_name=key_name)))

        return key

    def list(self,
             key_name=None,
             max_suggestions=100,
             cutoff=0.5,
             locked_only=False,
             key_type=None):
        """Return a list of all keys.
        """
        self._assert_valid_stash()

        key_list = [k for k in self._storage.list()
                    if k['name'] != 'stored_passphrase' and
                    (k.get('lock') if locked_only else True)]

        if key_type:
            # To maintain backward compatibility with keys without a type.
            # The default key type is secret, in which case we also look for
            # keys with no (None) types.
            types = ('secret', None) if key_type == 'secret' else [key_type]
            key_list = [k for k in key_list if k.get('type') in types]

        key_list = [k['name'] for k in key_list]
        if key_name:
            if key_name.startswith('~'):
                key_list = difflib.get_close_matches(
                    key_name.lstrip('~'), key_list, max_suggestions, cutoff)
            else:
                key_list = [k for k in key_list if key_name in k]

        audit(
            storage=self._storage.db_path,
            action='LIST' + ('[LOCKED]' if locked_only else ''),
            message=json.dumps(dict()))

        return key_list

    def delete(self, key_name):
        """Delete a key if it exists.
        """
        self._assert_valid_stash()

        if key_name == 'stored_passphrase':
            raise GhostError(
                '`stored_passphrase` is a reserved ghost key name '
                'which cannot be deleted')

        # TODO: Optimize. We get from the storage twice here for no reason
        if not self.get(key_name):
            raise GhostError('Key `{0}` not found'.format(key_name))
        key = self._storage.get(key_name)
        if key.get('lock'):
            raise GhostError(
                'Key `{0}` is locked and therefore cannot be deleted '
                'Please unlock the key and try again'.format(key_name))

        deleted = self._storage.delete(key_name)

        audit(
            storage=self._storage.db_path,
            action='DELETE',
            message=json.dumps(dict(key_name=key_name)))

        if not deleted:
            raise GhostError('Failed to delete {0}'.format(key_name))

    def _change_lock_state(self, key_name, lock):
        self._assert_valid_stash()

        if not self.get(key_name):
            raise GhostError('Key `{0}` not found'.format(key_name))

        key = self._storage.get(key_name)
        if not key.get('lock') == lock:
            key['lock'] = lock
            self._storage.delete(key_name)
            self._storage.put(key)

        audit(
            storage=self._storage.db_path,
            action='LOCK' if lock else 'UNLOCK',
            message=json.dumps(dict(key_name=key_name)))

    def lock(self, key_name):
        """Lock a key to prevent it from being deleted, purged and modified
        """
        self._change_lock_state(key_name, lock=True)

    def unlock(self, key_name):
        """Unlock a locked key
        """
        self._change_lock_state(key_name, lock=False)

    def is_locked(self, key_name):
        return self._storage.get(key_name).get('lock')

    def purge(self, force=False, key_type=None):
        """Purge the stash from all keys
        """
        self._assert_valid_stash()

        if not force:
            raise GhostError(
                "The `force` flag must be provided to perform a stash purge. "
                "I mean, you don't really want to just delete everything "
                "without precautionary measures eh?")

        audit(
            storage=self._storage.db_path,
            action='PURGE',
            message=json.dumps(dict()))

        for key_name in self.list(key_type=key_type):
            self.delete(key_name)

    def export(self, output_path=None, decrypt=False):
        """Export all keys in the stash to a list or a file
        """
        self._assert_valid_stash()

        all_keys = []
        for key in self.list():
            # We `dict` this as a precaution as tinydb returns
            # a tinydb.database.Element instead of a dictionary
            # and well.. I ain't taking no chances
            all_keys.append(dict(self.get(key, decrypt=decrypt)))
        if all_keys:
            if output_path:
                with open(output_path, 'w') as output_file:
                    output_file.write(json.dumps(all_keys, indent=4))
            return all_keys
        else:
            raise GhostError('There are no keys to export')

    def load(self, origin_passphrase, keys=None, key_file=None):
        """Import keys to the stash from either a list of keys or a file

        `keys` is a list of dictionaries created by `self.export`
        `stash_path` is a path to a file created by `self.export`
        """
        # TODO: Handle keys not dict or key_file not json
        self._assert_valid_stash()

        # Check if both or none are provided (ahh, the mighty xor)
        if not (bool(keys) ^ bool(key_file)):
            raise GhostError(
                'You must either provide a path to an exported stash file '
                'or a list of key dicts to import')
        if key_file:
            with open(key_file) as stash_file:
                keys = json.loads(stash_file.read())

        # If the passphrases are the same, there's no reason to decrypt
        # and re-encrypt. We can simply pass the value.
        decrypt = origin_passphrase != self.passphrase
        if decrypt:
            # TODO: The fact that we need to create a stub stash just to
            # decrypt means we should probably have some encryptor class.
            stub = Stash(TinyDBStorage('stub'), origin_passphrase)
        # TODO: Handle existing keys when loading
        for key in keys:
            self.put(
                name=key['name'],
                value=stub._decrypt(key['value']) if decrypt else key['value'],
                metadata=key['metadata'],
                description=key['description'],
                lock=key.get('lock'),
                key_type=key.get('type'),
                encrypt=decrypt)

    @property
    def key(self):
        passphrase = self.passphrase.encode('utf-8')
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'ghost',
            iterations=self._iterations,
            backend=default_backend())
        self._key = base64.urlsafe_b64encode(kdf.derive(passphrase))
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
        hexified_value = binascii.hexlify(encrypted_value).decode('ascii')
        return hexified_value

    def _decrypt(self, hexified_value):
        """The exact opposite of _encrypt
        """
        encrypted_value = binascii.unhexlify(hexified_value)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            jsonified_value = self.cipher.decrypt(
                encrypted_value).decode('ascii')
        value = json.loads(jsonified_value)
        return value

    def _assert_valid_stash(self):
        if not self._storage.is_initialized:
            raise GhostError(
                'Stash not initialized. Please initialize it and try again')
        else:
            try:
                key = self._storage.get('stored_passphrase')
                if key:
                    self._decrypt(key['value'])
            except InvalidToken:
                raise GhostError(
                    'The passphrase provided is invalid for this stash. '
                    'Please provide the correct passphrase')


def migrate(src_path,
            src_passphrase,
            src_backend,
            dst_path,
            dst_passphrase,
            dst_backend):
    """Migrate all keys in a source stash to a destination stash

    The migration process will decrypt all keys using the source
    stash's passphrase and then encrypt them based on the destination
    stash's passphrase.

    re-encryption will take place only if the passphrases are differing
    """
    src_storage = STORAGE_MAPPING[src_backend](**_parse_path_string(src_path))
    dst_storage = STORAGE_MAPPING[dst_backend](**_parse_path_string(dst_path))
    src_stash = Stash(src_storage, src_passphrase)
    dst_stash = Stash(dst_storage, dst_passphrase)
    # TODO: Test that re-encryption does not occur on similar
    # passphrases
    keys = src_stash.export()
    dst_stash.load(src_passphrase, keys=keys)


class TinyDBStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['tinydb'],
                 stash_name='ghost'):
        self.db_path = os.path.expanduser(db_path)
        self._db = None
        self._stash_name = stash_name

    def init(self):
        dirname = os.path.dirname(self.db_path)
        if dirname and not os.path.isdir(dirname):
            os.makedirs(os.path.dirname(self.db_path))
        if not os.path.isfile(self.db_path):
            open(self.db_path, 'w').close()

    @property
    def is_initialized(self):
        return os.path.isfile(self.db_path)

    def put(self, key):
        """Insert the key and return its database id
        """
        return self.db.insert(key)

    def get(self, key_name):
        """Return a dictionary consisting of the key itself

        e.g.
        {u'created_at': u'2016-10-10 08:31:53',
         u'description': None,
         u'metadata': None,
         u'modified_at': u'2016-10-10 08:31:53',
         u'name': u'aws',
         u'uid': u'459f12c0-f341-413e-9d7e-7410f912fb74',
         u'value': u'the_value'}

        """
        result = self.db.search(Query().name == key_name)
        if not result:
            return {}
        return result[0]

    def list(self):
        """Return a list of all keys (not just key names, but rather the keys
        themselves).

        e.g.
         {u'created_at': u'2016-10-10 08:31:53',
          u'description': None,
          u'metadata': None,
          u'modified_at': u'2016-10-10 08:31:53',
          u'name': u'aws',
          u'uid': u'459f12c0-f341-413e-9d7e-7410f912fb74',
          u'value': u'the_value'},
         {u'created_at': u'2016-10-10 08:32:29',
          u'description': u'my gcp token',
          u'metadata': {u'owner': u'nir'},
          u'modified_at': u'2016-10-10 08:32:29',
          u'name': u'gcp',
          u'uid': u'a51a0043-f241-4d52-93c1-266a3c5de15e',
          u'value': u'the_value'}]

        """
        # TODO: Return only the key names from all storages
        return self.db.search(Query().name.matches('.*'))

    def delete(self, key_name):
        """Delete the key and return true if the key was deleted, else false
        """
        self.db.remove(Query().name == key_name)
        return self.get(key_name) == {}

    @property
    def db(self):
        if self._db is None:
            self._db = TinyDB(
                self.db_path,
                indent=4,
                sort_keys=True,
                separators=(',', ': '))
        return self._db.table(self._stash_name)


class SQLAlchemyStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['sqlalchemy'],
                 stash_name='ghost'):
        if not SQLALCHEMY_EXISTS:
            raise ImportError('SQLAlchemy must be installed first')
        if 'sqlite' in db_path:
            self.db_path = db_path
            self._local_path = urlparse(db_path).path[1:]
        elif '://' in db_path:
            self.db_path = db_path
            self._local_path = None
        else:
            self.db_path = 'sqlite:///' + db_path
            self._local_path = db_path

        self.metadata = MetaData()
        self.keys = Table(
            stash_name,
            self.metadata,
            Column('name', String, primary_key=True),
            Column('value', PickleType),
            Column('description', String),
            Column('metadata', PickleType),
            Column('modified_at', String),
            Column('created_at', String),
            Column('uid', String))
        self._db = None

    def init(self):
        if self._local_path:
            dirname = os.path.dirname(self._local_path)
            if dirname and not os.path.isdir(dirname):
                os.makedirs(dirname)

        if not database_exists(self.db.url):
            create_database(self.db.url)
        # More on connection strings for sqlalchemy:
        # http://docs.sqlalchemy.org/en/latest/core/engines.html
        self.metadata.bind = self.db
        self.metadata.create_all()

    @property
    def is_initialized(self):
        return database_exists(self.db.url)

    def put(self, key):
        return self.db.execute(self.keys.insert(), **key).lastrowid

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
        return self._construct_key(key_values)

    def list(self):
        all_key_values = self.db.execute(sql.select([self.keys]))
        key_list = []
        for key_values in all_key_values:
            key_list.append(self._construct_key(key_values))
        return key_list

    def delete(self, key_name):
        result = self.db.execute(
            self.keys.delete().where(self.keys.c.name == key_name))
        return result.rowcount > 0

    @property
    def db(self):
        if self._db is None:
            self._db = create_engine(self.db_path)
        return self._db

    def _construct_key(self, values):
        """Return a dictionary representing a key from a list of columns
        and a tuple of values
        """
        key = {}
        for column, value in zip(self.keys.columns, values):
            key.update({column.name: value})
        return key


class ConsulStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['consul'],
                 stash_name='ghost',
                 verify=True,
                 client_cert=None,
                 auth=None):
        if not REQUESTS_EXISTS:
            raise ImportError('Requests must be installed first')
        self._url = urljoin(db_path, 'v1/kv/{0}/'.format(stash_name))
        self._session = requests.Session()
        self._session.verify = verify
        self._session.cert = client_cert
        self._session.auth = auth

    def init(self):
        """Consul creates directories on the fly, so no init is required."""

    @property
    def is_initialized(self):
        """...and therefore, this should always return true
        """
        return True

    def put(self, key):
        """Put and return the only unique identifier possible, its url
        """
        self._consul_request('PUT', self._key_url(key['name']), json=key)
        return key['name']

    def get(self, key_name):
        value = self._consul_request('GET', self._key_url(key_name))
        if value is None:
            return {}
        return self._decode(value[0])

    def list(self):
        keys = self._consul_request('GET', self._url + '?recurse')
        return [self._decode(key) for key in keys]

    def delete(self, key_name):
        self._consul_request('DELETE', self._key_url(key_name))
        # Consul returns either true or false for delete operations.
        # Instead of relying on it, we actually check that the key
        # is not retrieveable
        return self.get(key_name) == {}

    def _decode(self, data):
        """Decode one key as returned by consul.

        The format of the data returned is [{'Value': base-64-encoded-json,
        'Key': keyname}]. We need to decode and return just the values.
        """
        return json.loads(base64.b64decode(data['Value']).decode('utf-8'))

    def _key_url(self, key):
        return urljoin(self._url, key)

    def _consul_request(self, method, url, *args, **kwargs):
        handler = getattr(self._session, method.lower())
        response = handler(url, *args, **kwargs)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise GhostError('{0} {1} returned {2}: {3}'.format(
                             method, url, response.status_code,
                             response.content))
        return response.json()


class VaultStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['vault'],
                 token=None or os.environ.get('VAULT_TOKEN'),
                 cert=None,
                 stash_name='ghost'):

        if not HVAC_EXISTS:
            raise ImportError('hvac must be installed first')

        if not token:
            raise GhostError(
                'The `VAULT_TOKEN` env var must be set to use this storage '
                'type')

        self.client = hvac.Client(url=db_path, token=token, cert=cert)
        self._stash_name = stash_name

    def init(self):
        """
        """

    @property
    def is_initialized(self):
        return True

    def put(self, key):
        """Put and return the only unique identifier possible, its path
        """
        self.client.write(self._key_path(key['name']), **key)
        return self._key_path(key['name'])

    def get(self, key_name):
        vault_record = self.client.read(self._key_path(key_name))
        if not vault_record:
            return {}
        return self._convert_vault_record_to_ghost_record(vault_record)

    def list(self):
        keys = self.client.list(self._stash_name)
        if not keys:
            return []
        keys = keys['data']['keys']
        key_list = []
        for key_name in keys:
            key_list.append(self.get(key_name))
        return key_list

    def delete(self, key_name):
        self.client.delete(self._key_path(key_name))
        return self.get(key_name) == {}

    def _key_path(self, key_name):
        """Return a valid vault path

        Note that we don't use os.path.join as the path is read by vault using
        slashes even on Windows.
        """
        return 'secret/' + self._stash_name + '/' + key_name

    @staticmethod
    def _convert_vault_record_to_ghost_record(vault_record):
        ghost_record = dict(**vault_record['data'])
        ghost_record['metadata'] = ghost_record.get('metadata') or {}
        del vault_record['data']
        ghost_record['metadata'].update(vault_record)
        return ghost_record


class ElasticsearchStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['elasticsearch'],
                 stash_name='ghost',
                 use_ssl=False,
                 verify_certs=False,
                 ca_certs='',
                 client_cert='',
                 client_key=''):
        if not ES_EXISTS:
            raise ImportError('elasticsearch-py must be installed first')
        # TODO: Allow multiple hosts
        self.es = elasticsearch.Elasticsearch(
            [db_path],
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            ca_certs=ca_certs,
            client_cert=client_cert,
            client_key=client_key)
        self.params = dict(index=stash_name, doc_type='doc')

    def init(self):
        """Create an Elasticsearch index if necessary
        """
        # ignore 400 (IndexAlreadyExistsException) when creating an index
        self.es.indices.create(index=self.params['index'], ignore=400)

    @property
    def is_initialized(self):
        return self.es.indices.exists(index=self.params['index'])

    def put(self, key):
        document = self.es.index(body=key, **self.params)
        return document['_id']

    def get(self, key_name):
        document_list = self._get_document(key_name)
        if not document_list:
            return {}
        return document_list[0]['_source']

    def list(self):
        query = {"query": {"match_all": {}}}
        result = self.es.search(
            body=query,
            filter_path=['hits.hits._source', 'hits.hits._id'],
            **self.params)
        key_list = []
        for key in result['hits']['hits']:
            key_list.append(key['_source'])
        return key_list

    def delete(self, key_name):
        document_list = self._get_document(key_name)
        if not document_list:
            return True
        # `wait_for` a refresh to make this available for search
        self.es.delete(
            id=document_list[0]['_id'],
            refresh='wait_for',
            **self.params)
        # The response returned by es.delete actually contains
        # the success status of the request. We're not taking
        # any chances here but rather verifying that you can't
        # get that key anymore.
        return self.get(key_name) == {}

    def _get_document(self, key_name):
        query = {"query": {"match": {"name": key_name}}}
        result = self.es.search(
            body=query,
            filter_path=['hits.hits._source', 'hits.hits._id'],
            **self.params)
        return result['hits']['hits'] if result else {}


def _get_current_time():
    """Return a human readable unix timestamp formatted string

    e.g. 2015-06-11 10:10:01
    """
    return datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')


def generate_passphrase(size=12):
    """Return a generate string `size` long based on lowercase, uppercase,
    and digit chars
    """
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return str(''.join(random.choice(chars) for _ in range(size)))


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


def _prettify_dict(key):
    """Return a human readable format of a key (dict).

    Example:

    Description:   My Wonderful Key
    Uid:           a54d6de1-922a-4998-ad34-cb838646daaa
    Created_At:    2016-09-15T12:42:32
    Metadata:      owner=me;
    Modified_At:   2016-09-15T12:42:32
    Value:         secret_key=my_secret_key;access_key=my_access_key
    Name:          aws
    """
    assert isinstance(key, dict)

    pretty_key = ''
    for key, value in key.items():
        if isinstance(value, dict):
            pretty_value = ''
            for k, v in value.items():
                pretty_value += '{0}={1};'.format(k, v)
            value = pretty_value
        pretty_key += '{0:15}{1}\n'.format(key.title() + ':', value)
    return pretty_key


def _prettify_list(items):
    """Return a human readable format of a list.

    Example:

    Available Keys:
      - my_first_key
      - my_second_key
    """
    assert isinstance(items, list)

    keys_list = 'Available Keys:'
    for item in items:
        keys_list += '\n  - {0}'.format(item)
    return keys_list


def _parse_path_string(stash_path):
    stash_parts = stash_path.rsplit('[', 1)
    stash_name = stash_parts[1].rstrip(']') if len(stash_parts) == 2 \
        else 'ghost'
    stash_name = stash_name or 'ghost'
    return dict(
        db_path=stash_parts[0],
        stash_name=stash_name
    )


def _get_stash(backend, path, passphrase, quiet=False):
    stash_path = path or STORAGE_DEFAULT_PATH_MAPPING[backend]
    if not quiet:
        click.echo('Stash: {0} at {1}'.format(backend, stash_path))
    passphrase = passphrase or get_passphrase()
    storage = STORAGE_MAPPING[backend](**_parse_path_string(stash_path))
    stash = Stash(storage, passphrase=passphrase)
    return stash


def _write_passphrase_file(passphrase):
    with open(PASSPHRASE_FILENAME, 'w') as passphrase_file:
        passphrase_file.write(passphrase)


CLICK_CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help'],
    token_normalize_func=lambda param: param.lower())

# Currently static. We'll see how backend implementations go and adjust
# to dynamic mapping accordingly
STORAGE_MAPPING = {
    'tinydb': TinyDBStorage,
    'sqlalchemy': SQLAlchemyStorage,
    'consul': ConsulStorage,
    'vault': VaultStorage,
    'elasticsearch': ElasticsearchStorage
}


@click.group(context_settings=CLICK_CONTEXT_SETTINGS)
def main():
    """Ghost generates a secret-store in which you can
    keep your secrets encrypted. Ghost isn't real. It's just in your head.
    """


stash_option = click.option(
    '-s',
    '--stash',
    envvar='GHOST_STASH_PATH',
    metavar='PATH',
    type=click.STRING,
    help='Path to the storage (Can be set via the `GHOST_STASH_PATH` '
    'env var). You can also provide a stash name (defaults to ghost) '
    'by providing a name in brackets (e.g. http://...:8500[name])')
passphrase_option = click.option(
    '-p',
    '--passphrase',
    envvar='GHOST_PASSPHRASE',
    type=click.STRING,
    help='Stash Passphrase (Can be set via the `GHOST_PASSPHRASE` '
    'env var)')
backend_option = click.option(
    '-b',
    '--backend',
    envvar='GHOST_BACKEND',
    default='tinydb',
    type=click.Choice(STORAGE_MAPPING.keys()),
    help='Storage backend for the stash (Can be set via the '
    '`GHOST_BACKEND_TYPE` env var)')


@main.command(name='init', short_help='Initialize a stash')
@click.argument('STASH_PATH', required=False, type=click.STRING)
@click.option('-p',
              '--passphrase',
              default=None,
              type=click.STRING,
              help='Stash Passphrase')
@click.option('--passphrase-size', default=12)
@click.option('-b',
              '--backend',
              default='tinydb',
              type=click.Choice(STORAGE_MAPPING.keys()),
              help='Storage backend for the stash')
def init_stash(stash_path, passphrase, passphrase_size, backend):
    r"""Init a stash

    `STASH_PATH` is the path to the storage endpoint. If this isn't supplied,
    a default path will be used. In the path, you can specify a name
    for the stash (which, if omitted, will default to `ghost`) like so:
    `ghost init http://10.10.1.1:8500;stash1`.

    After initializing a stash, don't forget you can set environment
    variables for both your stash's path and its passphrase.
    On Linux/OSx you can run:

    export GHOST_STASH_PATH='http://10.10.1.1:8500;stash1'

    export GHOST_PASSPHRASE=$(cat passphrase.ghost)

    export GHOST_BACKEND='tinydb'
    """
    stash_path = stash_path or STORAGE_DEFAULT_PATH_MAPPING[backend]
    click.echo('Stash: {0} at {1}'.format(backend, stash_path))
    storage = STORAGE_MAPPING[backend](**_parse_path_string(stash_path))

    try:
        click.echo('Initializing stash...')
        if os.path.isfile(PASSPHRASE_FILENAME):
            raise GhostError(
                '{0} already exists. Overwriting might prevent you '
                'from accessing the stash it was generated for. '
                'Please make sure to save and remove the file before '
                'initializing another stash.'.format(PASSPHRASE_FILENAME))

        stash = Stash(
            storage,
            passphrase=passphrase,
            passphrase_size=passphrase_size)
        passphrase = stash.init()

        if not passphrase:
            click.echo('Stash already initialized.')
            sys.exit(0)

        _write_passphrase_file(passphrase)
    except GhostError as ex:
        sys.exit(ex)
    except (OSError, IOError) as ex:
        click.echo("Seems like we've run into a problem.")
        file_path = _parse_path_string(stash_path)['db_path']
        click.echo(
            'Removing stale stash and passphrase: {0}. Note that any '
            'directories created are not removed for safety reasons and you '
            'might want to remove them manually.'.format(file_path))
        if os.path.isfile(file_path):
            os.remove(file_path)
        sys.exit(ex)

    click.echo('Initialized stash at: {0}'.format(stash_path))
    click.echo(
        'Your passphrase can be found under the `{0}` file in the '
        'current directory.'.format(PASSPHRASE_FILENAME))
    click.echo(
        'Make sure you save your passphrase somewhere safe. '
        'If lost, you will lose access to your stash.')


@main.command(name='put', short_help='Insert a new key')
@click.argument('KEY_NAME')
@click.argument('VALUE', nargs=-1, required=True)
@click.option('-d',
              '--description',
              help="The key's description")
@click.option('--meta',
              metavar='key=value',
              multiple=True,
              help='`key=value` pairs to serve as metadata for the key '
              '(Can be used multiple times)')
@click.option('-m',
              '--modify',
              is_flag=True,
              help='Whether to modify an existing key if it exists')
@click.option('-a',
              '--add',
              is_flag=True,
              help='Whether to add values to an existing key if it exists')
@click.option('--lock',
              is_flag=True,
              help='Set the key to be locked, preventing its deletion and '
              'modification')
@click.option('-t',
              '--key-type',
              type=click.Choice(['ssh', 'secret']),
              default='secret',
              help='The type of the key')
@stash_option
@passphrase_option
@backend_option
def put_key(key_name,
            value,
            description,
            meta,
            modify,
            add,
            lock,
            key_type,
            stash,
            passphrase,
            backend):
    """Insert a key to the stash

    `KEY_NAME` is the name of the key to insert

    `VALUE` is a key=value argument which can be provided multiple times.
    it is the encrypted value of your key
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Stashing {0} key...'.format(key_type))
        stash.put(
            name=key_name,
            value=_build_dict_from_key_value(value),
            modify=modify,
            metadata=_build_dict_from_key_value(meta),
            description=description,
            lock=lock,
            key_type=key_type,
            add=add)
        click.echo('Key stashed successfully')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='lock', short_help='Lock a key to protect it')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
@backend_option
def lock_key(key_name,
             stash,
             passphrase,
             backend):
    """Lock a key to prevent it from being deleted, purged or modified

    `KEY_NAME` is the name of the key to lock
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Locking key...')
        stash.lock(key_name=key_name)
        click.echo('Key locked successfully')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='unlock', short_help='Unlock a key')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
@backend_option
def unlock_key(key_name,
               stash,
               passphrase,
               backend):
    """Unlock a key to allow it to be modified, deleted or purged

    `KEY_NAME` is the name of the key to unlock
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Unlocking key...')
        stash.unlock(key_name=key_name)
        click.echo('Key unlocked successfully')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='get', short_help='Retrieve a key')
@click.argument('KEY_NAME')
@click.argument('VALUE_NAME', required=False)
@click.option('-j',
              '--jsonify',
              is_flag=True,
              default=False,
              help='Output in JSON')
@click.option('--no-decrypt',
              is_flag=True,
              default=False,
              help='Retrieve the key without decrypting its value')
@stash_option
@passphrase_option
@backend_option
def get_key(key_name,
            value_name,
            jsonify,
            no_decrypt,
            stash,
            passphrase,
            backend):
    """Retrieve a key from the stash

    \b
    `KEY_NAME` is the name of the key to retrieve
    `VALUE_NAME` is a single value to retrieve e.g. if the value
     of the key `test` is `a=b,b=c`, `ghost get test a`a will return
     `b`
    """
    if value_name and no_decrypt:
        sys.exit('VALUE_NAME cannot be used in conjuction with --no-decrypt')

    stash = _get_stash(backend, stash, passphrase, quiet=jsonify or value_name)

    try:
        key = stash.get(key_name=key_name, decrypt=not no_decrypt)
    except GhostError as ex:
        sys.exit(ex)

    if not key:
        sys.exit('Key `{0}` not found'.format(key_name))
    if value_name:
        key = key['value'].get(value_name)
        if not key:
            sys.exit(
                'Value name `{0}` could not be found under key `{1}`'.format(
                    value_name, key_name))

    if jsonify or value_name:
        click.echo(
            json.dumps(key, indent=4, sort_keys=False).strip('"'),
            nl=True)
    else:
        click.echo('Retrieving key...')
        click.echo('\n' + _prettify_dict(key))


@main.command(name='delete', short_help='Delete a key')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
@backend_option
def delete_key(key_name, stash, passphrase, backend):
    """Delete a key from the stash

    `KEY_NAME` is the name of the key to delete
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Deleting key...')
        stash.delete(key_name=key_name)
        click.echo('Key deleted successfully')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='list', short_help='List keys')
@click.argument('KEY_NAME', required=False)
@click.option('-m',
              '--max-suggestions',
              default=3,
              help='The maximum number of suggestions to offer for `KEY_NAME`')
@click.option('-c',
              '--cutoff',
              default=0.5,
              help='The cutoff by which close matches will be provided')
@click.option('-j',
              '--jsonify',
              is_flag=True,
              help='Output in JSON')
@click.option('-l',
              '--locked',
              is_flag=True,
              help='Only list locked keys')
@click.option('-t',
              '--key-type',
              type=click.Choice(['ssh', 'secret']),
              default=None,
              help='The type of the key to put')
@stash_option
@passphrase_option
@backend_option
def list_keys(key_name,
              max_suggestions,
              cutoff,
              jsonify,
              locked,
              key_type,
              stash,
              passphrase,
              backend):
    """List all keys in the stash

    If `KEY_NAME` is provided, will look for keys containing `KEY_NAME`.
    If `KEY_NAME` starts with `~`, close matches will be provided according
    to `max_suggestions` and `cutoff`.
    """
    stash = _get_stash(backend, stash, passphrase, quiet=jsonify)

    try:
        keys = stash.list(
            key_name=key_name,
            max_suggestions=max_suggestions,
            cutoff=cutoff,
            locked_only=locked,
            key_type=key_type)
    except GhostError as ex:
        sys.exit(ex)
    if jsonify:
        click.echo(json.dumps(keys, indent=4, sort_keys=True))
    elif not keys:
        click.echo('The stash is empty. Go on, put some keys in there...')
    else:
        click.echo('Listing all keys...')
        click.echo(_prettify_list(keys))


@main.command(name='purge', short_help='Purge all keys')
@click.option('-f',
              '--force',
              required=True,
              is_flag=True,
              help='This flag is mandatory to perform a purge')
@stash_option
@passphrase_option
@backend_option
def purge_stash(force, stash, passphrase, backend):
    """Purge the stash from all of its keys
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Purging stash...')
        stash.purge(force)
        # Maybe we should verify that the list is empty
        # afterwards?
        click.echo('Purge complete!')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='export')
@click.option('-o',
              '--output-path',
              default='ghost-key-file.json',
              help='Save exported keys in a file')
@stash_option
@passphrase_option
@backend_option
def export_keys(output_path, stash, passphrase, backend):
    """Export all keys to a file
    """
    stash = _get_stash(backend, stash, passphrase)

    try:
        click.echo('Exporting stash to {0}...'.format(output_path))
        stash.export(output_path=output_path)
        click.echo('Export complete!')
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='load', short_help='Load keys from backup')
@click.argument('KEY_FILE')
@click.option('--origin-passphrase',
              help='The passphrase of the origin stash')
@stash_option
@passphrase_option
@backend_option
def load_keys(key_file, origin_passphrase, stash, passphrase, backend):
    """Load all keys from an exported key file to the stash

    `KEY_FILE` is the exported stash file to load keys from
    """
    stash = _get_stash(backend, stash, passphrase)

    click.echo('Importing all keys from {0}...'.format(key_file))
    stash.load(origin_passphrase, key_file=key_file)
    click.echo('Import complete!')


@main.command(name='migrate',
              short_help='Migrate keys from source to destination stash')
@click.argument('SOURCE_STASH_PATH', type=click.STRING)
@click.argument('DESTINATION_STASH_PATH', type=click.STRING)
@click.option('-sp',
              '--source-passphrase',
              default=None,
              type=click.STRING,
              help='Path to the source stash')
@click.option('-sb',
              '--source-backend',
              type=click.Choice(STORAGE_MAPPING.keys()),
              help='Storage backend for the stash')
@click.option('-dp',
              '--destination-passphrase',
              default=None,
              type=click.STRING,
              help='Path to the destination stash')
@click.option('-db',
              '--destination-backend',
              type=click.Choice(STORAGE_MAPPING.keys()),
              help='Storage backend for the stash')
def migrate_stash(source_stash_path,
                  source_passphrase,
                  source_backend,
                  destination_stash_path,
                  destination_passphrase,
                  destination_backend):
    """Migrate all keys from a source stash to a destination stash.

    `SOURCE_STASH_PATH` and `DESTINATION_STASH_PATH` are the paths
    to the stashs you wish to perform the migration on.
    """
    click.echo('Migrating all keys from {0} to {1}...'.format(
        source_stash_path, destination_stash_path))

    try:
        migrate(
            src_path=source_stash_path,
            src_passphrase=source_passphrase,
            src_backend=source_backend,
            dst_path=destination_stash_path,
            dst_passphrase=destination_passphrase,
            dst_backend=destination_backend)
    except GhostError as ex:
        sys.exit(ex)
    click.echo('Migration complete!')


@main.command(name='ssh', short_help='Use a key to SSH-connect to a machine')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
@backend_option
def ssh(key_name, stash, passphrase, backend):
    """Use an ssh type key to connect to a machine via ssh

    Note that trying to use a key of the wrong type (e.g. `secret`)
    will result in an error.

    `KEY_NAME` is the key to use.
    """
    # TODO: find_executable or raise
    def execute(command):
        try:
            click.echo('Executing: {0}'.format(' '.join(command)))
            subprocess.check_call(' '.join(command), shell=True)
        except subprocess.CalledProcessError:
            sys.exit(1)

    stash = _get_stash(backend, stash, passphrase)
    key = stash.get(key_name)

    if key:
        _assert_is_ssh_type_key(key)
    else:
        sys.exit('Key `{0}` not found'.format(key_name))

    conn_info = key['value']
    ssh_key_path = conn_info.get('ssh_key_path')
    ssh_key = conn_info.get('ssh_key')
    proxy_key_path = conn_info.get('proxy_key_path')
    proxy_key = conn_info.get('proxy_key')

    id_file = _write_tmp(ssh_key) if ssh_key else ssh_key_path
    conn_info['ssh_key_path'] = id_file

    if conn_info.get('proxy'):
        proxy_id_file = _write_tmp(proxy_key) if proxy_key else proxy_key_path
        conn_info['proxy_key_path'] = proxy_id_file

    ssh_command = _build_ssh_command(conn_info)
    try:
        execute(ssh_command)
    finally:
        # If they're not equal, that means we've created a temp one which
        # should be deleted, else, it's a path to an existing key file.
        if id_file != ssh_key_path:
            click.echo('Removing temp ssh key file: {0}...'.format(id_file))
            os.remove(id_file)
        if conn_info.get('proxy') and proxy_id_file != proxy_key_path:
            click.echo('Removing temp proxy key file: {0}...'.format(
                proxy_id_file))
            os.remove(proxy_id_file)


def _build_proxy_command(conn_info):
    proxy = conn_info.get('proxy')
    proxy_key_path = conn_info.get('proxy_key_path')

    conn = conn_info['conn']
    _, _host = conn.split('@')
    hp = _host.split(':')
    host, port = (hp[0], hp[1]) if len(hp) == 2 else (hp[0], '22')

    idf = '-o IdentityFile="{0}"'.format(proxy_key_path)
    proxy = '-o ProxyCommand="ssh -i {0} {1} nc {2} {3}"'.format(
        proxy_key_path or conn_info['ssh_key_path'], proxy, host, port)
    return [proxy, idf]


def _build_ssh_command(conn_info):
    """
    IndetityFile="~/.ssh/id_rsa"
    ProxyCommand="ssh -i ~/.ssh/id_rsa proxy_IP nc HOST_IP HOST_PORT"
    """
    command = ['ssh', '-i', conn_info['ssh_key_path'], conn_info['conn']]

    if conn_info.get('proxy'):
        command.extend(_build_proxy_command(conn_info))
    if conn_info.get('extend'):
        command.append(conn_info.get('extend'))
    return command


def _write_tmp(content):
    fd, temp_file_path = tempfile.mkstemp()
    os.write(fd, content.encode('utf8'))
    os.close(fd)
    return temp_file_path


def _assert_is_ssh_type_key(key):
    if not key.get('type') == 'ssh':
        sys.exit(
            'Must provide key of type `ssh` (provided `{0}` instead)'.format(
                key.get('type') or 'secret'))
