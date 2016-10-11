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
import binascii
import warnings
from datetime import datetime

try:
    from urllib.parse import urljoin, urlparse
except ImportError:
    # python 2
    from urlparse import urljoin, urlparse

import click

from tinydb import TinyDB, Query
from appdirs import user_data_dir
from cryptography.fernet import Fernet
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


GHOST_HOME = user_data_dir('ghost')
STORAGE_DEFAULT_PATH_MAPPING = {
    'tinydb': os.path.join(GHOST_HOME, 'stash.json'),
    'sqlalchemy': os.path.join(GHOST_HOME, 'stash.sql'),
    'consul': 'http://127.0.0.1:8500',
    'vault': 'http://127.0.0.1:8200',
    'elasticsearch': 'http://127.0.0.1:9200'
}

PASSPHRASE_FILENAME = 'passphrase.ghost'


class Stash(object):
    def __init__(self, storage, passphrase=None, passphrase_size=12):
        self._storage = storage
        passphrase = passphrase or generate_passphrase(passphrase_size)
        self.passphrase = passphrase

    # TODO: Consider base64 encoding instead of hexlification
    _key = None

    @property
    def key(self):
        if self._key is None:
            passphrase = self.passphrase.encode('utf-8')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'ghost',
                iterations=1000000,
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
            description='',
            encrypt=True):
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
        if value and encrypt and not isinstance(value, dict):
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

        if value:
            if encrypt:
                value = self._encrypt(value)
        else:
            value = existing_key.get('value')
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

    def get(self, key_name, decrypt=True):
        """Return a key with its parameters if it was found.
        """
        key = self._storage.get(key_name).copy()
        if not key.get('value'):
            return None
        if decrypt:
            key['value'] = self._decrypt(key['value'])
        return key

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

    def purge(self, force=False):
        """Purge the stash from all keys
        """
        if not force:
            raise GhostError(
                "The `force` flag must be provided to perform a stash purge. "
                "I mean, you don't really want to just delete everything "
                "without precautionary measures eh?")
        for key_name in self.list():
            self.delete(key_name)

    def export(self, output_path=None, decrypt=False):
        """Export all keys in the stash to a list or a file
        """
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

    def load(self, keys=None, key_file=None, encrypt=False):
        """Import keys to the stash from either a list of keys or a file

        `keys` is a list of dictionaries created by `self.export`
        `stash_path` is a path to a file created by `self.export`
        """
        # TODO: Handle keys not dict or key_file not json
        if not keys and not key_file or (keys and key_file):
            raise GhostError(
                'You must either provide a path to an exported stash file '
                'or a list of key dicts to import')
        if key_file:
            with open(key_file) as stash_file:
                keys = json.loads(stash_file.read())

        for key in keys:
            self.put(
                name=key['name'],
                value=key['value'],
                metadata=key['metadata'],
                description=key['description'],
                encrypt=encrypt)


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
    """
    src_storage = STORAGE_MAPPING[src_backend](db_path=src_path)
    dst_storage = STORAGE_MAPPING[dst_backend](db_path=dst_path)
    src_stash = Stash(src_storage, src_passphrase)
    dst_stash = Stash(dst_storage, dst_passphrase)
    keys = src_stash.export(decrypt=True)
    dst_stash.load(keys=keys, encrypt=True)


class TinyDBStorage(object):
    def __init__(self, db_path=STORAGE_DEFAULT_PATH_MAPPING['tinydb']):
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
        dirname = os.path.dirname(self.db_path)
        if dirname and not os.path.isdir(dirname):
            os.makedirs(os.path.dirname(self.db_path))
        elif os.path.isfile(self.db_path):
            raise GhostError('Stash {0} already initialized'.format(
                self.db_path))

    def put(self, key):
        """Insert the key and return its database id
        """
        return self.db.insert(key)

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

    def delete(self, key_name):
        """Delete the key and return true if the key was deleted, else false
        """
        return self.db.remove(Query().name == key_name)


class SQLAlchemyStorage(object):
    def __init__(self, db_path=STORAGE_DEFAULT_PATH_MAPPING['sqlalchemy']):
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
            'keys',
            self.metadata,
            Column('name', String, primary_key=True),
            Column('value', PickleType),
            Column('description', String),
            Column('metadata', PickleType),
            Column('modified_at', String),
            Column('created_at', String),
            Column('uid', String))

        self._db = None

    @property
    def db(self):
        if self._db is None:
            self._db = create_engine(self.db_path)
        return self._db

    def init(self):
        if self._local_path:
            dirname = os.path.dirname(self._local_path)
            if dirname and not os.path.isdir(dirname):
                os.makedirs(dirname)
            elif os.path.isfile(self._local_path):
                raise GhostError('Stash {0} already initialized'.format(
                    self._local_path))

        # More on connection strings for sqlalchemy:
        # http://docs.sqlalchemy.org/en/latest/core/engines.html
        self.metadata.bind = self.db
        self.metadata.create_all()

    def put(self, key):
        """
        `key` is the dictionary representing the key
        """
        return self.db.execute(self.keys.insert(), **key).lastrowid

    def _construct_key(self, values):
        """Return a dictionary representing a key from a list of columns
        and a tuple of values
        """
        key = {}
        for column, value in zip(self.keys.columns, values):
            key.update({column.name: value})
        return key

    def list(self):
        all_key_values = self.db.execute(sql.select([self.keys]))
        key_list = []
        for key_values in all_key_values:
            key_list.append(self._construct_key(key_values))
        return key_list

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

    def delete(self, key_name):
        result = self.db.execute(
            self.keys.delete().where(self.keys.c.name == key_name))
        return result.rowcount > 0


class ConsulStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['consul'],
                 directory='ghost',
                 verify=True,
                 client_cert=None,
                 auth=None):
        if not REQUESTS_EXISTS:
            raise ImportError('Requests must be installed first')
        self._url = urljoin(db_path, 'v1/kv/{0}/'.format(directory))
        self._session = requests.Session()
        self._session.verify = verify
        self._session.cert = client_cert
        self._session.auth = auth

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

    def init(self):
        """Consul creates directories on the fly, so no init is required."""

    def put(self, key):
        """
        `key` is the dictionary representing the key
        """
        return self._consul_request(
            'PUT', self._key_url(key['name']), json=key)

    def _decode(self, data):
        """Decode one key as returned by consul.

        The format of the data returned is [{'Value': base-64-encoded-json,
        'Key': keyname}]. We need to decode and return just the values.
        """
        return json.loads(base64.b64decode(data['Value']).decode('utf-8'))

    def list(self):
        keys = self._consul_request('GET', self._url + '?recurse')
        return [self._decode(k) for k in keys]

    def get(self, key_name):
        value = self._consul_request('GET', self._key_url(key_name))
        if value is None:
            return {}
        return self._decode(value[0])

    def delete(self, key_name):
        return self._consul_request('DELETE', self._key_url(key_name))


class VaultStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['vault'],
                 token=None or os.environ.get('VAULT_TOKEN'),
                 cert=None,
                 path='secret'):

        if not HVAC_EXISTS:
            raise ImportError('hvac must be installed first')

        if not token:
            raise GhostError(
                'The `VAULT_TOKEN` env var must be set to use this storage '
                'type')

        self.client = hvac.Client(url=db_path, token=token, cert=cert)
        self.path = path

    def _key_path(self, key_name):
        return os.path.join(self.path, key_name)

    def init(self):
        """
        """

    def put(self, key):
        # TODO: Check if vault has a uid of a secret to return
        self.client.write(self._key_path(key['name']), **key)

    def list(self):
        keys = self.client.list(self.path)
        if not keys:
            return []
        keys = keys['data']['keys']
        key_list = []
        for key_name in keys:
            key_list.append(self.get(key_name))
        return key_list

    @staticmethod
    def _convert_vault_record_to_ghost_record(vault_record):
        ghost_record = dict(**vault_record['data'])
        ghost_record['metadata'] = ghost_record.get('metadata') or {}
        del vault_record['data']
        ghost_record['metadata'].update(vault_record)
        return ghost_record

    def get(self, key_name):
        vault_record = self.client.read(self._key_path(key_name))
        if not vault_record:
            return {}
        return self._convert_vault_record_to_ghost_record(vault_record)

    def delete(self, key_name):
        self.client.delete(self._key_path(key_name))
        return self.get(key_name) == {}


class ElasticsearchStorage(object):
    def __init__(self,
                 db_path=STORAGE_DEFAULT_PATH_MAPPING['elasticsearch'],
                 index='ghost',
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
        self.params = dict(index=index, doc_type='doc')

    def init(self):
        """Create an Elasticsearch index if necessary
        """
        # ignore 400 (IndexAlreadyExistsException) when creating an index
        return self.es.indices.create(index=self.params['index'], ignore=400)

    def put(self, key):
        document = self.es.index(body=key, **self.params)
        return document['_id']

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

    def _get_document(self, key_name):
        query = {"query": {"match": {"name": key_name}}}
        result = self.es.search(
            body=query,
            filter_path=['hits.hits._source', 'hits.hits._id'],
            **self.params)
        return result['hits']['hits'] if result else {}

    def get(self, key_name):
        document_list = self._get_document(key_name)
        if not document_list:
            return {}
        return document_list[0]['_source']

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
    required=True,
    type=click.STRING,
    help='Path to the stash (Can be set via the `GHOST_STASH_PATH` '
    'env var)')
passphrase_option = click.option(
    '-p',
    '--passphrase',
    envvar='GHOST_PASSPHRASE',
    required=True,
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
    '`GHOST_BACKEND_TYPE` env var)'.format(
        STORAGE_MAPPING.keys()))


@main.command(name='init', short_help='Init a stash')
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
              help='Storage backend for the stash'.format(
                  STORAGE_MAPPING.keys()))
def init_stash(stash_path, passphrase, passphrase_size, backend):
    r"""Init a stash

    `STASH_PATH` is the path to the stash. If this isn't supplied,
    a default path will be used.

    After initializing a stash, don't forget you can set environment
    variables for both your stash's path and its passphrase.
    On Linux/OSx you can run:

    export GHOST_STASH_PATH='MY_PATH'

    export GHOST_PASSPHRASE=$(cat passphrase.ghost)
    """
    click.echo('Initializing stash...')
    stash_path = stash_path or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash_path)
    stash = Stash(storage, passphrase=passphrase)
    try:
        passphrase = stash.init()
        with open(PASSPHRASE_FILENAME, 'w') as passphrase_file:
            passphrase_file.write(passphrase)
    except (GhostError, OSError) as ex:
        sys.exit(ex)
    click.echo('Initialized stash at: {0}'.format(stash_path))
    click.echo(
        'Your passphrase can be found under the `{0}` file in the '
        'current directory'.format(PASSPHRASE_FILENAME))
    click.echo(
        'Make sure you save your passphrase somewhere safe. '
        'If lost, you will lose access to your stash.')


@main.command(name='put', short_help='Insert a key to the stash')
@click.argument('KEY_NAME')
@click.argument('VALUE', nargs=-1, required=True)
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
@backend_option
def put_key(key_name,
            value,
            description,
            meta,
            modify,
            stash,
            passphrase,
            backend):
    """Insert a key to the stash

    `KEY_NAME` is the name of the key to insert

    `VALUE` is a key=value argument which can be provided multiple times.
    it is the encrypted value of your key
    """
    click.echo('Stashing key...')
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
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
@click.option('--no-decrypt',
              is_flag=True,
              default=False,
              help='Retrieve the key without decrypting its value')
@stash_option
@passphrase_option
@backend_option
def get_key(key_name, jsonify, no_decrypt, stash, passphrase, backend):
    """Retrieve a key from the stash

    `KEY_NAME` is the name of the key to retrieve
    """
    if not jsonify:
        click.echo('Retrieving key...')
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    record = stash.get(key_name=key_name, decrypt=not no_decrypt)
    if not record:
        sys.exit('Key {0} not found'.format(key_name))
    if jsonify:
        click.echo(json.dumps(record, indent=4, sort_keys=False))
    else:
        click.echo('\n' + _prettify_dict(record))


@main.command(name='delete', short_help='Delete a key from the stash')
@click.argument('KEY_NAME')
@stash_option
@passphrase_option
@backend_option
def delete_key(key_name, stash, passphrase, backend):
    """Delete a key from the stash

    `KEY_NAME` is the name of the key to delete
    """
    click.echo('Deleting key...')
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
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
@backend_option
def list_keys(jsonify, stash, passphrase, backend):
    """List all keys in the stash
    """
    if not jsonify:
        click.echo('Listing all keys in {0}...'.format(stash))
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    keys = stash.list()
    if not keys:
        click.echo('The stash is empty. Go on, put some keys in there...')
    elif jsonify:
        click.echo(json.dumps(keys, indent=4, sort_keys=False))
    else:
        click.echo(_prettify_list(keys))


@main.command(name='purge')
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
    click.echo('Purging stash {0}...'.format(stash))
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.purge(force)
        # Maybe we should verify that the list is empty
        # afterwards?
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
    click.echo('Exporting stash {0} to {1}...'.format(stash, output_path))
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    try:
        stash.export(output_path=output_path)
    except GhostError as ex:
        sys.exit(ex)


@main.command(name='load')
@click.argument('KEY_FILE')
@stash_option
@passphrase_option
@backend_option
def load_keys(key_file, stash, passphrase, backend):
    """Load all keys from an exported key file to the stash

    `KEY_FILE` is the exported stash file to load keys from
    """
    click.echo('Importing all keys from {0} to {1}...'.format(key_file, stash))
    stash = stash or STORAGE_DEFAULT_PATH_MAPPING[backend]
    storage = STORAGE_MAPPING[backend](db_path=stash)
    stash = Stash(storage, passphrase=passphrase)
    stash.load(key_file=key_file)


@main.command(name='migrate')
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
              help='Storage backend for the stash'.format(
                  STORAGE_MAPPING.keys()))
@click.option('-dp',
              '--destination-passphrase',
              default=None,
              type=click.STRING,
              help='Path to the destination stash')
@click.option('-db',
              '--destination-backend',
              type=click.Choice(STORAGE_MAPPING.keys()),
              help='Storage backend for the stash'.format(
                  STORAGE_MAPPING.keys()))
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
