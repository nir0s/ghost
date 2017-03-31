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

import os
import time
import json
import shlex
import base64
import shutil
import tempfile
import subprocess

import mock
import pytest
import click.testing as clicktest

import hvac  # NOQA
import elasticsearch  # NOQA
from sqlalchemy import sql
from sqlalchemy import inspect
from sqlalchemy import create_engine


import ghost


TEST_PASSPHRASE = 'a'


def _invoke(command):
    cfy = clicktest.CliRunner()

    lexed_command = command if isinstance(command, list) \
        else shlex.split(command)
    func = lexed_command[0]
    params = lexed_command[1:]
    return cfy.invoke(getattr(ghost, func), params)


class TestGeneral:
    def test_get_current_time(self):
        assert len(ghost._get_current_time()) == 19

    def test_generate_passphrase(self):
        passphrase = ghost.generate_passphrase()
        assert len(passphrase) == 12
        assert isinstance(passphrase, str)
        longer_passphrase = ghost.generate_passphrase(13)
        assert len(longer_passphrase) == 13

    def test_build_dict_from_key_value(self):
        key_values = ['a=b', 'c=d']
        key_dict = ghost._build_dict_from_key_value(key_values)
        assert isinstance(key_dict, dict)
        assert 'a' in key_dict
        assert 'c' in key_dict
        assert key_dict.get('a') == 'b'
        assert key_dict.get('c') == 'd'

    def test_build_dict_no_key_equals_value(self):
        key_values = ['a=b', 'cd']
        with pytest.raises(ghost.GhostError):
            ghost._build_dict_from_key_value(key_values)

    def test_prettify_dict(self):
        input = dict(
            description='a',
            uid='b',
            created_at='c',
            metadata={'x': 'y'},
            modified='e',
            value={'key': 'value'},
            name='g')
        prettified_input = ghost._prettify_dict(input).splitlines()
        assert 'Description:   a' in prettified_input
        assert 'Uid:           b' in prettified_input
        assert 'Created_At:    c' in prettified_input
        assert 'Metadata:      x=y;' in prettified_input
        assert 'Modified:      e' in prettified_input
        assert 'Value:         key=value;' in prettified_input
        assert 'Name:          g' in prettified_input

    def test_prettify_dict_input_not_dict(self):
        with pytest.raises(AssertionError):
            ghost._prettify_dict('')

    def test_prettify_list(self):
        input = ['a', 'b', 'c']
        prettified_input = ghost._prettify_list(input).splitlines()
        for line in prettified_input:
            assert '  - a' in prettified_input
            assert '  - b' in prettified_input
            assert '  - c' in prettified_input

    def test_prettify_list_input_not_list(self):
        with pytest.raises(AssertionError):
            ghost._prettify_list('')

    def test_get_passphrase(self):
        def _make_temp_passphrase_file():
            fd, temp_file_path = tempfile.mkstemp()
            os.close(fd)
            os.remove(temp_file_path)
            return temp_file_path

        tempfile1 = _make_temp_passphrase_file()
        tempfile2 = _make_temp_passphrase_file()

        passphrase = '123'
        assert isinstance(ghost.POTENTIAL_PASSPHRASE_LOCATIONS, list)
        ghost.POTENTIAL_PASSPHRASE_LOCATIONS = [tempfile1, tempfile2]
        assert ghost.get_passphrase() is None
        for passphrase_file_path in ghost.POTENTIAL_PASSPHRASE_LOCATIONS:
            try:
                with open(passphrase_file_path, 'w') as passphrase_file:
                    passphrase_file.write(passphrase)
                assert ghost.get_passphrase() == passphrase
            finally:
                os.remove(passphrase_file_path)
        assert passphrase is ghost.get_passphrase(passphrase)


def _create_temp_file():
    fd, temp_file = tempfile.mkstemp()
    os.close(fd)
    print('PATH: {0}'.format(temp_file))
    try:
        os.remove(temp_file)
    except:
        pass
    return temp_file


@pytest.fixture
def stash_path():
    temp_file = _create_temp_file()
    yield temp_file
    if os.path.isfile(temp_file):
        try:
            os.remove(temp_file)
        except:
            pass


@pytest.fixture
def temp_file_path():
    temp_file = _create_temp_file()
    yield temp_file
    if os.path.isfile(temp_file):
        try:
            os.remove(temp_file)
        except:
            pass


def get_tinydb(path):
    with open(path) as db:
        return json.loads(db.read())['ghost']


class TestStorage(object):
    @staticmethod
    def is_initialized(structure):
        assert isinstance(structure, bool)

    @staticmethod
    def put(structure):
        assert isinstance(structure, (str, int))

    @staticmethod
    def get_nonexisting_key(structure):
        assert isinstance(structure, dict)
        assert not structure

    @staticmethod
    def get(structure):
        assert isinstance(structure, dict)
        assert isinstance(structure['value'], dict)
        assert isinstance(structure['metadata'], dict)
        str(structure['name'])
        str(structure['uid'])
        str(structure['description'])

    @staticmethod
    def delete(structure):
        assert isinstance(structure, bool)

    def list(self, structure):
        assert isinstance(structure, list)
        for key in structure:
            self.get(key)

    @staticmethod
    def empty_list(structure):
        assert isinstance(structure, list)
        assert len(structure) == 0


storage_tester = TestStorage()


BASE_TEST_KEY = {
    'name': 'my_key',
    'value': {'a': 'b'},
    'metadata': {},
    'created_at': '',
    'modified_at': '',
    'uid': '',
    'description': 'My Key'
}


class TestTinyDBStorage:
    def test_init(self):
        tmpdir = tempfile.mkdtemp()
        shutil.rmtree(tmpdir, ignore_errors=True)
        assert not os.path.isdir(tmpdir)
        stash_path = os.path.join(tmpdir, 'stash.json')
        storage = ghost.TinyDBStorage(stash_path)
        try:
            storage.init()
            assert os.path.isdir(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_init_stash_already_exists(self):
        fd, stash_path = tempfile.mkstemp()
        os.close(fd)
        try:
            storage = ghost.TinyDBStorage(stash_path)
            storage.init()
        finally:
            os.remove(stash_path)

    def test_init_stash_create_directory(self):
        stash_dir = tempfile.mkdtemp()
        shutil.rmtree(stash_dir, ignore_errors=True)
        stash_path = os.path.join(stash_dir, 'stash.json')
        try:
            storage = ghost.TinyDBStorage(stash_path)
            assert os.path.isdir(stash_dir) is False
            storage.init()
            assert os.path.isdir(stash_dir) is True
        finally:
            shutil.rmtree(stash_dir, ignore_errors=True)

    def test_init_stash_in_current_dir(self):
        """Test this because it depends on the ability
        of the storage to understand whether it should or should not create
        a directory.
        """
        prev_dir = os.getcwd()
        stash_dir = tempfile.mkdtemp()
        os.chdir(stash_dir)
        stash_path = os.path.join(stash_dir, 'stash.json')
        try:
            storage = ghost.TinyDBStorage(stash_path)
            stash = ghost.Stash(storage)
            assert os.path.isfile(stash_path) is False
            stash.init()
            assert os.path.isfile(stash_path) is True
        finally:
            os.chdir(prev_dir)
            shutil.rmtree(stash_dir, ignore_errors=True)

    def test_is_initialized(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        stash = ghost.Stash(storage)
        assert storage.is_initialized is False
        stash.init()
        assert storage.is_initialized is True
        storage_tester.is_initialized(storage.is_initialized)

    def test_put(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        key_id = storage.put(BASE_TEST_KEY)
        db = get_tinydb(stash_path)
        assert '1' in db
        assert db['1']['name'] == BASE_TEST_KEY['name']
        assert len(db) == 1
        storage_tester.put(key_id)

    def test_list(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        storage.put(BASE_TEST_KEY)
        key_list = storage.list()
        assert BASE_TEST_KEY in key_list
        assert len(key_list) == 1
        storage_tester.list(key_list)

    def test_empty_list(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        key_list = storage.list()
        storage_tester.empty_list(key_list)

    def test_get_delete(self, stash_path):
        inserted_key = BASE_TEST_KEY
        storage = ghost.TinyDBStorage(stash_path)
        storage.put(inserted_key)
        retrieved_key = storage.get(BASE_TEST_KEY['name'])
        assert inserted_key == retrieved_key
        storage_tester.get(retrieved_key)

        result = storage.delete(BASE_TEST_KEY['name'])
        storage_tester.delete(result)

        key = storage.get(BASE_TEST_KEY['name'])
        storage_tester.get_nonexisting_key(key)


class TestSQLAlchemyStorage:
    def test_missing_requirement(self):
        with mock.patch('ghost.SQLALCHEMY_EXISTS', False):
            with pytest.raises(ImportError):
                ghost.SQLAlchemyStorage()

    def test_init(self):
        tmpdir = os.path.join(tempfile.mkdtemp())
        shutil.rmtree(tmpdir, ignore_errors=True)
        assert not os.path.isdir(tmpdir)
        stash_path = os.path.join(tmpdir, 'stash.json')
        storage = ghost.SQLAlchemyStorage(stash_path)
        try:
            storage.init()
            assert os.path.isdir(tmpdir)
            engine = create_engine(storage.db_path)
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            assert 'ghost' in tables
            columns = [c['name'] for c in inspector.get_columns(tables[0])]
            assert 'description' in columns
            assert 'uid' in columns
            assert 'name' in columns
            assert 'value' in columns
            assert 'metadata' in columns
            assert 'modified_at' in columns
            assert 'created_at' in columns
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_init_stash_already_exists(self):
        fd, stash_path = tempfile.mkstemp()
        os.close(fd)
        storage = ghost.SQLAlchemyStorage('sqlite:///' + stash_path)
        storage.init()
        try:
            os.remove(stash_path)
        except:
            pass

    def test_db_path_not_sqlite(self):
        db_path = 'postgresql+psycopg2://user:password@localhost/ghost'
        storage = ghost.SQLAlchemyStorage(db_path)
        assert storage.db_path == db_path
        assert storage._local_path is None

    def test_init_stash_create_directory(self):
        stash_dir = tempfile.mkdtemp()
        shutil.rmtree(stash_dir, ignore_errors=True)
        stash_path = os.path.join(stash_dir, 'stash.json')
        try:
            storage = ghost.SQLAlchemyStorage(stash_path)
            assert os.path.isdir(stash_dir) is False
            storage.init()
            assert os.path.isdir(stash_dir) is True
        finally:
            shutil.rmtree(stash_dir, ignore_errors=True)

    def test_init_stash_in_current_dir(self):
        """Test this because it depends on the ability
        of the storage to understand whether it should or should not create
        a directory.
        """
        prev_dir = os.getcwd()
        stash_dir = tempfile.mkdtemp()
        os.chdir(stash_dir)
        stash_path = os.path.join(stash_dir, 'stash.json')
        try:
            storage = ghost.SQLAlchemyStorage(stash_path)
            assert os.path.isfile(stash_path) is False
            storage.init()
            assert os.path.isfile(stash_path) is True
        finally:
            os.chdir(prev_dir)
            shutil.rmtree(stash_dir, ignore_errors=True)

    def test_is_initialized(self, stash_path):
        storage = ghost.SQLAlchemyStorage(stash_path)
        stash = ghost.Stash(storage)
        assert storage.is_initialized is False
        stash.init()
        assert storage.is_initialized is True
        storage_tester.is_initialized(storage.is_initialized)

    def test_put(self, stash_path):
        storage = ghost.SQLAlchemyStorage(stash_path)
        storage.init()
        key_id = storage.put(BASE_TEST_KEY)
        engine = create_engine(storage.db_path)
        results = engine.execute(sql.select(
            [storage.keys], storage.keys.c.name == BASE_TEST_KEY['name']))
        for result in results:
            assert result[0] == BASE_TEST_KEY['name']
            assert result[1] == BASE_TEST_KEY['value']
            assert result[2] == BASE_TEST_KEY['description']

        storage_tester.put(key_id)

    def test_list(self, stash_path):
        storage = ghost.SQLAlchemyStorage(stash_path)
        storage.init()
        storage.put(BASE_TEST_KEY)
        key_list = storage.list()
        assert len(key_list) == 1
        assert BASE_TEST_KEY['name'] == key_list[0]['name']
        storage_tester.list(key_list)

    def test_empty_list(self, stash_path):
        storage = ghost.SQLAlchemyStorage(stash_path)
        storage.init()
        key_list = storage.list()

        storage_tester.empty_list(key_list)

    def test_get_delete(self, stash_path):
        storage = ghost.SQLAlchemyStorage(stash_path)
        storage.init()
        storage.put(BASE_TEST_KEY)
        retrieved_key = storage.get(BASE_TEST_KEY['name'])
        assert BASE_TEST_KEY['name'] == retrieved_key['name']
        storage_tester.get(retrieved_key)

        result = storage.delete(BASE_TEST_KEY['name'])
        storage_tester.delete(result)

        key = storage.get(BASE_TEST_KEY['name'])
        storage_tester.get_nonexisting_key(key)


class TestConsulStorage:
    def test_missing_requirement(self):
        """Without requests, an error is thrown as soon as possible."""
        with mock.patch('ghost.REQUESTS_EXISTS', False):
            with pytest.raises(ImportError):
                ghost.ConsulStorage()

    def test_is_initialized(self):
        storage = ghost.ConsulStorage()
        assert storage.is_initialized is True
        storage_tester.is_initialized(storage.is_initialized)

    def test_get_400(self):
        """Unhandled errors from consul are turned into a GhostError."""
        storage = ghost.ConsulStorage()

        def mock_get(url):
            return mock.Mock(status_code=400)

        with mock.patch.object(storage._session, 'get', side_effect=mock_get):
            with pytest.raises(ghost.GhostError):
                storage.get('key_name')

    def test_get_decode(self):
        """The ConsulStorage can decode data in the format returned by consul.
        """
        original_key = {'secret': 42}
        storage = ghost.ConsulStorage()

        def mock_get(url):
            resp = mock.Mock()
            resp.status_code = 200
            # consul returns the data jsonified and base64-encoded
            json_bytes = json.dumps(original_key).encode('utf-8')
            resp.json.return_value = \
                [{'Value': base64.b64encode(json_bytes)}]
            return resp

        with mock.patch.object(storage._session, 'get',
                               side_effect=mock_get) as m:
            retrieved_key = storage.get('key_name')

        m.assert_called_with('http://127.0.0.1:8500/v1/kv/ghost/key_name')
        assert retrieved_key == original_key

    def test_get_404(self):
        """Getting a nonexistent key returns an empty dict."""
        storage = ghost.ConsulStorage()

        def mock_get(url):
            return mock.Mock(status_code=404)

        with mock.patch.object(storage._session, 'get',
                               side_effect=mock_get) as m:
            retrieved_key = storage.get('nonexistent')

        m.assert_called_with('http://127.0.0.1:8500/v1/kv/ghost/nonexistent')
        assert retrieved_key == {}

    def test_list(self):
        """Listing keys returns the whole stored objects."""
        storage = ghost.ConsulStorage(stash_name='ghost')
        original_key = {'secret': 42, 'name': 'baz'}

        def mock_get(url):
            resp = mock.Mock()
            resp.status_code = 200
            json_bytes = json.dumps(original_key).encode('utf-8')
            resp.json.return_value = [
                {'Value': base64.b64encode(json_bytes), 'Key': 'ghost/baz'}
            ]
            return resp

        with mock.patch.object(storage._session, 'get',
                               side_effect=mock_get) as m:
            retrieved_keys = storage.list()

        m.assert_called_with('http://127.0.0.1:8500/v1/kv/ghost/?recurse')
        assert retrieved_keys == [original_key]

    def test_put(self):
        """Putting takes the key_name from the passed in dict."""
        storage = ghost.ConsulStorage()
        original_key = {'name': 'the_name', 'value': 42}

        def mock_put(url, json):
            # assert here, because using `assert_called_with` would
            # make an assumption if the args were passed positionally or by
            # name
            assert url == 'http://127.0.0.1:8500/v1/kv/ghost/the_name'
            assert json == original_key

            resp = mock.Mock()
            resp.status_code = 200
            resp.json.return_value = json['name']
            return resp

        with mock.patch.object(storage._session, 'put',
                               side_effect=mock_put) as m:
            key_id = storage.put(original_key)

        assert len(m.mock_calls) == 1
        assert key_id == 'the_name'

        storage_tester.put(key_id)

    def test_delete(self):
        """Deleting an existing key simply returns True"""
        storage = ghost.ConsulStorage()

        def mock_delete(url):
            return mock.Mock(status_code=200)

        def mock_get(url):
            return mock.Mock(status_code=404)

        with mock.patch.object(storage._session, 'get',
                               side_effect=mock_get) as m:
            with mock.patch.object(storage._session, 'delete',
                                   side_effect=mock_delete) as m:
                deleted = storage.delete('to_delete')

        m.assert_called_with('http://127.0.0.1:8500/v1/kv/ghost/to_delete')
        assert deleted

    def test_delete_404(self):
        """Deleting a nonexisting key returns False"""
        storage = ghost.ConsulStorage()

        def mock_delete(url):
            return mock.Mock(status_code=404)

        def mock_get(url):
            return mock.Mock(status_code=404)

        with mock.patch.object(storage._session, 'get',
                               side_effect=mock_get) as m:
            with mock.patch.object(storage._session, 'delete',
                                   side_effect=mock_delete) as m:
                deleted = storage.delete('to_delete')

        m.assert_called_with('http://127.0.0.1:8500/v1/kv/ghost/to_delete')
        assert deleted


class HvacClient(object):
    def __init__(self, url, token=None, cert=None):
        self.store = {}

    def list(self, path='ghost'):
        """
        {
            'lease_id': '',
            'warnings': None,
            'wrap_info': None,
            'auth': None,
            'lease_duration': 0,
            'request_id': 'a0d5c74c-fe92-90ba-f73a-95b08cd4ec61',
            'data': {
                'keys': ['aws', 'aws2', 'awss', 'gcp', 'stored_passphrase']
            },
            'renewable': False
        }
        """
        return {
            'data': {
                'keys': self.store.keys()
            }
        } if self.store.keys() else None

    def read(self, path):
        """
        {
            'lease_id': '',
            'warnings': None,
            'wrap_info': None,
            'auth': None,
            'lease_duration': 2592000,
            'request_id': 'accdb21c-5b70-06e7-c38a-4a589e9dd5d3',
            'data': {
                'uid': '0c5ce284-1300-4892-9e00-15e27e3db0d2',
                'created_at': '2016-10-06 08:29:53',
                'modified_at': '2016-10-06 08:29:53',
                'value': 'encrypted_value',
                'name': 'aws',
                'metadata': None,
                'description': None
            },
            'renewable': False
        }
        """
        return self.store.get(os.path.basename(path))

    def write(self, path, **kwargs):
        key = {'data': dict(**kwargs), 'vault_metadata': 'x'}
        self.store[os.path.basename(path)] = key

    def delete(self, path):
        self.store.pop(os.path.basename(path))


class TestVaultStorage:
    def test_missing_requirement(self):
        with mock.patch('ghost.HVAC_EXISTS', False):
            with pytest.raises(ImportError):
                ghost.VaultStorage()

    def test_init_no_token(self):
        with pytest.raises(ghost.GhostError) as ex:
            ghost.VaultStorage()
        assert 'The `VAULT_TOKEN` env var' in str(ex)

    def test_key_path(self):
        storage = ghost.VaultStorage(token='a')
        # This might seem like a weird test, but we generally just wanna make
        # sure that the path always looks like this.
        assert storage._key_path('my_key') == 'secret/ghost/my_key'

    def test_is_initialized(self):
        storage = ghost.VaultStorage(token='a')
        assert storage.is_initialized is True
        storage_tester.is_initialized(storage.is_initialized)

    @mock.patch('hvac.Client', HvacClient)
    def test_put_get_delete(self):
        storage = ghost.VaultStorage(token='a')
        key_id = storage.put(BASE_TEST_KEY)
        storage_tester.put(key_id)

        expected_key = BASE_TEST_KEY.copy()
        expected_key['metadata'] = {'vault_metadata': 'x'}
        retrieved_key = storage.get(BASE_TEST_KEY['name'])
        assert expected_key == retrieved_key
        storage_tester.get(retrieved_key)

        result = storage.delete(BASE_TEST_KEY['name'])
        storage_tester.delete(result)

        key = storage.get(BASE_TEST_KEY['name'])
        storage_tester.get_nonexisting_key(key)

    @mock.patch('hvac.Client', HvacClient)
    def test_empty_list(self):
        storage = ghost.VaultStorage(token='a')
        key_list = storage.list()
        storage_tester.empty_list(key_list)

    @mock.patch('hvac.Client', HvacClient)
    def test_list(self):
        storage = ghost.VaultStorage(token='a')
        expected_key = BASE_TEST_KEY.copy()
        expected_key['metadata'] = {'vault_metadata': 'x'}
        storage.put(BASE_TEST_KEY)
        key_list = storage.list()
        assert len(key_list) == 1
        assert key_list[0] == expected_key
        storage_tester.list(key_list)


class ESIndices(object):
    def __init__(self):
        self.index_exists = False

    def exists(self, index):
        return self.index_exists

    def create(self, index, ignore):
        """
        {
            u'status': 400,
            u'error': {
                u'index': u'ghost',
                u'root_cause': [
                    {
                        u'index': u'ghost',
                        u'reason': u'already exists',
                        u'type': u'index_already_exists_exception'
                    }
                ],
                u'type': u'index_already_exists_exception',
                u'reason': u'already exists'
            }
        }
        """
        self.index_exists = True


class ElasticsearchClient(object):

    def __init__(self,
                 db_path='x',
                 index='ghost',
                 use_ssl=False,
                 verify_certs=False,
                 ca_certs='',
                 client_cert='',
                 client_key=''):
        self.store = {}
        self.indices = ESIndices()

    def search(self, body, filter_path, **kwargs):
        """
         {
            u'hits': {
                u'hits': [
                    {
                        u'_id': u'AVewADAWUnUKEMeMQ4QB',
                        u'_source': {
                            u'description': None,
                            u'created_at':
                            u'2016-10-10 22:09:44',
                            u'modified_at':
                            u'2016-10-10 22:09:44',
                            u'value': u'the_value',
                            u'name': u'aws',
                            u'uid': u'7a1caa7d-14d4-4045-842c-66adf22190b5',
                            u'metadata': None
                        }
                    },
                ]
            }
        }
        """
        if 'match_all' in body['query']:
            items = list(self.store.items())
            for name, key in items:
                return self.store[name]
            else:
                return {'hits': {'hits': []}}
        else:
            return self.store.get(body['query']['match']['name'])

    def index(self, body, **kwargs):
        key = {'hits': {'hits': [{'_source': body, '_id': 'mock_id'}]}}
        self.store[body['name']] = key
        return key['hits']['hits'][0]

    def delete(self, id, refresh, **kwargs):
        items = list(self.store.items())
        for name, key in items:
            if key['hits']['hits'][0]['_id'] == id:
                del self.store[name]


class TestElasticsearchStorage:
    def test_missing_requirement(self):
        with mock.patch('ghost.ES_EXISTS', False):
            with pytest.raises(ImportError):
                ghost.ElasticsearchStorage()

    @mock.patch('elasticsearch.Elasticsearch', ElasticsearchClient)
    def test_is_initialized(self):
        storage = ghost.ElasticsearchStorage()
        assert storage.is_initialized is False
        # Just means that init has been called.
        # We assume that that create function in the es API actually works.
        storage.init()
        assert storage.is_initialized is True
        storage_tester.is_initialized(storage.is_initialized)

    @mock.patch('elasticsearch.Elasticsearch', ElasticsearchClient)
    def test_put_get_delete(self):
        storage = ghost.ElasticsearchStorage()
        key_id = storage.put(BASE_TEST_KEY)
        storage_tester.put(key_id)
        retrieved_key = storage.get(BASE_TEST_KEY['name'])
        assert BASE_TEST_KEY == retrieved_key
        storage_tester.get(retrieved_key)

        result = storage.delete(BASE_TEST_KEY['name'])
        storage_tester.delete(result)

        key = storage.get(BASE_TEST_KEY['name'])
        storage_tester.get_nonexisting_key(key)

    @mock.patch('elasticsearch.Elasticsearch', ElasticsearchClient)
    def test_delete_non_existing_key(self):
        storage = ghost.ElasticsearchStorage()
        assert storage.delete('non_existing_key') is True

    @mock.patch('elasticsearch.Elasticsearch', ElasticsearchClient)
    def test_empty_list(self):
        storage = ghost.ElasticsearchStorage()
        key_list = storage.list()
        storage_tester.empty_list(key_list)

    @mock.patch('elasticsearch.Elasticsearch', ElasticsearchClient)
    def test_list(self):
        storage = ghost.ElasticsearchStorage()
        storage.put(BASE_TEST_KEY)
        key_list = storage.list()
        assert len(key_list) == 1
        assert key_list[0] == BASE_TEST_KEY
        storage_tester.list(key_list)


@pytest.fixture
def test_stash(stash_path):
    log_dir = tempfile.mkdtemp()
    ghost.AUDIT_LOG_FILE_PATH = \
        os.path.join(log_dir, 'audit.log')
    stash = ghost.Stash(ghost.TinyDBStorage(stash_path))
    stash.init()
    yield stash
    shutil.rmtree(log_dir, ignore_errors=True)


def assert_stash_initialized(stash_path):
    db = get_tinydb(stash_path)
    assert '1' in db
    assert db['1']['name'] == 'stored_passphrase'
    assert len(db) == 1


def assert_key_put(db, dont_verify_value=False):
    key = db['2']
    assert key['name'] == 'aws'
    if not dont_verify_value:
        assert key['value'] == {'key': 'value'}
    assert key['description'] is None
    assert key['metadata'] is None


def assert_in_log(message_like):
    with open(ghost.AUDIT_LOG_FILE_PATH) as audit_log_file:
        assert message_like in audit_log_file.read()


class TestStash:
    def test_init(self, stash_path):
        log_dir = tempfile.mkdtemp()
        ghost.AUDIT_LOG_FILE_PATH = \
            os.path.join(log_dir, 'audit.log')

        storage = ghost.TinyDBStorage(stash_path)
        stash = ghost.Stash(storage, TEST_PASSPHRASE)
        passphrase = stash.init()
        assert stash._storage == storage
        assert stash.passphrase == TEST_PASSPHRASE
        assert passphrase == TEST_PASSPHRASE
        assert_stash_initialized(stash_path)

        shutil.rmtree(log_dir, ignore_errors=True)

    def test_broken_is_initialized(self, test_cli_stash):
        assert test_cli_stash.is_initialized is True
        test_cli_stash._storage.delete('stored_passphrase')
        assert test_cli_stash.is_initialized is False

    def test_generated_passphrase(self, test_stash):
        assert_stash_initialized(test_stash._storage.db_path)

    def test_put(self, test_stash):
        key_id = test_stash.put('aws', {'key': 'value'})
        db = get_tinydb(test_stash._storage.db_path)
        db[str(key_id)]['value'] = \
            test_stash._decrypt(db[str(key_id)]['value'])
        assert_key_put(db)
        assert_in_log('PUT')
        storage_tester.put(key_id)

    def test_put_no_value_provided(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('new-key')
        assert 'You must provide a value for new keys' in str(ex.value)

    def test_put_value_not_dict(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', 'string')
        assert 'Value must be of type dict' in str(ex.value)

    def test_put_with_metadata_and_description(self, test_stash):
        id = test_stash.put(
            'aws',
            {'key': 'value'},
            metadata={'meta': 'data'},
            description='my_key')
        db = get_tinydb(test_stash._storage.db_path)
        key = db[str(id)]
        assert key['metadata'] == {'meta': 'data'}
        assert key['description'] == 'my_key'

    def test_put_modify_existing_key(self, test_stash):
        """On top of checking that a key can be modified, it also checks that
        the created_at field stays the same while the modified date changes
        """
        test_stash.put('aws', {'key': 'value'})
        key = test_stash.get('aws')
        created_at = key['created_at']
        modified_at = key['modified_at']
        assert key['value'] == {'key': 'value'}
        time.sleep(1)
        test_stash.put('aws', {'modified_key': 'modified_value'}, modify=True)
        key = test_stash.get('aws')
        assert key['value'] == {'modified_key': 'modified_value'}
        assert key['created_at'] == created_at
        assert key['modified_at'] != modified_at
        test_stash.put('aws', description='modified', modify=True)
        key = test_stash.get('aws')
        assert key['value'] == {'modified_key': 'modified_value'}
        assert key['description'] == 'modified'

        assert_in_log('MODIFY')

    def test_put_modify_nonexisting_key(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', {'key': 'value'}, modify=True)
        assert "therefore cannot be modified" in str(ex.value)

    def test_put_add_nonexisting_key(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', {'key': 'value'}, modify=True)
        assert "therefore cannot be modified" in str(ex.value)

    def test_put_existing_key_no_modify(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', {'key': 'value'})
        assert "Use the modify flag to overwrite" in str(ex.value)

    def test_put_add_to_existing_key(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        test_stash.put('aws', {'key2': 'value2'}, add=True)
        key = test_stash.get('aws')
        assert key['value'] == {'key': 'value', 'key2': 'value2'}
        assert_in_log('MODIFY')

    def test_put_add_to_existing_key_overwrite_value(self, test_stash):
        test_stash.put('aws', {'key': 'value', 'key2': 'value2'})
        test_stash.put('aws', {'key': 'value2'}, add=True)
        key = test_stash.get('aws')
        assert key['value'] == {'key': 'value2', 'key2': 'value2'}
        assert_in_log('MODIFY')

    def test_get(self, test_stash):
        def _test_key(key):
            assert isinstance(key, dict)
            assert 'name' in key
            assert 'value' in key
            assert 'description' in key
            assert 'modified_at' in key
            assert 'created_at' in key
            assert 'uid' in key
        test_stash.put('aws', {'key': 'value'})
        key = test_stash.get('aws')
        _test_key(key)
        # Get again, just to verify
        key = test_stash.get('aws')
        _test_key(key)

        assert_in_log('GET')

    def test_get_nonexisting_key(self, test_stash):
        key = test_stash.get('aws')
        assert key is None

    def test_get_no_decrypt(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key = test_stash.get('aws', decrypt=False)
        assert key['value'] != {'key': 'value'}

    def test_delete(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key = test_stash.get('aws')
        assert key is not None
        test_stash.delete('aws')
        key = test_stash.get('aws')
        assert key is None

        assert_in_log('DELETE')

    def test_delete_nonexisting_key(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.delete('aws')
        assert 'Key `aws` not found' in str(ex.value)

    def test_delete_failed(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        test_stash._storage.delete = lambda _: False
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.delete('aws')
        assert 'Failed to delete' in str(ex.value)

    def test_list(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert key_list[0] == 'aws'
        assert 'stored_passphrase' not in key_list

        assert_in_log('LIST')

    def test_empty_list(self, test_stash):
        key_list = test_stash.list()
        assert len(key_list) == 0

    def test_purge(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key_list = test_stash.list()
        assert len(key_list) == 1
        test_stash.purge(force=True)
        key_list = test_stash.list()
        assert len(key_list) == 0
        stored_passphrase_key = test_stash.get('stored_passphrase')
        assert stored_passphrase_key is not None

        assert_in_log('PURGE')

    def test_purge_no_force(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.purge()
        assert 'The `force` flag must be provided' in str(ex.value)

    def test_export_to_file(self, test_stash, temp_file_path):
        test_stash.put('aws', {'key': 'value'})
        keys = test_stash.export(temp_file_path)
        with open(temp_file_path) as exported_stash_file:
            keys_from_file = json.loads(exported_stash_file.read())
        assert keys[0]['name'] == 'aws'
        assert keys_from_file[0]['name'] == 'aws'

    def test_export_no_keys(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.export(temp_file_path)
        assert 'There are no keys to export' in str(ex.value)

    def test_load(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        keys = test_stash.export()
        assert keys[0]['name'] == 'aws'
        test_stash.purge(force=True)
        test_stash.load(test_stash.passphrase, keys)
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert 'aws' in key_list

    def test_load_from_file(self, test_stash, temp_file_path):
        test_stash.put('aws', {'key': 'value'})
        test_stash.export(temp_file_path)

        test_stash.purge(force=True)
        keys = test_stash.list()
        assert len(keys) == 0
        test_stash.load(test_stash.passphrase, key_file=temp_file_path)
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert 'aws' in key_list

    def test_load_no_keys_no_file_provided(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.load('stub_passphrase')
        assert 'You must either provide a path to an exported' in str(ex.value)

    def test_migrate(self, test_stash, temp_file_path):
        """Test migration between a tinydb and sqlite stashes

        We setup a stash with two keys, setup an empty destination stash
        and then migrate from one to the other.
        """
        migration_params, destination_stash = _create_migration_env(
            test_stash, temp_file_path)
        ghost.migrate(**migration_params)
        assert len(destination_stash.list()) == 3
        assert 'aws' in destination_stash.list()
        assert 'gcp' in destination_stash.list()
        assert 'openstack' in destination_stash.list()
        # Verify that not only were the keys loaded, their values are correct.
        # To understand why the two indices of the lists below make sense,
        # see _create_migration_env where the keys are put.
        example_src_key = test_stash.get(test_stash.list()[0])
        example_dst_key = destination_stash.get(destination_stash.list()[1])
        assert example_src_key['value'] == example_dst_key['value']

    # TODO: Test lock here also
    def test_lock_an_already_locked_key(self, test_stash):
        test_stash.put('aws', {'key': 'value'}, lock=True)
        assert test_stash.is_locked('aws') is True
        test_stash.lock('aws')
        assert test_stash.is_locked('aws') is True

    def test_unlock_an_already_unlocked_key(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        assert test_stash.is_locked('aws') is False
        test_stash.unlock('aws')
        assert test_stash.is_locked('aws') is False

    def test_list_filtered_matches(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        test_stash.put('aws-2', {'key': 'value'})
        test_stash.put('abws-2', {'key': 'value'})
        test_stash.put('gcp-3', {'key': 'value'})

        result = test_stash.list('aws')
        assert len(result) == 2
        assert 'aws' in result
        assert 'aws-2' in result

    def test_list_closest_matches(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        test_stash.put('aws-2', {'key': 'value'})
        test_stash.put('abws-2', {'key': 'value'})
        test_stash.put('gcp-3', {'key': 'value'})

        # this has a 0.5 cutoff
        result = test_stash.list('~aws')
        assert len(result) == 3
        assert 'aws' in result
        assert 'aws-2' in result
        assert 'abws-2' in result

        # should return two matches instead of three
        # as the cutoff is 0.7 instead of the default 0.5.
        result = test_stash.list('~aws', cutoff=0.7)
        assert len(result) == 2
        assert 'aws' in result
        assert 'aws-2' in result

        # should return two matches instead of three. one is the
        # original one and one is a close match according to the max
        result = test_stash.list('~aws', max_suggestions=2)
        assert len(result) == 2
        assert 'aws' in result
        assert 'aws-2' in result

    def test_list_locked_closest_matches(self, test_stash):
        test_stash.put('aws', {'key': 'value'}, lock=True)
        test_stash.put('aws-2', {'key': 'value'})
        test_stash.put('abws-2', {'key': 'value'}, lock=True)
        test_stash.put('gcp-3', {'key': 'value'})

        result = test_stash.list('~aws', locked_only=True)
        assert len(result) == 2
        assert 'aws' in result
        assert 'abws-2' in result

    def test_list_locked_filtered_matches(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        test_stash.put('aws-2', {'key': 'value'}, lock=True)
        test_stash.put('abws-2', {'key': 'value'})
        test_stash.put('gcp-3', {'key': 'value'})

        result = test_stash.list('aws', locked_only=True)
        assert len(result) == 1
        assert 'aws-2' in result


def _create_migration_env(test_stash, temp_file_path):
        test_stash.put('aws', {'a': 'b'})
        test_stash.put('gcp', {'c': 'd'})

        source_passphrase = test_stash.passphrase
        test_sqlite_path = 'sqlite:///{0}'.format(temp_file_path)
        destination_storage = ghost.SQLAlchemyStorage(test_sqlite_path)
        destination_stash = ghost.Stash(destination_storage)
        destination_passphrase = destination_stash.init()
        destination_stash.put('openstack', {'e': 'f'})
        assert len(destination_stash.list()) == 1
        assert 'openstack' in destination_stash.list()
        migration_params = dict(
            src_path=test_stash._storage.db_path,
            src_passphrase=source_passphrase,
            src_backend='tinydb',
            dst_path=test_sqlite_path,
            dst_passphrase=destination_passphrase,
            dst_backend='sqlalchemy')
        return migration_params, destination_stash


@pytest.fixture
def test_cli_stash(stash_path):
    log_dir = tempfile.mkdtemp()
    ghost.GHOST_HOME = tempfile.mkdtemp()
    shutil.rmtree(ghost.GHOST_HOME, ignore_errors=True)
    ghost.AUDIT_LOG_FILE_PATH = \
        os.path.join(log_dir, 'audit.log')
    fd, passphrase_file_path = tempfile.mkstemp()
    os.close(fd)
    os.remove(passphrase_file_path)
    ghost.PASSPHRASE_FILENAME = passphrase_file_path
    _invoke('init_stash "{0}"'.format(stash_path))
    os.environ['GHOST_STASH_PATH'] = stash_path
    with open(passphrase_file_path) as passphrase_file:
        passphrase = passphrase_file.read()
    os.remove(passphrase_file_path)
    os.environ['GHOST_PASSPHRASE'] = passphrase
    os.environ['GHOST_BACKEND_TYPE'] = 'tinydb'
    yield ghost.Stash(ghost.TinyDBStorage(stash_path), passphrase)
    try:
        os.remove(passphrase_file_path)
        os.remove(stash_path)
        shutil.rmtree(log_dir, ignore_errors=True)
        shutil.rmtree(ghost.GHOST_HOME, ignore_errors=True)
    except:
        pass


def _print_command(cmd, shell):
    raise RuntimeError('CMD: {0}'.format(cmd))


def _mock_subprocess_check_call(cmd, shell):
    raise subprocess.CalledProcessError(1, cmd)


def _mock_write_passphrase_file(passphrase):
    raise OSError('Expected OSError')


class TestCLI:
    @staticmethod
    def _assert_bad_passphrase(result):
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'The passphrase provided is invalid' in result.output

    def test_invoke_main(self):
        result = _invoke('main')
        assert 'Usage: main [OPTIONS] COMMAND [ARGS]' in result.output

    def test_init(self, test_cli_stash):
        assert_stash_initialized(test_cli_stash._storage.db_path)

    def test_init_already_initialized(self, test_cli_stash):
        result = _invoke('init_stash "{0}" -p {1}'.format(
            os.environ['GHOST_STASH_PATH'], test_cli_stash.passphrase))
        assert 'Stash already initialized' in result.output
        assert result.exit_code == 0

    @pytest.mark.skipif(os.name == 'nt', reason='Irrelevant on Windows')
    @mock.patch('ghost._write_passphrase_file', _mock_write_passphrase_file)
    def test_init_permission_denied_on_passphrase(self):
        fd, temp_file = tempfile.mkstemp()
        os.close(fd)
        os.remove(temp_file)
        result = _invoke('init_stash "{0}" -p whatever'.format(temp_file))
        assert 'Expected OSError' in str(result.exception)
        assert 'Removing stale stash and passphrase' in str(result.output)
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        # Since the invocation process both creates and deletes the stash
        # in case of failure, there's no way to verify that the file
        # exists in the middle of the test. This is a reasonable assumption
        # though as otherwise the removal statement will not be covered.
        assert not os.path.isfile(temp_file)

    @pytest.mark.skipif(os.name == 'nt', reason='Irrelevant on Windows')
    def test_init_permission_denied_on_stash(self, test_cli_stash):
        result = _invoke('init_stash "/x" -p {0}'.format(
            test_cli_stash.passphrase))
        assert 'Permission denied' in str(result.exception)
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1

    def test_put(self, test_cli_stash):
        _invoke('put_key aws key=value')
        db = get_tinydb(test_cli_stash._storage.db_path)
        db['2']['value'] = test_cli_stash._decrypt(db['2']['value'])
        assert_key_put(db)

    def test_put_bad_passphrase(self, test_cli_stash):
        result = _invoke('put_key aws key=value -p {0}'.format('bad'))
        self._assert_bad_passphrase(result)

    @pytest.mark.skipif(os.name == 'nt', reason='TODO why fails on nt')
    def test_put_not_initialized(self):
        # TODO: test this on all backends
        # TODO: check on windows if bad passphrase is provided
        result = _invoke('put_key aws key=value')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Stash not initialized' in result.output

    def test_put_no_modify_or_add(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('put_key aws key=value')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `aws` already exists' in result.output

    def test_modify_locked(self, test_cli_stash):
        _invoke('put_key aws key=value --lock')
        result = _invoke('put_key aws key=other_value --modify')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `aws` is locked' in result.output
        assert _invoke('get_key aws key').output.strip() == 'value'

    def test_put_add_nonexisting_key(self, test_cli_stash):
        result = _invoke('put_key aws key=value --add')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert "Key `aws` doesn't exist" in result.output

    def test_get(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('get_key aws')
        key = get_tinydb(test_cli_stash._storage.db_path)['2']
        key['value'] = test_cli_stash._decrypt(key['value'])
        pretty_key = ghost._prettify_dict(key)
        pretty_key_parts = pretty_key.splitlines()
        for part in pretty_key_parts:
            assert part in result.output

    def test_get_bad_passphrase(self, test_cli_stash):
        result = _invoke('get_key aws -p {0}'.format('bad'))
        self._assert_bad_passphrase(result)

    def test_get_jsonified(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('get_key aws -j')
        key = get_tinydb(test_cli_stash._storage.db_path)['2']
        key['value'] = test_cli_stash._decrypt(key['value'])
        assert json.loads(result.output) == key

    def test_get_single_value(self, test_cli_stash):
        _invoke('put_key aws key1=value1 key2=value2')
        # Don't need to pass -j, it should return it bare anyway
        result = _invoke('get_key aws key2')
        assert result.output == 'value2\n'
        # But if passed, should result in the same output
        result = _invoke('get_key aws key2 -j')
        assert result.output == 'value2\n'

    def test_get_single_nonexisting_value(self, test_cli_stash):
        _invoke('put_key aws key1=value1 key2=value2')
        # Don't need to pass -j, it should return it bare anyway
        result = _invoke('get_key aws key3')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Value name `key3` could not be found' in result.output

    def test_get_single_value_with_no_decrypt_flag(self):
        result = _invoke('get_key aws specific_value --no-decrypt')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'VALUE_NAME cannot be used in conjuction' in result.output

    def test_get_nonexisting_value(self, test_cli_stash):
        result = _invoke('get_key non-existing-key')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `non-existing-key` not found' in result.output

    def test_delete_key(self, test_cli_stash):
        _invoke('put_key aws key=value')
        db = get_tinydb(test_cli_stash._storage.db_path)
        assert len(db) == 2
        assert db['2']['name'] == 'aws'
        _invoke('delete_key aws')
        db = get_tinydb(test_cli_stash._storage.db_path)
        assert len(db) == 1
        assert db['1']['name'] == 'stored_passphrase'

    def test_delete_bad_passphrase(self, test_cli_stash):
        result = _invoke('delete_key aws -p {0}'.format('bad'))
        self._assert_bad_passphrase(result)

    def test_delete_stored_passphrase(self, test_cli_stash):
        result = _invoke('delete_key stored_passphrase')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert '`stored_passphrase` is a reserved' in result.output

    def test_delete_nonexisting_key(self, test_cli_stash):
        result = _invoke('delete_key aws')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `aws` not found' in result.output

    def test_list(self, test_cli_stash):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        result = _invoke('list_keys')
        assert '  - aws' in result.output
        assert '  - gcp' in result.output

    def test_list_locked_only(self, test_cli_stash):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value --lock')
        result = _invoke('list_keys')
        assert '  - aws' in result.output
        assert '  - gcp' in result.output
        result = _invoke('list_keys --locked')
        assert '  - aws' not in result.output
        assert '  - gcp' in result.output

    def test_list_bad_passphrase(self, test_cli_stash):
        result = _invoke('list_keys -p {0}'.format('bad'))
        self._assert_bad_passphrase(result)

    def test_list_jsonified(self, test_cli_stash):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        result = _invoke('list_keys -j')
        assert json.loads(result.output) == test_cli_stash.list()

    def test_list_while_stash_is_empty(self, test_cli_stash):
        result = _invoke('list_keys')
        assert 'The stash is empty' in result.output

    def test_purge(self, test_cli_stash):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        _invoke('purge_stash -f')
        assert len(test_cli_stash.list()) == 0

    def test_purge_no_keys(self, test_cli_stash):
        result = _invoke('purge_stash -f')
        assert result.exit_code == 0

    def test_purge_no_force(self, test_cli_stash):
        result = _invoke('purge_stash')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'The `force` flag must be provided to perform a stash purge' \
            in result.output

    def test_export(self, test_cli_stash, temp_file_path):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        _invoke('export_keys -o "{0}"'.format(temp_file_path))
        with open(temp_file_path) as exported_stash:
            data = json.loads(exported_stash.read())
        assert data[0]['name'] == 'aws'
        assert data[0]['value'] != {'key': 'value'}
        assert data[1]['name'] == 'gcp'

    def test_export_no_keys(self, test_cli_stash, temp_file_path):
        result = _invoke('export_keys -o "{0}"'.format(temp_file_path))
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'There are no keys to export' in result.output

    def test_load(self, test_cli_stash, temp_file_path):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        key_list = test_cli_stash.list()
        _invoke('export_keys -o "{0}"'.format(temp_file_path))
        _invoke('purge_stash -f')
        result = _invoke('list_keys -j')
        assert json.loads(result.output.strip('\n')) == []
        _invoke('load_keys "{0}" --origin-passphrase {1}'.format(
            temp_file_path, test_cli_stash.passphrase))
        result = _invoke('list_keys -j')
        assert json.loads(result.output) == key_list

    def test_fail_init_two_stashes_passphrase_file_exists(self,
                                                          stash_path,
                                                          temp_file_path):
        _invoke('init_stash "{0}"'.format(stash_path))
        result = _invoke('init_stash "{0}" -b sqlalchemy'.format(
            temp_file_path))

        assert 'Overwriting might prevent you' in result.output
        assert result.exit_code == 1

    def test_migrate(self, test_stash, temp_file_path):
        migration_params, destination_stash = _create_migration_env(
            test_stash, temp_file_path)
        _invoke(
            'migrate_stash "{src_path}" "{dst_path}" '
            '-sp {src_passphrase} -dp {dst_passphrase} '
            '-sb {src_backend} -db {dst_backend}'.format(**migration_params))
        current_keys = destination_stash.list()
        assert len(current_keys) == 3
        assert 'aws' in current_keys
        assert 'gcp' in current_keys
        assert 'openstack' in current_keys

    def test_fail_migrate(self, test_stash, temp_file_path):
        migration_params, destination_stash = _create_migration_env(
            test_stash, temp_file_path)
        fd, invalid_stash = tempfile.mkstemp()
        os.close(fd)
        try:
            result = _invoke(
                'migrate_stash "{0}" "{dst_path}" '
                '-sp {src_passphrase} -dp {dst_passphrase} '
                '-sb {src_backend} -db {dst_backend}'.format(
                    invalid_stash, **migration_params))
        finally:
            try:
                os.remove(invalid_stash)
            except:
                pass
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'There are no keys to export' in result.output

    def test_lock(self, test_cli_stash):
        _invoke('put_key aws key=value')
        assert 'aws' in json.loads(_invoke('list_keys -j').output)

        _invoke('lock_key aws')
        result = _invoke('delete_key aws')
        assert 'Key `aws` is locked' in result.output
        assert 'aws' in json.loads(_invoke('list_keys -j').output)
        _invoke('unlock_key aws')
        _invoke('delete_key aws')
        assert 'aws' not in _invoke('list_keys -j').output

    def test_lock_by_put(self, test_cli_stash):
        _invoke('put_key aws key=value --lock')
        result = _invoke('delete_key aws')
        assert 'Key `aws` is locked' in result.output
        assert 'aws' in json.loads(_invoke('list_keys -j').output)

    def test_lock_non_existing_key(self, test_cli_stash):
        assert 'aws' not in json.loads(_invoke('list_keys -j').output)
        result = _invoke('lock_key aws')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `aws` not found' in result.output

    def test_unlock_non_existing_key(self, test_cli_stash):
        assert 'aws' not in json.loads(_invoke('list_keys -j').output)
        result = _invoke('unlock_key aws')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key `aws` not found' in result.output

    @mock.patch('ghost.subprocess.check_call', _print_command)
    @pytest.mark.skipif(os.name == 'nt', reason='TODO')
    def test_ssh_with_key(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' ssh_key='123' -t ssh")
        result = _invoke('ssh server')
        assert 'ssh' in str(result.exception)
        assert 'ubuntu@10.10.1.10' in str(result.exception)
        assert '-i' in str(result.exception)
        assert '/tmp/' in str(result.exception)

    @mock.patch('ghost.subprocess.check_call', _print_command)
    def test_ssh_with_key_path(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' "
                "ssh_key_path='/path/to/key' -t ssh")
        result = _invoke('ssh server')
        expected_command = 'ssh -i /path/to/key ubuntu@10.10.1.10'
        assert expected_command in str(result.exception)

    # @pytest.mark.skipif(os.environ.get('CI') is None, reason='Because I can')
    @mock.patch('ghost.subprocess.check_call', _mock_subprocess_check_call)
    def test_ssh_failed(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' "
                "ssh_key_path='/path/to/key' -t ssh")
        result = _invoke('ssh server')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1

    def test_ssh_with_non_ssh_type_key(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' "
                "ssh_key_path='/path/to/key'")
        result = _invoke('ssh server')
        assert type(result.exception) == SystemExit
        assert 'Must provide key of type `ssh`' in result.output

    def test_ssh_non_existing_key(self, test_cli_stash):
        result = _invoke('ssh server')
        assert type(result.exception) == SystemExit
        assert 'Key `server` not found' in result.output

    @mock.patch('ghost.subprocess.check_call', _print_command)
    def test_ssh_with_proxy_key_path(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' "
                "ssh_key_path='/path/to/key' -t ssh "
                "proxy='ubuntu@1.1.1.1' proxy_key_path='/path/to/proxy/key'")
        result = _invoke('ssh server')
        expected_command = (
            'ssh -i /path/to/key ubuntu@10.10.1.10 '
            '-o ProxyCommand="ssh -i /path/to/proxy/key ubuntu@1.1.1.1 '
            'nc 10.10.1.10 22" -o IdentityFile="/path/to/proxy/key"'
        )
        assert expected_command in str(result.exception)

    @mock.patch('ghost.subprocess.check_call', _print_command)
    @pytest.mark.skipif(os.name == 'nt', reason='TODO')
    def test_ssh_with_proxy_key(self, test_cli_stash):
        _invoke("put_key server conn='ubuntu@10.10.1.10' "
                "ssh_key_path='/path/to/key' -t ssh "
                "proxy='ubuntu@1.1.1.1' proxy_key='123'")
        result = _invoke('ssh server')
        assert 'ssh -i /path/to/key ubuntu@10.10.1.10' in str(result.exception)
        assert '-o ProxyCommand="ssh -i /tmp' in str(result.exception)
        assert 'ubuntu@1.1.1.1 nc 10.10.1.10 22"' in str(result.exception)
        assert '-o IdentityFile="/tmp/' in str(result.exception)

    @mock.patch('ghost.subprocess.check_call', _print_command)
    def test_ssh_with_key_path_and_extension(self, test_cli_stash):
        _invoke("""put_key server conn='ubuntu@10.10.1.10'
                ssh_key_path='/path/to/key' -t ssh extend='-o Key="Value"'""")
        result = _invoke('ssh server')
        expected_command = \
            'ssh -i /path/to/key ubuntu@10.10.1.10 -o Key="Value"'
        assert expected_command in str(result.exception)


class TestMultiStash:
    # TODO: Test that migrate works when using multi-stash mode
    # TODO: Test that all CLI commands work when using multi-stash mode
    def test_parse_stash_path_string(self):
        stash_path = '/etc/my-stash.json[stash1]'
        assert ghost._parse_path_string(stash_path) == {
            'db_path': '/etc/my-stash.json',
            'stash_name': 'stash1'
        }

    def test_parse_stash_path_string_no_stash_name(self):
        stash_path = '/etc/my-stash.json'
        assert ghost._parse_path_string(stash_path) == {
            'db_path': '/etc/my-stash.json',
            'stash_name': 'ghost'
        }

    def test_parse_stash_path_string_no_stash_name_in_brackets(self):
        stash_path = '/etc/my-stash.json[]'
        assert ghost._parse_path_string(stash_path) == {
            'db_path': '/etc/my-stash.json',
            'stash_name': 'ghost'
        }


class TestTypeSystem(object):
    def test_put_key_with_missing_required_value(self, test_stash):
        value = {'ssh_key': '...'}

        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('server', value=value, key_type='ssh')
        assert 'Must provide value' in str(ex.value)

    def test_put_key_with_missing_oneof_value(self, test_stash):
        value = {'conn': '...'}

        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('server', value=value, key_type='ssh')
        assert 'Must provide one of' in str(ex.value)

    def test_put_key_with_too_many_oneof_values(self, test_stash):
        value = {'conn': 'x', 'ssh_key': '...', 'ssh_key_path': '...'}

        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('server', value=value, key_type='ssh')
        assert 'Must provide one of' in str(ex.value)

    def test_list_key_of_type(self, test_stash):
        test_stash.put('some-key', value={'a': 'b'})

        value = {'conn': 'ubuntu@10.10.1.10', 'ssh_key': '...'}
        test_stash.put('server', value=value, key_type='ssh')
        key_list = test_stash.list(key_type='ssh')
        assert key_list == ['server']
