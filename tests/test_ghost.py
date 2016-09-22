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
import shutil
import tempfile

import pytest
import click.testing as clicktest

import ghost


def _invoke(command):
    cfy = clicktest.CliRunner()

    lexed_command = command if isinstance(command, list) \
        else shlex.split(command)
    func = lexed_command[0]
    params = lexed_command[1:]
    return cfy.invoke(getattr(ghost, func), params)


class TestUtils:
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


def _create_temp_file():
    fd, temp_file = tempfile.mkstemp()
    print('PATH: {0}'.format(temp_file))
    os.remove(temp_file)
    os.close(fd)
    return temp_file


@pytest.fixture
def stash_path():
    temp_file = _create_temp_file()
    yield temp_file
    if os.path.isfile(temp_file):
        os.remove(temp_file)


@pytest.fixture
def temp_file_path():
    temp_file = _create_temp_file()
    yield temp_file
    if os.path.isfile(temp_file):
        os.remove(temp_file)


def get_tinydb(path):
    with open(path) as db:
        return json.loads(db.read())['_default']


class TestTinyDBStorage:
    def test_init(self):
        tmpdir = tempfile.mkdtemp()
        shutil.rmtree(tmpdir)
        assert not os.path.isdir(tmpdir)
        stash_path = os.path.join(tmpdir, 'stash.json')
        storage = ghost.TinyDBStorage(stash_path)
        try:
            storage.init()
            assert os.path.isdir(tmpdir)
        finally:
            shutil.rmtree(tmpdir)

    def test_init_stash_already_exists(self):
        fd, stash_path = tempfile.mkstemp()
        os.close(fd)
        storage = ghost.TinyDBStorage(stash_path)
        with pytest.raises(ghost.GhostError) as ex:
            storage.init()
        assert 'Stash {0} already initialized'.format(stash_path) in ex.value

    def test_put(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        storage.put({'name': 'my_key'})
        db = get_tinydb(stash_path)
        assert '1' in db
        assert db['1']['name'] == 'my_key'
        assert len(db) == 1

    def test_list(self, stash_path):
        key = {'name': 'my_key'}
        storage = ghost.TinyDBStorage(stash_path)
        storage.put(key)
        key_list = storage.list()
        assert key in key_list
        assert len(key_list) == 1

    def test_empty_list(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        key_list = storage.list()
        assert len(key_list) == 0

    def test_get_delete(self, stash_path):
        inserted_key = {'name': 'my_key'}
        storage = ghost.TinyDBStorage(stash_path)
        storage.put(inserted_key)
        retrieved_key = storage.get('my_key')
        assert inserted_key == retrieved_key
        storage.delete('my_key')
        retrieved_key = storage.get('my_key')
        assert retrieved_key == {}


TEST_PASSPHRASE = 'abcdefg'


@pytest.fixture
def test_stash(stash_path):
    stash = ghost.Stash(ghost.TinyDBStorage(stash_path))
    stash.init()
    return stash


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


class TestStash:
    def test_init(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        stash = ghost.Stash(storage, TEST_PASSPHRASE)
        passphrase = stash.init()
        assert stash._storage == storage
        assert stash.passphrase == TEST_PASSPHRASE
        assert passphrase == TEST_PASSPHRASE
        assert_stash_initialized(stash_path)

    def test_generated_passphrase(self, test_stash):
        assert_stash_initialized(test_stash._storage.db_path)

    def test_init_passphrase_not_string(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        stash = ghost.Stash(storage, ['x'])
        with pytest.raises(ghost.GhostError) as ex:
            stash.init()
        assert 'passphrase must be a non-empty string' in ex.value

    def test_put(self, test_stash):
        id = test_stash.put('aws', {'key': 'value'})
        db = get_tinydb(test_stash._storage.db_path)
        db[str(id)]['value'] = test_stash._decrypt(db[str(id)]['value'])
        assert_key_put(db)

    def test_put_no_value_provided(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('new-key')
        assert 'You must provide a value for new keys' in ex.value

    def test_put_value_not_dict(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', 'string')
        assert 'Value must be of type dict' in ex.value

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

    def test_put_modify_nonexisting_key(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', {'key': 'value'}, modify=True)
        assert "therefore cannot be modified" in str(ex.value)

    def test_put_existing_key_no_modify(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.put('aws', {'key': 'value'})
        assert "Use the modify flag to overwrite" in str(ex.value)

    def test_get(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key = test_stash.get('aws')
        assert isinstance(key, dict)
        assert 'name' in key
        assert 'value' in key
        assert 'description' in key
        assert 'modified_at' in key
        assert 'created_at' in key
        assert 'uid' in key

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

    def test_delete_nonexisting_key(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.delete('aws')
        assert 'Key aws not found' in ex.value

    def test_list(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert key_list[0] == 'aws'
        assert 'stored_passphrase' not in key_list

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
        assert 'There are no keys to export' in ex.value

    def test_load(self, test_stash):
        test_stash.put('aws', {'key': 'value'})
        keys = test_stash.export()
        assert keys[0]['name'] == 'aws'
        test_stash.purge(force=True)
        test_stash.load(keys)
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert 'aws' in key_list

    def test_load_from_file(self, test_stash, temp_file_path):
        test_stash.put('aws', {'key': 'value'})
        test_stash.export(temp_file_path)

        test_stash.purge(force=True)
        keys = test_stash.list()
        assert len(keys) == 0
        test_stash.load(key_file=temp_file_path)
        key_list = test_stash.list()
        assert len(key_list) == 1
        assert 'aws' in key_list

    def test_load_no_keys_no_file_provided(self, test_stash):
        with pytest.raises(ghost.GhostError) as ex:
            test_stash.load()
        assert 'You must either provide a path to an exported' in str(ex.value)


@pytest.fixture
def test_cli_stash(stash_path):
    _invoke('init_stash {0}'.format(stash_path))
    os.environ['GHOST_STASH_PATH'] = stash_path
    with open('passphrase.ghost') as passphrase_file:
        passphrase = passphrase_file.read()
    os.environ['GHOST_PASSPHRASE'] = passphrase
    yield ghost.Stash(ghost.TinyDBStorage(stash_path), passphrase)
    os.remove('passphrase.ghost')
    os.remove(stash_path)


class TestCLI:
    def test_invoke_main(self):
        result = _invoke('main')
        assert 'Usage: main [OPTIONS] COMMAND [ARGS]' in result.output

    def test_init(self, test_cli_stash):
        assert_stash_initialized(test_cli_stash._storage.db_path)

    def test_init_already_initialized(self, test_cli_stash):
        result = _invoke('init_stash')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'already initialized' in result.output

    def test_put(self, test_cli_stash):
        _invoke('put_key aws key=value')
        db = get_tinydb(test_cli_stash._storage.db_path)
        db['2']['value'] = test_cli_stash._decrypt(db['2']['value'])
        assert_key_put(db)

    def test_put_no_modify(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('put_key aws key=value')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'The key already exists' in result.output

    def test_get(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('get_key aws')
        key = get_tinydb(test_cli_stash._storage.db_path)['2']
        key['value'] = test_cli_stash._decrypt(key['value'])
        pretty_key = ghost._prettify_dict(key)
        pretty_key_parts = pretty_key.splitlines()
        for part in pretty_key_parts:
            assert part in result.output

    def test_get_jsonified(self, test_cli_stash):
        _invoke('put_key aws key=value')
        result = _invoke('get_key aws -j')
        key = get_tinydb(test_cli_stash._storage.db_path)['2']
        key['value'] = test_cli_stash._decrypt(key['value'])
        assert json.loads(result.output) == key

    def test_get_nonexisting_value(self, test_cli_stash):
        result = _invoke('get_key non-existing-key')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key non-existing-key not found' in result.output

    def test_delete_key(self, test_cli_stash):
        _invoke('put_key aws key=value')
        db = get_tinydb(test_cli_stash._storage.db_path)
        assert len(db) == 2
        assert db['2']['name'] == 'aws'
        _invoke('delete_key aws')
        db = get_tinydb(test_cli_stash._storage.db_path)
        assert len(db) == 1
        assert db['1']['name'] == 'stored_passphrase'

    def test_delete_nonexisting_key(self, test_cli_stash):
        result = _invoke('delete_key aws')
        assert type(result.exception) == SystemExit
        assert result.exit_code == 1
        assert 'Key aws not found' in result.output

    def test_list(self, test_cli_stash):
        _invoke('put_key aws key=value')
        _invoke('put_key gcp key=value')
        result = _invoke('list_keys')
        assert '  - aws' in result.output
        assert '  - gcp' in result.output

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
