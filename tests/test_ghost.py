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
import tempfile

import pytest

import ghost


def _invoke(command):
    cfy = clicktest.CliRunner()

    lexed_command = command if isinstance(command, list) \
        else shlex.split(command)
    func = lexed_command[0]
    params = lexed_command[1:]
    return cfy.invoke(getattr(repex, func), params)


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
            metadata='d',
            modified='e',
            value='f',
            name='g')
        prettified_input = ghost._prettify_dict(input).splitlines()
        for line in prettified_input:
            assert 'Description:   a' in prettified_input
            assert 'Uid:           b' in prettified_input
            assert 'Created_At:    c' in prettified_input
            assert 'Metadata:      d' in prettified_input
            assert 'Modified:      e' in prettified_input
            assert 'Value:         f' in prettified_input
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


@pytest.fixture
def stash_path():
    fd, stash_file = tempfile.mkstemp()
    os.remove(stash_file)
    os.close(fd)
    yield stash_file
    os.remove(stash_file)


class TestTinyDBStorage:
    def test_put(self, stash_path):
        storage = ghost.TinyDBStorage(stash_path)
        storage.put('aws')
