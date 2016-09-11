########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

import os
import shlex
import tempfile

import testtools
import click.testing as clicktest

import repex


TEST_RESOURCES_DIR = os.path.join('tests', 'resources')
TEST_RESOURCES_DIR_PATTERN = os.path.join('tests', 'resource.*')
MOCK_SINGLE_FILE = os.path.join(TEST_RESOURCES_DIR, 'mock_single_file.yaml')
MOCK_MULTIPLE_FILES = os.path.join(
    TEST_RESOURCES_DIR, 'mock_multiple_files.yaml')
TEST_FILE_NAME = 'mock_VERSION'
MOCK_TEST_FILE = os.path.join(TEST_RESOURCES_DIR, 'single', TEST_FILE_NAME)
EMPTY_CONFIG_FILE = os.path.join(TEST_RESOURCES_DIR, 'empty_mock_files.yaml')
MULTIPLE_DIR = os.path.join(TEST_RESOURCES_DIR, 'multiple')
SINGLE_DIR = os.path.join(TEST_RESOURCES_DIR, 'multiple')
EXCLUDED_FILE = os.path.join(MULTIPLE_DIR, 'excluded', TEST_FILE_NAME)
MOCK_FILES_WITH_VALIDATOR = os.path.join(
    TEST_RESOURCES_DIR, 'files_with_failed_validator.yaml')


def _invoke(command):
    cfy = clicktest.CliRunner()

    lexed_command = command if isinstance(command, list) \
        else shlex.split(command)
    func = lexed_command[0]
    params = lexed_command[1:]
    return cfy.invoke(getattr(repex, func), params)


class TestBase(testtools.TestCase):
    def test_invoke_main(self):
        result = _invoke('main')
        self.assertIn(
            'Usage: main [OPTIONS] COMMAND [ARGS]',
            result.output)

    def test_illegal_iterate_invocation(self):
        result = _invoke('from_config non_existing_config')
        self.assertEqual(type(result.exception), SystemExit)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('Could not open config file: ', result.output)

    def test_illegal_replace_invocation(self):
        result = _invoke('in_path non_existing_path -r x -w y')
        self.assertEqual(type(result.exception), SystemExit)
        self.assertEqual(result.exit_code, 1)
        self.assertIn('File not found: ', result.output)

    def test_mutually_exclusive_arguments(self):
        result = _invoke('in_path --ftype=non_existing_path --to-file=x')
        self.assertEqual(type(result.exception), SystemExit)
        self.assertIn('is mutually exclusive with', result.output)

    def test_iterate_no_config_supplied(self):
        ex = self.assertRaises(
            repex.RepexError,
            repex.iterate)
        self.assertIn(repex.ERRORS['no_config_supplied'], str(ex))

    def test_iterate_no_files(self):
        ex = self.assertRaises(
            TypeError,
            repex.iterate,
            config_file_path=EMPTY_CONFIG_FILE,
            variables={})
        self.assertIn(repex.ERRORS['invalid_yaml'], str(ex))

    def test_iterate_variables_not_dict(self):
        ex = self.assertRaises(
            TypeError,
            repex.iterate,
            config_file_path=MOCK_SINGLE_FILE,
            variables='x')
        self.assertIn(repex.ERRORS['variables_not_dict'], str(ex))

    def test_file_no_permissions_to_write_to_file(self):
        if os.name == 'nt':
            self.skipTest('Irrelevant on Windows')

        pathobj = {
            'path': MOCK_TEST_FILE,
            'match': '3.1.0-m2',
            'replace': '3.1.0-m2',
            'with': '3.1.0-m3',
            'to_file': '/mock.test'
        }
        try:
            repex.handle_path(pathobj, verbose=True)
            self.fail()
        except IOError as ex:
            self.assertIn('Permission denied', str(ex))

    def test_file_must_include_missing(self):
        pathobj = {
            'path': MOCK_TEST_FILE,
            'match': '3.1.0-m2',
            'replace': '3.1.0',
            'with': '',
            'to_file': 'VERSION.test',
            'must_include': [
                'MISSING_INCLUSION'
            ]
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['prevalidation_failed'], str(ex))

    def test_file_must_include_not_list(self):
        pathobj = {
            'path': MOCK_TEST_FILE,
            'match': '3.1.0-m2',
            'replace': '3.1.0',
            'with': '',
            'to_file': 'VERSION.test',
            'must_include': ''
        }
        ex = self.assertRaises(
            TypeError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['must_include_not_list'], str(ex))

    def _test_path_with_and_without_base_directory(self):
        p = {
            'path': os.path.join('single', TEST_FILE_NAME),
            'base_directory': TEST_RESOURCES_DIR,
            'match': '3.1.0-m2',
            'replace': '3.1.0-m2',
            'with': '3.1.0-m3',
        }
        t = {
            'path': MOCK_TEST_FILE,
            'match': '3.1.0-m3',
            'replace': '3.1.0-m3',
            'with': '3.1.0-m2',
        }
        repex.handle_path(p, verbose=True)
        with open(p['path']) as f:
            content = f.read()
        self.assertIn('3.1.0-m3', content)
        repex.handle_path(t, verbose=True)
        with open(t['path']) as f:
            content = f.read()
        self.assertIn('3.1.0-m2', content)

    def test_to_file_requires_explicit_path(self):
        pathobj = {
            'type': 'x',
            'path': TEST_RESOURCES_DIR_PATTERN,
            'base_directory': '',
            'match': '3.1.0-m2',
            'replace': '3.1.0-m2',
            'with': '3.1.0-m3',
            'to_file': '/x.x',
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['to_file_requires_explicit_path'], str(ex))

    def test_file_does_not_exist(self):
        pathobj = {
            'path': 'MISSING_FILE',
            'match': '3.1.0-m2',
            'replace': '3.1.0',
            'with': '',
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['file_not_found'], str(ex))

    def test_type_with_path_config(self):
        pathobj = {
            'type': 'x',
            'path': MOCK_TEST_FILE,
            'base_directory': '',
            'match': '3.1.0-m2',
            'replace': '3.1.0-m2',
            'with': '3.1.0-m3',
            'to_file': '/x.x',
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['type_path_collision'], str(ex))

    def test_single_file_not_found(self):
        pathobj = {
            'path': 'x',
            'base_directory': '',
            'match': '3.1.0-m2',
            'replace': '3.1.0-m2',
            'with': '3.1.0-m3'
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex.handle_path,
            pathobj,
            verbose=True)
        self.assertIn(repex.ERRORS['file_not_found'], str(ex))


class TestMultipleFiles(testtools.TestCase):
    def setUp(self):
        super(TestMultipleFiles, self).setUp()
        self.version_files = []
        for root, _, files in os.walk(MULTIPLE_DIR):
            self.version_files = \
                [os.path.join(root, f) for f in files if f == 'mock_VERSION']
        self.version_files_without_excluded = \
            [f for f in self.version_files if f != EXCLUDED_FILE]
        self.excluded_files = [f for f in self.version_files if f not
                               in self.version_files_without_excluded]

    def test_iterate_multiple_files(self):

        def _test(replaced_value, initial_value):
            for version_file in self.version_files_without_excluded:
                with open(version_file) as f:
                    self.assertIn(replaced_value, f.read())
            for version_file in self.excluded_files:
                with open(version_file) as f:
                    self.assertIn(initial_value, f.read())

        # TODO: This is some stupid thing related to formatting on windows
        # The direct invocation with click doesn't work on windows..
        # probably due to some string formatting of the command.
        if os.name == 'nt':
            variables = {'preversion': '3.1.0-m2', 'version': '3.1.0-m3'}
            repex.iterate(MOCK_MULTIPLE_FILES, variables=variables)
        else:
            fd, tmp = tempfile.mkstemp()
            os.close(fd)
            with open(tmp, 'w') as f:
                f.write("version: '3.1.0-m3'")
            try:
                _invoke(
                    "from_config {0} --vars-file={1} "
                    "--var='preversion'='3.1.0-m2'".format(
                        MOCK_MULTIPLE_FILES, tmp))
            finally:
                os.remove(tmp)

        _test('"version": "3.1.0-m3"', '"version": "3.1.0-m2"')
        variables = {'preversion': '3.1.0-m3', 'version': '3.1.0-m2'}
        repex.iterate(MOCK_MULTIPLE_FILES, variables=variables)
        _test('"version": "3.1.0-m2"', '"version": "3.1.0-m2"')

    def test_replace_multiple_files(self):

        def _test(path, params, initial_value, final_value):
            result = _invoke(['in_path', path] + params)
            self.assertEqual(result.exit_code, 1)
            # verify that all files were modified
            for version_file in self.version_files_without_excluded:
                with open(version_file) as f:
                    self.assertIn(initial_value, f.read())
            # all other than the excluded ones
            for version_file in self.excluded_files:
                with open(version_file) as f:
                    self.assertIn(final_value, f.read())

        params = [
            '-t', 'mock_VERSION',
            '-b', 'tests/resources/',
            '-x', 'multiple/exclude',
            '-m', '"version": "\d+\.\d+(\.\d+)?(-\w\d+)?"',
            '-r', '\d+\.\d+(\.\d+)?(-\w\d+)?',
            '-w', '3.1.0-m3',
            '--must-include=date',
            '--validator=tests/resources/validator.py:validate',
        ]
        _test('multiple', params, '3.1.0-m3', '3.1.0-m2')
        params[11] = '3.1.0-m2'
        _test('multiple', params, '3.1.0-m2', '3.1.0-m2')


class TestConfig(testtools.TestCase):

    def test_import_config_file(self):
        config = repex._get_config(config_file_path=MOCK_SINGLE_FILE)
        self.assertEquals(type(config['paths']), list)
        self.assertEquals(type(config['variables']), dict)

    def test_config_file_not_found(self):
        ex = self.assertRaises(
            repex.RepexError,
            repex._get_config,
            config_file_path='non_existing_path')
        self.assertIn(repex.ERRORS['config_file_not_found'], str(ex))

    def test_import_bad_config_file_mapping(self):
        ex = self.assertRaises(
            repex.RepexError,
            repex._get_config,
            config_file_path=os.path.join(
                TEST_RESOURCES_DIR, 'bad_mock_files.yaml'))
        self.assertIn(repex.ERRORS['invalid_yaml'], str(ex))

    def test_config_variables_not_dict(self):
        config = {
            'paths': [{'key': 'value'}],
            'variables': '{{ .x }}'
        }
        ex = self.assertRaises(
            TypeError,
            repex._get_config,
            config=config)
        self.assertIn(repex.ERRORS['variables_not_dict'], str(ex))

    def test_config_paths_not_list(self):
        config = {
            'paths': {'key': 'value'},
        }
        ex = self.assertRaises(
            TypeError,
            repex._get_config,
            config=config)
        self.assertIn(repex.ERRORS['paths_not_list'], str(ex))

    def test_config_no_paths(self):
        config = {
            'paths': '',
        }
        ex = self.assertRaises(
            repex.RepexError,
            repex._get_config,
            config=config)
        self.assertIn(repex.ERRORS['no_paths_configured'], str(ex))


class TestValidator(testtools.TestCase):

    def setUp(self):
        super(TestValidator, self).setUp()
        self.single_file_config = repex._get_config(MOCK_SINGLE_FILE)
        self.validation_config = repex._get_config(MOCK_FILES_WITH_VALIDATOR)
        self.single_file_output_file = \
            self.single_file_config['paths'][0]['to_file']
        self.validator_config = self.validation_config['paths'][0]['validator']

    def test_validator(self):
        variables = {'version': '3.1.0-m3'}

        try:
            repex.iterate(
                config=self.validation_config,
                variables=variables)
        finally:
            os.remove(self.single_file_output_file)

    def test_failed_validator_per_file(self):
        variables = {'version': '3.1.0-m3'}

        self.validation_config['paths'][0]['validator']['function'] = \
            'fail_validate'

        try:
            ex = self.assertRaises(
                repex.RepexError,
                repex.iterate,
                config=self.validation_config,
                variables=variables)
            self.assertIn(repex.ERRORS['validation_failed'], str(ex))
            with open(self.single_file_output_file) as f:
                self.assertIn('3.1.0-m3', f.read())
        finally:
            os.remove(self.single_file_output_file)

    def _check_config(self, error):
        ex = self.assertRaises(
            repex.RepexError,
            repex.Validator,
            self.validator_config)
        self.assertIn(repex.ERRORS[error], str(ex))

    def test_invalid_validator_type(self):
        self.validator_config.update({'type': 'bad_type'})
        self._check_config('invalid_validator_type')

    def test_validator_path_not_supplied(self):
        self.validator_config.pop('path')
        self._check_config('validator_path_not_supplied')

    def test_validator_function_not_supplied(self):
        self.validator_config.pop('function')
        self.validator_config['path'] = os.path.join(
            TEST_RESOURCES_DIR, 'validator.py')
        self._check_config('validator_function_not_supplied')

    def test_validator_path_not_found(self):
        self.validator_config.update({'path': 'bad_path'})
        self._check_config('validator_path_not_found')

    def test_validator_function_not_found(self):
        self.validator_config.update({'function': 'bad_function'})
        self.validator_config['path'] = os.path.join(
            TEST_RESOURCES_DIR, 'validator.py')
        validator = repex.Validator(self.validator_config)
        ex = self.assertRaises(
            repex.RepexError,
            validator.validate,
            'some_file')
        self.assertIn(repex.ERRORS['validator_function_not_found'], str(ex))


class TestSingleFile(testtools.TestCase):

    def setUp(self):
        super(TestSingleFile, self).setUp()
        self.single_file_config = repex._get_config(MOCK_SINGLE_FILE)
        self.single_file_output_file = \
            self.single_file_config['paths'][0]['to_file']
        self.multi_file_config = repex._get_config(MOCK_MULTIPLE_FILES)
        self.multi_file_excluded_dirs = \
            self.multi_file_config['paths'][0]['excluded']

    def tearDown(self):
        super(TestSingleFile, self).tearDown()
        if os.path.isfile(self.single_file_output_file):
            os.remove(self.single_file_output_file)

    def test_iterate(self):
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config_file_path=MOCK_SINGLE_FILE,
            variables=variables)
        with open(self.single_file_output_file) as f:
            self.assertIn('3.1.0-m3', f.read())

    def test_iterate_user_tags_no_path_tags(self):
        tags = ['test_tag']
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config_file_path=MOCK_SINGLE_FILE,
            variables=variables,
            verbose=True,
            tags=tags)
        self.assertFalse(os.path.isfile(self.single_file_output_file))

    def test_iterate_path_tags_no_user_tags(self):
        tags = ['test_tag']
        self.single_file_config['paths'][0]['tags'] = tags
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config=self.single_file_config,
            variables=variables,
            verbose=True)
        self.assertFalse(os.path.isfile(self.single_file_output_file))

    def test_iterate_path_tags_user_tags(self):
        tags = ['test_tag']
        self.single_file_config['paths'][0]['tags'] = tags
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config=self.single_file_config,
            variables=variables,
            verbose=True,
            tags=tags)
        with open(self.single_file_output_file) as f:
            self.assertIn('3.1.0-m3', f.read())

    def test_iterate_any_tag(self):
        tags = ['test_tag']
        any_tag = ['any']
        self.single_file_config['paths'][0]['tags'] = tags
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config=self.single_file_config,
            variables=variables,
            verbose=True,
            tags=any_tag)
        with open(self.single_file_output_file) as f:
            self.assertIn('3.1.0-m3', f.read())

    def test_tags_not_list(self):
        tags = 'x'
        ex = self.assertRaises(
            TypeError,
            repex.iterate,
            config=self.single_file_config,
            tags=tags,
            verbose=True)
        self.assertIn(repex.ERRORS['tags_not_list'], str(ex))

    def test_iterate_with_vars(self):
        variables = {'version': '3.1.0-m3'}
        repex.iterate(
            config_file_path=MOCK_SINGLE_FILE,
            variables=variables)
        with open(self.single_file_output_file) as f:
            self.assertIn('3.1.0-m3', f.read())

    def test_iterate_with_vars_in_config(self):
        repex.iterate(config_file_path=MOCK_SINGLE_FILE)
        with open(self.single_file_output_file) as f:
            self.assertIn('3.1.0-m4', f.read())

    def test_env_var_based_replacement(self):
        variables = {'version': '3.1.0-m3'}
        os.environ['REPEX_VAR_VERSION'] = '3.1.0-m9'
        try:
            repex.iterate(
                config_file_path=MOCK_SINGLE_FILE,
                variables=variables)
            with open(self.single_file_output_file) as f:
                self.assertIn('3.1.0-m9', f.read())
        finally:
            os.environ.pop('REPEX_VAR_VERSION')

    # @mock.patch('re.search', return_value=False)
    def test_variable_not_expanded(self):
        attributes = {'path': '"{{ .some_var }}"'}
        variables = {'some_var': '3.1.0-m3'}

        def false_return(*args):
            return False

        variable_expander = repex.VariablesHandler()
        variable_expander._check_if_expanded = false_return
        ex = self.assertRaises(
            repex.RepexError,
            variable_expander.expand,
            variables,
            attributes)
        self.assertIn(repex.ERRORS['string_failed_to_expand'], str(ex))

    def test_variable_not_expanded_again(self):
        var_string = '{{ .some_var }}'
        expanded_variable = 'data {{ .some_var }} data'

        variable_expander = repex.VariablesHandler()
        result = variable_expander._check_if_expanded(
            var_string, expanded_variable)
        self.assertFalse(result)


class TestGetAllFiles(testtools.TestCase):

    def setUp(self):
        super(TestGetAllFiles, self).setUp()
        self.multi_file_config = repex._get_config(MOCK_MULTIPLE_FILES)
        self.multi_file_excluded_dirs = \
            self.multi_file_config['paths'][0]['excluded']
        self.excluded_files = \
            [os.path.join(self.multi_file_excluded_dirs[0], TEST_FILE_NAME)]
        self.base_dir = self.multi_file_config['paths'][0]['base_directory']

        for root, _, files in os.walk(MULTIPLE_DIR):
            self.version_files = \
                [os.path.join(root, f) for f in files if f == 'mock_VERSION']
        self.version_files_without_excluded = \
            [f for f in self.version_files if f != EXCLUDED_FILE]
        self.excluded_files = [f for f in self.version_files if f not
                               in self.version_files_without_excluded]

    def test_get_all_files_no_exclusion(self):
        files = repex.get_all_files(
            filename_regex=TEST_FILE_NAME,
            path=TEST_RESOURCES_DIR_PATTERN,
            base_dir=TEST_RESOURCES_DIR)
        for version_file in self.version_files:
            self.assertIn(version_file, files)

    def test_get_all_files_with_dir_exclusion(self):
        files = repex.get_all_files(
            filename_regex=TEST_FILE_NAME,
            path=TEST_RESOURCES_DIR_PATTERN,
            base_dir=TEST_RESOURCES_DIR,
            excluded_paths=self.multi_file_excluded_dirs)
        for version_file in self.version_files_without_excluded:
            self.assertIn(version_file, files)
        for f in self.excluded_files:
            self.assertNotIn(os.path.join(self.base_dir, f), files)

    def test_get_all_files_excluded_list_is_str(self):
        ex = self.assertRaises(
            TypeError,
            repex.get_all_files,
            filename_regex=TEST_FILE_NAME,
            path=TEST_RESOURCES_DIR_PATTERN,
            base_dir=TEST_RESOURCES_DIR,
            excluded_paths='INVALID_EXCLUDED_LIST')
        self.assertIn(repex.ERRORS['excluded_paths_not_list'], str(ex))

    def test_get_all_regex_files(self):
        mock_yaml_files = [f for f in os.listdir(TEST_RESOURCES_DIR)
                           if (f.startswith('mock') and f.endswith('yaml'))]
        files = repex.get_all_files(
            filename_regex='mock.*\.yaml',
            path=TEST_RESOURCES_DIR_PATTERN,
            base_dir=TEST_RESOURCES_DIR)
        self.assertEquals(len(mock_yaml_files), len(files))
        for f in mock_yaml_files:
            self.assertIn(os.path.join(TEST_RESOURCES_DIR, f), files)

    def test_get_all_regex_files_with_exclusion(self):
        mock_yaml_files = [os.path.join('single', 'mock_VERSION')]
        files = repex.get_all_files(
            filename_regex='mock.*',
            path=TEST_RESOURCES_DIR_PATTERN,
            base_dir=TEST_RESOURCES_DIR,
            excluded_paths=['multiple'],
            verbose=True,
            excluded_filename_regex='.*yaml',)
        self.assertEquals(len(mock_yaml_files), len(files))
        for f in mock_yaml_files:
            self.assertIn(os.path.join(TEST_RESOURCES_DIR, f), files)
