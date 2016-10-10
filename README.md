ghost - shhhhhh
===============

[![Travis Build Status](https://travis-ci.org/nir0s/ghost.svg?branch=master)](https://travis-ci.org/nir0s/ghost)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/kn6yqwqhsdn54ich/branch/master?svg=true)](https://ci.appveyor.com/project/nir0s/ghost/branch/master)
[![PyPI Version](http://img.shields.io/pypi/v/ghost.svg)](http://img.shields.io/pypi/v/ghost.svg)
[![Supported Python Versions](https://img.shields.io/pypi/pyversions/ghost.svg)](https://img.shields.io/pypi/pyversions/ghost.svg)
[![Requirements Status](https://requires.io/github/nir0s/ghost/requirements.svg?branch=master)](https://requires.io/github/nir0s/ghost/requirements/?branch=master)
[![Code Coverage](https://codecov.io/github/nir0s/ghost/coverage.svg?branch=master)](https://codecov.io/github/nir0s/ghost?branch=master)
[![Is Wheel](https://img.shields.io/pypi/wheel/ghost.svg?style=flat)](https://pypi.python.org/pypi/ghost)
[![Latest Github Release](https://img.shields.io/github/release/nir0s/ghost.svg)](https://img.shields.io/github/release/nir0s/ghost.svg)

ghost aims to provide a secret-store with a single, simple-to-use API supporting multiple storage backends without requiring a server to run.

## Alternatives

* While [Vault](http://vaultproject.io) is truly spectacular and I've been using it for quite a while now, it requires a server running.
* [Credstash](https://github.com/fugue/credstash) is only AWS KMS based. 
* [Keywhiz](https://github.com/square/keywhiz), like vault, also requires a server.. and let's face it, I ain't gonna run Java on my laptop just for that thank you.
* [Unicreds](https://github.com/Versent/unicreds) is based on credstash and, again, only supports KMS.
* [Sops](https://github.com/mozilla/sops) is complicated to use and also is KMS based. 
* There's a new project called [sstash](https://github.com/realcr/sstash), but it only supports file based encryption and is not intuitive enough as I see it. 
* Google developed something called [Keyczar](https://github.com/google/keyczar), but it doesn't seem to be under development.


## Installation

```shell
pip install ghost
```

For dev:

```shell
pip install https://github.com/nir0s/ghost/archive/master.tar.gz
```

## Usage

### CLI

```bash
$ ghost
Usage: ghost [OPTIONS] COMMAND [ARGS]...

  Ghost generates a secret-store in which you can keep your secrets
  encrypted. Ghost isn't real. It's just in your head.

Options:
  -h, --help  Show this message and exit.

Commands:
  delete  Delete a key from the stash
  export  Export all keys to a file
  get     Retrieve a key from the stash
  init    Init a stash
  list    List all keys in the stash
  load    Loads all keys from an exported key file to...
  purge   Purge the stash from all of its keys
  put     Insert a key to the stash


# Initializing a stash
$ ghost init
Initializing stash...
Initialized stash at: /home/nir0s/.local/share/ghost/stash.json
Your passphrase can be found under the `passphrase.ghost` file in the current directory
Make sure you save your passphrase somewhere safe. If lost, any access to your stash will be impossible.
...

$ export GHOST_STASH_PATH='~/.local/share/ghost/my_stash.json'
$ export GHOST_PASSPHRASE=$(cat passphrase.ghost)

$ ghost list
Listing all keys in ~/.local/share/ghost/my_stash.json...
The stash is empty. Go on, put some keys in there...

# Putting keys in the stash
$ ghost put aws secret=my_secret access=my_access
Stashing key...
$ ghost put gcp token=my_token --description "GCP Token" --meta Owner=Me --meta Exp=15.06.17
...

# Retrieving a key (alternatively, bash redirect to file - `ghost get aws` > file)
$ ghost get aws
Retrieving key...

Description:   None
Uid:           08ee6102-5668-440f-b583-97a1c7a17e5a
Created_At:    2016-09-15 15:10:01
Metadata:      None
Modified_At:   2016-09-15 15:10:01
Value:         access=my_access;secret=my_secret;
Name:          aws

# Retrieving a key in machine readable json
$ ghost get gcp -j
{
    "description": "My GCP Token", 
    "uid": "b8552219-8761-4179-b20d-0a1544dd91a3", 
    "created_at": "2016-09-15 15:22:53", 
    "metadata": {
        "Owner": "Me", 
        "ExpirationDate": "15.06.17"
    }, 
    "modified_at": "2016-09-15 15:23:46", 
    "value": {
        "token": "my_token"
    }, 
    "name": "gcp"
}

# Modifying an existing key
$ ghost put gcp token=my_modified_token --modify
Stashing key...

$ ghost get gcp
Retrieving key...

Description:   My GCP Token
Uid:           789a3705-044c-4e34-b720-4bc43bfbae90
Created_At:    2016-09-15 15:56:04
Metadata:      Owner=Me;ExpirationDate=15.06.17;
Modified_At:   2016-09-15 15:57:05
Value:         token=my_modified_token;
Name:          gcp

# Listing the existing keys
$ ghost list
Listing all keys in ~/.local/share/ghost/my_stash.json...
Available Keys:
  - aws
  - gcp

# Deleting a key
$ ghost delete aws
Deleting key...
...

# Deleting all keys
$ ghost purge -f
Purging stash ~/.local/share/ghost/my_stash.json...

$ ghost list
Listing all keys in ~/.local/share/ghost/my_stash.json...
The stash is empty. Go on, put some keys in there...
...
```

NOTE: `--passphrase` and `--stash` can be supplied via the `GHOST_STASH_PATH` and `GHOST_PASSPHRASE` env vars.

NOTE: The default backend for the CLI is TinyDB. If you want to use the SQLAlchemy backend, you must either provide the `--stash` and `--backend` flags with every command or set the `GHOST_STASH_PATH` and `GHOST_BACKEND` env vars after having initialized the stash. Not providing the stash path and the backend will result in ghost failing misrebly.

### Directly from Python

```python
import ghost

# Initialize a new stash
storage = TinyDBStorage(db_path='~/.local/share/ghost/stash.json')
# Can also generate a passphrase via `ghost.generate_passphrase(size=20)`
stash = Stash(storage, passphrase='P!3pimp5i31')
stash.init()

# Insert a key
stash.put(key='aws', value={'secret': 'my_secret', access: 'my_access'})
# Get the key
key = stash.get(key='aws')
print(key)
...

# List all keys in a stash
stash.list()

# Delete a key
stash.delete('aws')
```

## Backends

NOTE: ghost includes dependencies required for TinyDB only. `optional-requirements.txt` contain dependencies for other backends.

NOTE: Whlie true for the API, the CLI does not currently expose any advanced configuration for the Vault and Consul backends such as setting certs, credentials or paths.

Until the API documentation is complete, please take a look at the Storage API's on host to use each storage.

### [TinyDB](http://tinydb.readthedocs.io/en/latest/usage.html)

The TinyDB backend provides an easy to read, portable JSON file based stash. It is the default backend when using the CLI as it is the simplest to digest for new users.

### [SQLAlchemy](http://www.sqlalchemy.org)

(Tested on v1.0.15)

The SQLAlchemy backend provides a way to use all well known SQL databases as backends including a local sqlite file. Functionally, the sqlite backend resembles the TinyDB backend, but is not humanly readable.

All SQLAlchemy connection strings are allowed so Postgre, MySQL, MSSQL and the likes are easily accessible as long as you provide the correct connection string.

### [Elasticsearch](http://elastic.co)

(Tested on v2.4.1 using elasticsearch-py 2.4.0)

The Elasticsearch resembles the TinyDB backend in that it simply stores JSON documents. An Index called `ghost` is created in the cluster (unless another index name is provided via the API) and used to store the keys.

### [Consul](http://www.consul.io)

(Tested on v0.7.0)

The Consul backend allows to use Consul's distributed nature to distribute keys between servers. Consul's kv-store (v1) is used to store the keys. You must configure your Consul cluster prior to using it with Ghost as ghost will practically do zero-configuration on your cluster. As long as the kv-store REST API is accessible to ghost, you're good. You may, of course, use a single Consul server as a stash, but that is of course not recommended to prevent dataloss.

### [Vault](http://www.vaultproject.io)

(Tested on v0.6.1)

NOTE: You MUST provide your Vault token either via the API or via the `VAULT_TOKEN` env var to use the Vault backend.

Controversially, you may use Vault as your stash. Since Vault itself encrypts and decrypts keys and requires a token, it would seem weird to use ghost as a front-end for it. I do not recommend using the ghost with Vault unless you need to do cross-backend work - that is, using multiple backends at once or preserving a single API where Vault isn't always accessible. The main reason for using ghost and not Vault is its no-server nature. If you already have Vault running, you may as well use its CLI/API and not use ghost to overcome unnecessary abstraction layers.

As such, much like with Consul, note that ghost does not provide any complicated configuration options for Vault using the CLI or otherwise. You need to have your Vault[Cluster] preconfigured after-which ghost will store all keys under the `secrets` path (can be overriden). You may provide a key named `aws/account_1`, for instance, in which case ghost will just pass the path along to Vault.


## Encryption & Decryption

Encryption is done using [cryptography](https://cryptography.io/en/latest/). It is done only on values and these are saved in hexa. Keys are left in plain text.

Values are encrypted once provided and decrypted only upon request, meaning that they're only available in memory for a very short period of time.

See cryptography's [documentation](https://cryptography.io/en/latest/) for additional information.


## Exporting and Importing

You can export and import all keys in a stash using the `ghost export` and `ghost load` commands (same methods in the Python API).

The `export` command allows you to generate a json file containing all keys (encrypted, of course) while the `load` command can then load that file into another stash using the same, or a different storage backend. 

So, for instance, if you have a local implementation using sqlite, you could export all keys; create a new stash using the SQLAlchemy storage for postgre and load all keys into that storage for your server's implementation.

The `migrate` command will allow you to easily migrate all of your keys from one backend to another like so:

```bash
ghost migrate my_stash.json postgresql://localhost/ghost --source-passphrase 123 --destination-passphrase 321 --source-backend tinydb --destination-backend sqlalchemy
```

Note that using the `migrate` command (or API) will result in keys being decrypted and reencrypted on the destination stash.


## Secret key delegation

Since ghost doesn't run as a server, it doesn't provide a formal method for delegating keys to a server without explicitly passing them over in plain text post-decryption. You can work around that by retrieving a key without decrypting it (via the `--no-decrypt` flag in the CLI or the `decrypt` argument in the Python API) and sending it to the other server where the same passphrase is held and decrypting  it there.

This can be done somewhat like this:

```python
...
encrypted_value = stash.get('my_key', decrypt=False)['value']
save_to_file(encrypted_value)

# and on the server
...
stash = Stash(storage, passphrase='SAME_PASSPHRASE')
decrypted_value = stash._decrypt(encrypted_value_from_file)
```

## Testing

```shell
git clone git@github.com:nir0s/ghost.git
cd ghost
pip install tox
tox
```

## Contributions..

You can add additional backends by implementing a single class which implements the `init`, `put`, `get`, `delete` and `list` methods. Both the TinyDB and SQLAlchemy implementations are extremely lightweight and can be used as reference implementations.

Pull requests are always welcome..
