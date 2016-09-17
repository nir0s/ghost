ghost - shhhhhh
===============

WIP! No tests yet! Not for use in production! (Well, it depends on what you call production really.)

[![Build Status](https://travis-ci.org/nir0s/ghost.svg?branch=master)](https://travis-ci.org/nir0s/ghost)
[![Build status](https://ci.appveyor.com/api/projects/status/kn6yqwqhsdn54ich/branch/master?svg=true)](https://ci.appveyor.com/project/Cloudify/ghost/branch/master)
[![PyPI](http://img.shields.io/pypi/dm/ghost.svg)](http://img.shields.io/pypi/dm/ghost.svg)
[![PypI](http://img.shields.io/pypi/v/ghost.svg)](http://img.shields.io/pypi/v/ghost.svg)

ghost aims to provide a secret store with a single, simple-to-use API supporting multiple backends.

ghost leans on the premise that you might want a single API for both clients and servers to use so the cross-backend nature should provide just that without forcing the user to run a server.

## Alternatives

The reason for ghost to exist is that I found no alternatives which are an easy enough abstraction for multiple backends, with, also, a file-based backend which also doesn't require a server (Also needed a Pythonic API for work related issues but that's a different issue)

* While [Vault](http://vaultproject.io) is truly spectacular and I've been using it for quite a while now, it requires a server running.
* [Credstash](https://github.com/fugue/credstash) is only AWS KMS based. 
* [Unicreds](https://github.com/Versent/unicreds) is based on credstash and, again, only supports KMS.
* [Sops](https://github.com/mozilla/sops) is complicated to use and also is KMS based. 
* There's a new project called [sstash](https://github.com/realcr/sstash), but it only supports file based encryption and is not intuitive enough as I see it. 
* Google developed something called [Keyczar](https://github.com/google/keyczar), but it doesn't seem to be under development.
* [Keywhiz](https://github.com/square/keywhiz), like vault, also requires a server.. and let's face it, I ain't gonna run Java on my laptop just for that thank you.


## Installation

```shell
pip install ghost
```

For dev:

```shell
pip install https://github.com/nir0s/ghost/archive/master.tar.gz
```

## Usage

NOTE: The CLI currently only supports working with the TinyDB backend. To use the SQLAlchemy backend, use ghost directly from Python.

### CLI

```bash
$ ghost
Usage: ghost [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --help  Show this message and exit.

Commands:
  delete  Delete a key from the stash
  get     Retrieve a key from the stash
  init    Init a stash
  list    List all keys in the stash
  put     Insert a key to the stash


$ ghost init
Initializing stash...
Initialized stash at: /home/nir0s/.ghost/stash.json
Your passphrase is: qVqkxQ1UfP9s
...

$ export GHOST_STASH_PATH='~/my_stash.json'
$ export GHOST_PASSPHRASE='qVqkxQ1UfP9s'

$ ghost list
Listing all keys in ~/my_stash.json...
The stash is empty. Go on, put some keys in there...

$ ghost put aws --val secret=my_secret --val access=my_access
Stashing key in ~/my_stash.json...
$ ghost put gcp --val token=my_token --description "GCP Token" --meta Owner=Me --meta Exp=15.06.17
...

$ ghost get aws
Retrieving key from ~/my_stash.json...

Description:   None
Uid:           08ee6102-5668-440f-b583-97a1c7a17e5a
Created_At:    2016-09-15T15:10:01
Metadata:      None
Modified_At:   2016-09-15T15:10:01
Value:         access=my_access;secret=my_secret;
Name:          aws

$ ghost get gcp -j
{
    "description": "My GCP Token", 
    "uid": "b8552219-8761-4179-b20d-0a1544dd91a3", 
    "created_at": "2016-09-15T15:22:53", 
    "metadata": {
        "Owner": "Me", 
        "ExpirationDate": "15.06.17"
    }, 
    "modified_at": "2016-09-15T15:23:46", 
    "value": {
        "token": "my_token"
    }, 
    "name": "gcp"
}

$ ghost put gcp --val token=my_modified_token --modify
Stashing key in ~/my_stash.json...

$ ghost get gcp
Retrieving key from ~/my_stash.json...

Description:   My GCP Token
Uid:           789a3705-044c-4e34-b720-4bc43bfbae90
Created_At:    2016-09-15T15:56:04
Metadata:      Owner=Me;ExpirationDate=15.06.17;
Modified_At:   2016-09-15T15:57:05
Value:         token=my_modified_token;
Name:          gcp

$ ghost list
Listing all keys in ~/my_stash.json...
Available Keys:
  - aws
  - gcp

$ ghost delete aws
Deleting key from stash ~/my_stash.json...
...
```

NOTE: `--passphrase` and `--stash` can be supplied via the `GHOST_STASH_PATH` and `GHOST_PASSPHRASE` env vars.

### Directly from Python

```python
import ghost

# Initialize a new stash
storage = TinyDBStorage(db_path='~/.ghost/stash.json')
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

Currently, only two backends are provided.

* [TinyDB](http://tinydb.readthedocs.io/en/latest/usage.html)
* [SQLAlchemy](http://www.sqlalchemy.org) (Tested on v1.0.15)

NOTE: ghost doesn't install SQLAlchemy by default or any other backend other than TinyDB for that matter. Please Install SQLAlchemy separately if you need to use its backend.

I'd like to also support Vault in addition to KMS and any other cloud provider based key stores.

## Encryption & Decryption

Encryption is done using [cryptography](https://cryptography.io/en/latest/). It is done only on values and these are saved in hexa. Keys are left in plain text.

Values are encrypted once provided and are decrypted only upon request, meaning that they're only available in memory for a very short period of time.

See [cryptography](https://cryptography.io/en/latest/) documentation for additional information.

## Testing

```shell
git clone git@github.com:nir0s/ghost.git
cd ghost
pip install tox
tox
```

## Contributions..

Pull requests are always welcome..
