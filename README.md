Clu - A Secret Store without clues
==================================

[![Circle CI](https://circleci.com/gh/nir0s/clu/tree/master.svg?style=shield)](https://circleci.com/gh/nir0s/clu/tree/master)
[![Build Status](https://travis-ci.org/nir0s/clu.svg?branch=master)](https://travis-ci.org/nir0s/clu)
[![Build status](https://ci.appveyor.com/api/projects/status/kn6yqwqhsdn54ich/branch/master?svg=true)](https://ci.appveyor.com/project/Cloudify/clu/branch/master)
[![PyPI](http://img.shields.io/pypi/dm/clu.svg)](http://img.shields.io/pypi/dm/clu.svg)
[![PypI](http://img.shields.io/pypi/v/clu.svg)](http://img.shields.io/pypi/v/clu.svg)

Clu aims to provide a secret store with a single, simple-to-use API supporting multiple backends.

Clu leans on the premise that you might want a single API for both clients and servers to use so the cross-backend nature should provide just that without forcing the user to run a server.

## Alternatives

The reason for Clu to exist is that I found no alternatives which are an easy enough abstraction for multiple backends. 

* While Vault is truly spectacular, it requires a server.
* [Credstash](https://github.com/fugue/credstash) is only AWS KMS based. 
* [Sops](https://github.com/mozilla/sops) is complicated to use and also is KMS based. 
* There's a new project called [sstash](https://github.com/realcr/sstash), but it only supports file based encryption and is not intuitive enough as I see it. 
* Google developed something called [Keyczar](https://github.com/google/keyczar), but it doesn't seem to be under contsant development.
* [Keywhiz](https://github.com/square/keywhiz), like vault, also requires a server.. and let's face it, I ain't gonna run Java on my laptop just for that thank you.


## Installation

```shell
pip install clu
```

For dev:

```shell
pip install https://github.com/nir0s/clu/archive/master.tar.gz
```

## Usage

### CLI

```bash
$ clu init ~/my_stash.json --phrase I!@p2ip11DA
$ clu put aws '{"secret": "my_secret", "access": "my_access"}' --stash ~/my_stash.json --phrase I!@p2ip11DA
clu get aws --phrase I!@p2ip11DA --stash ~/my_stash.json
```

NOTE: `--phrase` and `--stash` can be supplied via the `CLU_STASH` and `CLU_PHRASE` env vars.

### Directly from Python

```python
import clu

# Initialize a new stash
clu.init(path='~/.clu/stash.json', phrase='P!3pimp5i31')

# Now load the stash
stash = clu.load(path='~/.clu/stash', phrase='P!3pimp5i31')
# Insert a key
stash.put(key='aws', value={'secret': 'my_secret', access: 'my_access'})
# Get the key
creds = stash.get(key='aws')

# Delete the stash
clu.delete('~/.clu/stash.json')
```

## Backends

Currently, only a [TinyDB](http://tinydb.readthedocs.io/en/latest/usage.html) backend is provided.

I'd like to support SQLite (via SQLAlchemy, or otherwise), Postgre and Vault in addition to KMS and any other cloud provider based key stores.

## Encryption & Decryption

For the TinyDB backend, encryption is provided using [simple-crypt](https://github.com/andrewcooke/simple-crypt). Encryption is done only on values and these are saved in hexa. Keys are left in plain text.

Values are encrypted once provided and are decrypted only upon request, meaning that they're only available in memory for a very short period of time.
Note that simple-crypt (via PBKDF) adds some sleep time to prevent brute force attacks so it might take a few seconds for both processes to take place.


## Testing

```shell
git clone git@github.com:nir0s/clu.git
cd clu
pip install tox
tox
```

## Contributions..

Pull requests are always welcome..
