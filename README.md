ghost (shhhhhh)
===============

[![Travis Build Status](https://travis-ci.org/nir0s/ghost.svg?branch=master)](https://travis-ci.org/nir0s/ghost)
[![AppVeyor Build Status](https://ci.appveyor.com/api/projects/status/kuf0x8j62kts1bpg/branch/master?svg=true)](https://ci.appveyor.com/project/nir0s/ghost)
[![PyPI Version](http://img.shields.io/pypi/v/ghost.svg)](http://img.shields.io/pypi/v/ghost.svg)
[![Supported Python Versions](https://img.shields.io/pypi/pyversions/ghost.svg)](https://img.shields.io/pypi/pyversions/ghost.svg)
[![Requirements Status](https://requires.io/github/nir0s/ghost/requirements.svg?branch=master)](https://requires.io/github/nir0s/ghost/requirements/?branch=master)
[![Code Coverage](https://codecov.io/github/nir0s/ghost/coverage.svg?branch=master)](https://codecov.io/github/nir0s/ghost?branch=master)
[![Code Quality](https://landscape.io/github/nir0s/ghost/master/landscape.svg?style=flat)](https://landscape.io/github/nir0s/ghost)
[![Is Wheel](https://img.shields.io/pypi/wheel/ghost.svg?style=flat)](https://pypi.python.org/pypi/ghost)

ghost aims to provide a secret-store with a single, simple-to-use API supporting multiple storage backends without requiring a server to run.

To that end, ghost supports file based backends like TinyDB and SQLite. Using other backends means, of course, that they need to be available to ghost, while ghost itself remains stateless.

Currently, ghost supports authenticating only via a passphrase. Authenticating via KMS, GitHub and the likes, might be supported in the future.


## Alternatives

* While [Vault](http://vaultproject.io) is truly spectacular and I've been using it for quite a while now, it requires a server running.
* [Credstash](https://github.com/fugue/credstash) is only AWS KMS + DDB based. 
* [Keywhiz](https://github.com/square/keywhiz), like vault, also requires a server.. and let's face it, I ain't gonna run a JVM on my laptop just for that thank you.
* [Unicreds](https://github.com/Versent/unicreds) is based on credstash and, again, only supports KMS + DDB.
* [Sops](https://github.com/mozilla/sops) is complicated to use and also is KMS+DDB based. 
* There's a new project called [sstash](https://github.com/realcr/sstash), but it only supports file based encryption and is not intuitive enough as I see it. 
* Google developed something called [Keyczar](https://github.com/google/keyczar), but it doesn't seem to be under development.
* Pinterest has a seemingly interesting project called [Knox](https://github.com/pinterest/knox). Knox required a server to be running and doesn't support multiple backends. It also seems more developer oriented than anything else.
* Lyft has a really nice solution called [Confidant](https://lyft.github.io/confidant/) which also has a nice UI to go along with it. It authenticates via KMS and stores keys in DDB and requires and server to be running.


## Installation

Ghost supports Linux, Windows and OSX on Python 2.6, 2.7 and 3.3+

```shell
pip install ghost
```

For dev:

```shell
pip install https://github.com/nir0s/ghost/archive/master.tar.gz
```


## Usage

### CLI

```shell
$ ghost
Usage: ghost [OPTIONS] COMMAND [ARGS]...

  Ghost generates a secret-store in which you can keep your secrets
  encrypted. Ghost isn't real. It's just in your head.

Options:
  -h, --help  Show this message and exit.

Commands:
  delete   Delete a key from the stash
  export   Export all keys to a file
  get      Retrieve a key from the stash
  init     Init a stash
  list     List all keys in the stash
  load     Load all keys from an exported key file to...
  migrate  Migrate all keys from a source stash to a...
  purge    Purge the stash from all of its keys
  put      Insert a key to the stash


# Initializing a stash
$ ghost init
Initializing stash...
Initialized stash at: /home/nir0s/.ghost/stash.json
Your passphrase can be found under the `passphrase.ghost` file in the current directory
Make sure you save your passphrase somewhere safe. If lost, any access to your stash will be impossible.
...

$ export GHOST_PASSPHRASE=$(cat passphrase.ghost)

$ ghost list
Listing all keys in /home/nir0s/.ghost/stash.json...
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

# Retrieving a single value from the key
$ ghost get aws secret
my_secret

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
Listing all keys in /home/nir0s/.ghost/stash.json...
Available Keys:
  - aws
  - gcp

# Deleting a key
$ ghost delete aws
Deleting key...
...

# Deleting all keys
$ ghost purge -f
Purging stash /home/nir0s/.ghost/stash.json...

$ ghost list
Listing all keys in /home/nir0s/.ghost/stash.json...
The stash is empty. Go on, put some keys in there...
...
```

NOTE: The default backend for the CLI is TinyDB. If you want to use the SQLAlchemy backend, you must either provide the `--stash` and `--backend` flags with every command or set the `GHOST_STASH_PATH` and `GHOST_BACKEND` env vars after having initialized the stash. Not providing the stash path and the backend will result in ghost failing misrebly.

### Directly from Python

```python
import ghost

# Initialize a new stash
storage = ghost.TinyDBStorage(
    db_path='/home/nir0s/.ghost/stash.json',
    stash_name='ghost')
# Can also generate a passphrase via `ghost.generate_passphrase(size=20)`
stash = ghost.Stash(storage, passphrase='P!3pimp5i31')
stash.init()

# Insert a key
stash.put(name='aws', value={'secret': 'my_secret', 'access': 'my_access'})
# Get the key
key = stash.get(key_name='aws')
print(key)
...

# List all keys in a stash
stash.list()

# Delete a key
stash.delete('aws')
```


## Working with multiple stashes

By default, ghost generates a default stash named "ghost", regardless of the storage backend you're using. Each backend supports working with multiple stashes (or otherwise, "tenants"). This allows users to distinguish between environments, for example.

To initialize a named stash:

```shell
$ ghost init http://internal-es:9200[stash-name] --backend elasticsearch
```

You can initialize as many stashes as you want, as long, of course, as each storage backend's endpoint has a unique name for each of its stashes.


## Locking and Unlocking keys

Sometimes, you might want to lock a key to make sure it isn't deleted or modified accidentally. 

NOTE: Purging a stash will also delete locked keys.

To that end, ghost allows you to lock a key:

```shell
$ ghost lock my_key
Locking key...
$ ghost delete my_key
Deleting key...
Key `my_key` is locked and therefore cannot be deleted Please unlock the key and try again
...

$ ghost unlock my_key
...

```

## Listing containing matches or closest match

We can also list keys which contain a certain string or some close matches to that string.

For example, let's assume we have four keys: `aws`, `aws-2`, `abws-2` and `gcp`:

```shell
$ ghost list
Listing all keys...
Available Keys:
  - aws
  - aws-2
  - abws-2
  - gcp

$ ghost list aws
Listing all keys...
Available Keys:
  - aws
  - aws-2

$ ghost list ~aws
Listing all keys...
Available Keys:
  - aws
  - aws-2
  - abws-2

```

* Providing a `KEY_NAME` argument to `ghost list` will allow us to look for any keys containing `KEY_NAME`.
* Providing a tilde infront of `KEY_NAME` allows us to look for closest matches. The cutoff weight can be passed using the `--cutoff` flag (or the `cutoff` argument in Python).
* Note that this does not mean you can't provide key names starting with a tilde, as ~aws will always be a close match of aws unless the cutoff is high enough in which case it'll stop being reasonable to search for closest matches (around ~0.8 or so).

## Purging a stash

To allow for extreme measures when necessary, ghost provides the `purge` API (and command). If you quickly need to delete all keys from a stash, you can use it. To purge a stash you'll have to provide a mandatory `force` flag as precautionary measure.


## Passphrase file generation and discovery

When initializing a stash, ghost generates a passphrase file containing either the passphrase you explicitly provide or an auto-generated one. The file is saved under `cwd/passphrase.ghost`. After having been generated, you can read the file into an environment variable to use it like so:

```shell
$ export GHOST_PASSPHRASE=$(cat passphrase.ghost)
```

To simplify UX when using the CLI, ghost discovers the `passphrase.ghost` file generated when initializing the a stash and uses it unless told otherwise.

unless the `--passphrase` flag or `GHOST_PASSPHRASE` env var are set, ghost will search for the `passphrase.ghost` file under:

1. `cwd/passphrase.ghost`
2. `~/.ghost/passphrase.ghost`
3. (Only non-Windows) `/etc/ghost/passphrase.ghost`

The Python API requires passing the passphrase explicitly to the Stash class when generating its instance.

It is important to note that if you regularly use two storage backends, you might not want to use the auto-discovery mechanism at all as to not accidently try to use one key with a mismatching stash.


## Backends

NOTE: ghost includes dependencies required for TinyDB only as its installation should be light-weight by default. `
You can install extras for each specific backend. See below.

NOTE: While true for the API, the CLI does not currently expose any advanced configuration for the backends such as setting certs, credentials or paths.

Until the API documentation is complete, please take a look at the Storage API's on how to use each storage.

### [TinyDB](http://tinydb.readthedocs.io/en/latest/usage.html)

The TinyDB backend provides an easy to read, portable JSON file based stash. It is the default backend when using the CLI as it is the simplest to digest for new users.

### [SQLAlchemy](http://www.sqlalchemy.org)

(Initially tested on v1.0.15)

NOTE: To use postgre, mysql and the likes, you must have the relevant package installed for SQLAlchemy to work. For instance, providing `postgresql://scott:tiger@localhost/mydatabase` as the path to the backend requires installing `psycopg2`. Failing to install the relevant package will result in SQLAlchemy raising an error which will state what's missing.

To enable, run `pip install ghost[sqlalchemy]`

The SQLAlchemy backend provides a way to use all well known SQL databases as backends including a local sqlite file. Functionally, the sqlite SQLAlchemy based backend resembles the TinyDB backend, but is not humanly readable.

All SQLAlchemy connection strings are allowed so Postgre, MySQL, MSSQL and the likes are easily accessible

### [Elasticsearch](http://elastic.co)

(Initially tested on v2.4.1 using elasticsearch-py 2.4.0)

To enable, run `pip install ghost[elasticsearch]`

The Elasticsearch backend resembles the TinyDB backend in that it simply stores JSON documents. An Index called `ghost` is created in the cluster (unless another index name is provided via the API) and used to store the keys.

### [Consul](http://www.consul.io)

(Initially tested on v0.7.0)

To enable, run `pip install ghost[consul]`

NOTE: As per [consul's documentation], you cannot provide values larger
than 512kb.

The Consul backend allows to use Consul's distributed nature to distribute keys between servers. Consul's kv-store (v1) is used to store the keys. You must configure your Consul cluster prior to using it with Ghost as ghost will practically do zero-configuration on your cluster. As long as the kv-store REST API is accessible to ghost, you're good. You may, of course, use a single Consul server as a stash, but to prevent dataloss, that is of course not recommended.

### [Vault](http://www.vaultproject.io)

(Initially tested on v0.6.1 using hvac 0.2.16)

To enable, run `pip install ghost[vault]`

NOTE: You MUST provide your Vault token either via the API or via the `VAULT_TOKEN` env var to use the Vault backend.

Controversially, you may use Vault as your stash. Since Vault itself encrypts and decrypts keys and requires a token, it would seem weird to use ghost as a front-end for it. I do not recommend using ghost with Vault unless you need to do cross-backend work - that is, use multiple backends at once or preserve a single API where Vault isn't always accessible. The main reason for using ghost and not Vault is mainly its no-server nature. If you already have Vault running, you may as well use its CLI/API and not use ghost to overcome unnecessary abstraction layers.

As such, much like with Consul, note that ghost does not provide any complicated configuration options for Vault using the CLI or otherwise. You need to have your Vault[Cluster] preconfigured after-which ghost will store all keys under the `secrets` path (can be overriden). You may provide a key named `aws/account_1`, for instance, in which case ghost will just pass the path along to Vault.


## Encryption & Decryption

Encryption is done using [cryptography](https://cryptography.io/en/latest/). It is done only on values and these are saved in hexa. Keys are left in plain text.

Values are encrypted once provided and decrypted only upon request, meaning that they're only available in memory for a very short period of time.

See cryptography's [documentation](https://cryptography.io/en/latest/) for additional information.


## Audit log

NOTE: This is WIP. The audit log is currently kept on the machine where ghost is run. As such, it is hardly useful for auditing purposes when using a remote backend. As ghost evoles, it will offer remote auditing. 

An audit log is saved under `~/.ghost/audit.log` containing a log of all primary actions (`put`, `get`, `delete`, `purge`, `list`) done on any stash. The path can be set using the `GHOST_AUDIT_LOG` env var.

The log file itself is not machine readable. Whether it will be remains to be seen.

The log should look somewhat like this:

```
2016-10-25 15:23:24,441 - [/home/nir0s/.ghost/stash.json] [LIST]
2016-10-25 15:23:31,350 - [/home/nir0s/.ghost/stash.json] [PUT] - {"key_name": "aws", "metadata": "null", "description": null, "value": "HIDDEN", "uid": "19fde800-89b9-4c25-a0af-b790e118bab7"}
2016-10-25 15:23:34,954 - [/home/nir0s/.ghost/stash.json] [LIST]
2016-10-25 15:24:33,322 - [/home/nir0s/.ghost/stash.json] [GET] - {"key_name": "aws"}
2016-10-25 15:24:33,323 - [/home/nir0s/.ghost/stash.json] [DELETE] - {"key_name": "aws"}
2016-10-25 15:24:33,323 - [/home/nir0s/.ghost/stash.json] [DELETE] - {"key_name": "aws"}
2016-10-25 15:24:49,890 - [/home/nir0s/.ghost/stash.json] [PUT] - {"key_name": "aws", "metadata": "null", "description": null, "value": "HIDDEN", "uid": "ffa4fb66-e3c0-445c-bafc-a60f480dc45a"}
2016-10-25 15:24:52,230 - [/home/nir0s/.ghost/stash.json] [PUT] - {"key_name": "gcp", "metadata": "null", "description": null, "value": "HIDDEN", "uid": "567f891a-d097-4575-a472-4409dc459a9a"}
2016-10-25 15:24:55,625 - [/home/nir0s/.ghost/stash.json] [PUT] - {"key_name": "gfa", "metadata": "null", "description": null, "value": "HIDDEN", "uid": "434b197b-c82e-41b1-a4d2-eaeb7cd6cf72"}
2016-10-25 15:25:00,553 - [/home/nir0s/.ghost/stash.json] [LIST]
2016-10-25 15:25:08,413 - [/home/nir0s/.ghost/stash.json] [GET] - {"key_name": "aws"}
2016-10-25 15:25:08,414 - [/home/nir0s/.ghost/stash.json] [DELETE] - {"key_name": "aws"}
2016-10-25 15:25:08,414 - [/home/nir0s/.ghost/stash.json] [DELETE] - {"key_name": "aws"}
2016-10-25 15:25:16,416 - [/home/nir0s/.ghost/stash.json] [PURGE] - all keys
```

## Exporting and Importing

You can export and import all keys in a stash using the `ghost export` and `ghost load` commands (same methods in the Python API).

The `export` command allows you to generate a json file containing all keys (encrypted, of course) while the `load` command can then load that file into another stash using the same, or a different storage backend. 

So, for instance, if you have a local implementation using sqlite, you could export all keys; create a new stash using the SQLAlchemy storage for postgre and load all keys into that storage for your server's implementation.

The `migrate` command will allow you to easily migrate all of your keys from one backend to another like so:

```shell
ghost migrate my_stash.json postgresql://localhost/ghost \
  --source-passphrase 123 \
  --destination-passphrase 321 \
  --source-backend tinydb \
  --destination-backend sqlalchemy
```

Note that using the `migrate` command (or API) will result in keys being decrypted and reencrypted on the destination stash.


## Secret key delegation

Since ghost doesn't run as a distributed server, it doesn't provide a formal method for delegating keys to a server without explicitly passing them over in plain text post-decryption. You can work around that by retrieving a key without decrypting it (via the `--no-decrypt` flag in the CLI or the `decrypt` argument in the Python API) and sending it to the other server where the same passphrase is held and decrypting  it there.

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

See [CONTRIBUTIONS](https://github.com/nir0s/ghost/blob/master/CONTRIBUTING.md)
on how to contribute additional backends.

Pull requests are always welcome..
