# Contributing

## Backends

Contributing a new backend to ghost requires implementing a single class comprising, at the very least the class's constructor (`__init__`) and the `init`, `put`, `list`, `get` and `delete` base methods.

Each corresponding backend base method should return the same data structure.


### Backend dependencies

If any dependencies are required for the backend, please add them under `setup.py` in the `extras_require` section using your backend's name:

```python
extras_require={
    'sqlalchemy': ['sqlalchemy>=1.0.15'],
    ...
    'mystorage': ['mystorage'],
},
```

You can then conditionally import them like so:

```python
try:
    import mystorage
    MYSTORAGE_EXISTS = True
except ImportError:
    MYSTORAGE_EXISTS = False
```

### Constructor

The constructor should, at the very least, receive a `db_path` argument representing the path, ip or url of the stash's backend.

```python
class MyStorage(object):
    def __init__(db_path=STORAGE_DEFAULT_PATH_MAPPING['mystorage], 
                 **backend_config):
        if not MYSTORAGE_EXISTS:
            raise ImportError('mystorage must be installed first')
        self.client = self._get_client(db_path, backend_config)
        ...
```


### init

The `init` method should perform any actions related to initializing the backend like creating directories, indices, etc..

It should not return any value.

```python
def init(self):
    self.client.create()
    self._configure_backend()
    ...
```

### put

The `put` method should insert a key into the stash.

It should return the id of the key whether as it is in the backend.

```python
def put(self, key):
    """Insert the key and return its database id
    """
    id = self.client.insert_key(key)
    return id
```

### list

The `list` method should return a list of all key objects in the stash

```python
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
    return self.client.list()
```

### get

The `get` method should return a single key

```python
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
    key = self.client.get(key_name)
    if not key:
        return {}
    return key
```

### delete

The `delete` method should delete a key from the stash and return true if it was deleted or false if it wasn't

```python
def delete(self, key_name):
    """Delete the key and return true if the key was deleted, else false
    """
    self.client.delete(key_name)
    key = self.get(key_name):
    return key is {}
```

### Adding the backend to the CLI and setting its default path

For your backend, you should add the default path to the global `STORAGE_DEFAULT_PATH_MAPPING`:

```python
{
    'tinydb': os.path.join(GHOST_HOME, 'stash.json'),
    ...
    'mystorage': https://localhost:1212,
}
```

For it to be available to the CLI, you should add a mapping to the global `STORAGE_MAPPING`:

```python
{
    'tinydb': TinyDBStorage,
    ...
    'mystorage': MyStorage,
}
```

### Coverage

Coverage is expected to be a 100% for every backend. The only part not required is the conditional `import` part for its dependencies.