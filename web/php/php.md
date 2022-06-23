# PHP vulnerabilities

## Magic hashes

- Vuln is in comparison of hashes with == instead of ===
- Hashes that start with 0e is taken as integer 0 exponent number behind
- '0e462097431906509019562988736854' == '0' is true
> The digits following 0e must be base 10!!

## strcmp()

- strcmp(array(), 'asdf') == NULL == 0
- To provide array in GET/POST, do password[]=a

## Injecting with different types

- take note of == vs ===
- === ensures its the same type
- can take advantage of this by injecting an array a[]=''
- Evals to null

## Hash collision with password_verify function
- null byte in hash will cause the rest of the hash to be truncated (shortened)
- easier to find hash starting with xxx00 which would collide

## Object injection
- To perform, there must be an existing class that calls a magic method that usually starts with `__xxxx` 
- when object is deserialized, you can basically create your own object with and set the values of the object properties
- the functions defined in the original object is called and executed on your object with your specified values 

## Leaking source code with file=something
- `file=php://filter/convert.base64-encode/resource=filename.php`
- note that sometimes `.php` maybe already appended and in that case remove `.php` from payload

## Code execution using `preg_replace` regex `/e` modifier
- /e modifier would cause `preg_replace` to execute stuff that has been replaced, 2nd parameter of `preg_replace`
- One can inject the /e modifier using null bytes or other stuff
- Then inject code to be executed
- Note that `\\1` is regex to reference the first bracketed expression. Often seen in php `preg_replace` 2nd param. Basically a free injection spot but payload is filtered by the replaced chars

## Vulnerability with `stripslashes`
- un-quotes all C-like backslashes
- which means we can use hex representations of letters and stuff 
- "\x41\x41\x41" -> "AAA"
- Remember to escape the backslash so that the string received is `\x41\x41\x41`, without escaping is basically sending "AAA" which is pointless

## PHP `create_function` vuln
- `create_function` internally uses eval
- how it works is that it crafts a string based on the input params
- then evals that whole string to create a function
- this allows us to inject stuff to eval other things and get RCE

## extract()
- This function overrides the original namespace, allowing for control of any arbitrary variable at the time of calling the function. This is very handy for bypassing certain checks or inducing some vulnerable PHP errors.

## unserialize()

Similar to Python's 
