# Javascript vulns 

http://jsnice.org/ Deobfuscate JavaScript

## Prototype pollution

Every object in Javascript inherits from the base Object prototype. 

By overwriting/adding an attribute to `__proto__`, all other objects will also magically gain this attribute. 

### Example

```js
var ihaveaccesstothis = 'hello';

var attackme = {
	'admin': false,
};

console.log(attackme.admin); // false
console.log(attackme.__proto__); // Object
console.log(ihaveaccesstothis.__proto__); // String
console.log(ihaveaccesstothis.__proto__.__proto__); // Object !

ihaveaccesstothis.__proto__.__proto__.admin = True;

console.log(attackme.admin) // true
```

Caveat: If the object has nested inheritances (eg. I want to overwrite String.toLower()), overwriting the base Object prototype won't work. We need access to the String prototype.

### In query params

Prototype pollution can also occur client-side in query params. If the query string parser returns keys directly and not as strings, we can overwrite the object's attributes.

`?__proto__[admin]=1`

It's slightly weaker as we can only pass in strings.

### RCE

If we can pass in functions, simply target an attribute function that is being called (eg. String.valueOf() or smtg else) and overwrite it to something else.

### Other stuff

Every attribute of window is a global variable (and vice versa!) This means that asdf == window.asdf, window.name == name, window.location == location etc. If we are able to set these variables, we can possibly control these values to arbitrary stuff, enabling XSS etc.

<https://github.com/BlackFan/client-side-prototype-pollution>
