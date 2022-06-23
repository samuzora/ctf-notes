# Nginx

## ../ reverse proxy bypass

`/foo/bar/#/../../../../../etc/passwd`

**Details:**

- `proxy_pass` must be specified without a URI (eg. `http://localhost.com/`)
	- Nginx will pass the request URI in the same form as sent by the client. If the backend parses the traversal then we have path traversal.
