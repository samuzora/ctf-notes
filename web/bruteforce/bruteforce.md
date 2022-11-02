# Bruteforcing login forms
> Sometimes, the only vulnerability of a site is its users. They may set easy to predict usernames or passwords, which can be an attack vector.

## Bruteforcing Subdomains or Paths
- Use *dirbuster* in Kali Linux (Click `List Info` for Wordlists `/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt`)
- https://subdomainfinder.c99.nl/
- https://dnshistory.org/historical-dns-records/

## General technique
For most login forms, we want to first determine a valid username, and then bruteforce the password. This reduces the time taken from O(n^2) to just O(n), which is a huge improvement for us. But how do we tell if a username is valid or not?

### Different responses
Sometimes, an application may give different responses based on whether the username is valid or not. For example, 'Username is incorrect'/'Password is incorrect', or even 'Credentials wrong/Credentials wrong.' 

### Time taken to process password
If a password of significant length (> 100) is provided, the application may take longer to parse the password if it parses it after the username is verified. This is especially if the hash algo used is a slow one, which grows exponentially time-wise when length increases. 

## How to carry out bruteforce
*Using Burp Professional:*
- Send a request to the target via Burp Proxy.
- Send the request in HTTP History to Burp Intruder.
- Clear all payloads except for the desired one.
- Set all wordlists for payloads.
- Define a custom resource option and set number of threads to something higher (100)
- Start Attack

*Using ZAP:*
- Send a request to the target via ZAP Manual Scan.
- Right click on the request in History and click Attack > Fuzz.
- Load files/wordlists.
- Start Attack

## Filter evasion
### IP banned! Help!!
It may be possible to "spoof" your IP by setting the X-Forwarded-For header in the request. For this, you will need to use Burp's Pitchfork attack mode.
- Set the first payload as the value of X-Forwarded-For and the second payload as the username/password.
- Using Python, generate a short list of fake IPs and paste it into the first payload's list
- Carry on

> Make sure that you have enough IPs to fully test your wordlist! Check how many times the application allows incorrect attempts before you are banned.

### IP ban, not vulnerable to IP spoofing :(( 
You can attempt another method, if you have access to a valid account on the app. All you need to do is run 2 attacks simultaneously. One will keep logging into the site with a valid account, and the other will do the actual bruteforce. This will blind the site to your bruteforcing.

> You might want to set the first attack's frequency to something obscenely high, and the second attack's frequency to something much lower. This accounts for the time taken to process the correct attempt, which will definitely be longer than the time taken to process the wrong attempts. If the timings are off, you might get banned and need to wait.

If this doesn't work, you can try and check if the application accepts input in JSON format. If it does, you can just dump all your passwords as an array in the password parameter, and one of those might be correct.

> This might depend on the language the app was written in. It might also work with POST data.

### Account lock
This might be a good thing! You can make use of the account lock to enumerate a username out. Using Burp Pro, create an attack that cycles through the username list about 10 times. The first payload should be the username and the second should be a null payload that repeats 10 times. At the same time, you want to determine the number of tries you have before the account is locked, which may be helpful later on.

Once you've found the username, the real problem approaches. You cannot effectively bruteforce the password with such an account lock.

However, some apps may suffer from incorrect logic, and not throw any error if the password is correct but the account is locked. This allows you to still bruteforce the password even if the account is locked. 
