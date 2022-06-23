# Multi-factor authentication
> Though secure in theory, some applications may suffer from poor logic when implementing MFA. Below are some of these insufferable mistakes by mindless fools.

## Logged in before MFA
Some applications simply log you in after entering the username and password, without even verifying the 2FA. Thus, all you need to do is exit the 2FA page and you'll still be logged in via cookies.

## MFA to bypass password
Some applications, to match the 2FA to an account, will pass the username of the account as a cookie, whether in plaintext or otherwise.

This introduces a serious vulnerability, in that the attacker just needs the username of the victim and can already bruteforce the 2FA, which in most cases is faster than bruteforcing the password.
