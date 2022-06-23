# Web Application Filters

## AWS ELB
The WAF doesn't check past 8192 characters of a request body or json. Thus, if we want to evade the filter, we can just add 8192 spaces to the front (remember to url-encode if necessary). 
> Note that request bodies can only be passed in POST requests.
However, the application might be configured to accept POST requests, so we can test that out by switching the protocol to POST and adding a header, `Content-Type: application/x-www-form-urlencoded`.
