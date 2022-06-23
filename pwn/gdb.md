GNU DeBugger
---
This tool will be your butterknife for pwning (r2 is your bread, IDA Pro is your butter)

## Finding the offset between input and instruction pointer
### Easy way (gdb-gef)
`pattern create 500`  
`pattern search $eip`

`pattern create 500`  
`pattern search $rbp`

### Hard way (fallback in case of error) (vanilla gdb)
This method is more tedious, but it yields a greater chance of success. The earlier method depends on various factors, such as our input overwriting the instruction pointer. If our input does not, or if there is some condition before we can do that, we can't use the above method. Thus, it is necessary to use this method too.

Here, you want to diassemble the function and get the address after the function calls gets. You want to break after gets.  
`disas vuln`

Next, you want to set a breakpoint at the address after gets. (+100 is the number of bytes after the start of the function to the location you want to break at.  
`b *vuln+100`

Now you should send an easily recognizable and searchable string into the vulnerable buffer, like "abcde".

To search for the string:  
`search-p abcde`

The above gives you the address of your vulnerable buffer. 

To search for $eip / $rbp:
`info stack`
