# File Descriptors
> What are file descriptors? Every process running on the machine has a unique PID. This allows each process to obtain its own instance of stdin, stdout, stderr, as well as any other files that were opened in the program. 

## Accessing file descriptors
They are usually found in `/proc/self/fd`, or `/proc/{PID}/fd` if you know the PID. stdin is `/proc/self/fd/0`, stdout is `/proc/self/fd/1`, and stderr is `/proc/self/fd/3`. Any other files opened will be in `/proc/self/fd/{x}` (x being a random integer).

## Unclosed files
Sometimes files are left opened in a program. This means that they exist in the `/proc/self/fd` directory, and will not be deleted until the file is closed. This allows an attacker to obtain the contents of the file left opened. 

### Length limit
`/dev/fd` is a symlink to `/proc/self/fd`, saving you a few characters.
