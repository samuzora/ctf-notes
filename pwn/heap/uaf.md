# Use After Free

## Freeing

Chunks are not actually emptied when they are freed, but only when they need to be reused for allocation. All freeing does is marking the chunk as "available for use", so the next chunk to be written will be written there.

If a reference is made to the chunk after it's been reused, the data we get will be the updated one and not the already freed chunk. eg. if a process saves the address of the chunk and the chunk is subsequently freed and reused, the data in the chunk will be different than the original one, even though it's found at the same address.

## Exploitation

Because of the above, we can pass in unexpected data to chunks being referenced.

### Example

Scenario: 

The binary in question has 3 functions:

1. Add user
2. Change user score
3. Delete user

If a user gets 100 points, the binary will print the flag.

Below are the structs:

```c
struct user {
	char* name[8],
}

struct score {
	int userid,
	int score,
} // ints here are 32-bit (4 bytes)
```

There's a check for score.score when we do Change user score, which prevents score being higher than 1.

How do we get 100 or higher?

**Process:**

1. Create new user
2. Add new score for that user
3. Delete the score
4. Add new user 
	- First half of name should be \x64\0\0\0 and second half should be \1\0\0\0
Then we'll have 100 points!
