# PGL Writeup
Author: Philip Thayer (zilmoe)

## Challenge
This is a write-up for the reversing challenge "pgl", that was hosted by the US Cyber Combine throughout the summer of 2025

## The binary
When running the binary, we are greeted with a menu for a TID that seems to be a Pokemon License Validator.

```
=== Pokemon Gold License Validator ===
Enter your trainer details to validate your Pokemon Master license.

Enter your TID:
```

After running through the binary, it seems to be some kind of ID checker that processes the TID and the SID in some way to validate our license key.

``` 
=== Pokemon Gold License Validator ===
Enter your trainer details to validate your Pokemon Master license.

Enter your TID: 123
Enter your SID: 123
Enter your Trainer Name: zilmoe
Enter your Pokemon Master License: zilmoe

Validating license...
Invalid license key format! Must be XXXX-YYYY-ZZZZ-WWWW (hex)
Invalid license! You're not a true Pokemon Master yet. 
```

The next step is to run this in Ghidra and start reversing this binary.

## Reversing

When decompiling this binary in Ghidra, we get some pretty weird decompilations.
For one, the binary seems unusually small. There's only five functions, including the entry function.
Another telltale sign something is off about the binary is that the program tree is unusually empty.

This is a normal program:

![Alternative description](https://raw.githubusercontent.com/zilmoe/writeups/main/uscg/pgl/normal_program.png)

And this is our program:

![Alternative description](https://raw.githubusercontent.com/zilmoe/writeups/main/uscg/pgl/compressed_program.png)


So this leads to the question, why is our executable so weird?
Running strings on the binary answers this question.

```
> strings pgl
UPX!
-9ya
tdoPyd
/lib64
nux-x86-
so.2
G5/C
...
...
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
_RPWQM)
j"AZR^j
PZS^
/proc/self/exe
IuDSWH
s2V^
XAVAWPH
...
...
...
com2
$/;dC6
`#o=
?7G`
UPX!
UPX!
```

The binary tells us it has been compressed with UPX, a executable packer meant to compress executable files.
This is a typical method of obfuscating code. Luckily, it is very easy to unpack.

If we have UPX installed on our system, we can run:
```
upx -d -o challenge.bin pgl
```
and the unpacked executable will be saved as challenge.bin.

Now, we get a much cleaner Ghidra output!

![Alternative description](https://raw.githubusercontent.com/zilmoe/writeups/main/uscg/pgl/uncompressed_pgl.png)

Now that we can view the decompilation, let's start reversing!

Here is the main function:
```c
undefined8 FUN_00101140(void)

{
  int iVar1;
  undefined auStack_78 [4];
  undefined local_74 [4];
  undefined local_70 [24];
  undefined local_58 [72];
  
  puts("=== Pokemon Gold License Validator ===");
  puts("Enter your trainer details to validate your Pokemon Master license.\n");
  __printf_chk(2,"Enter your TID: ");
  __isoc99_scanf(&DAT_001021dd,auStack_78);
  __printf_chk(2,"Enter your SID: ");
  __isoc99_scanf(&DAT_001021dd,local_74);
  __printf_chk(2,"Enter your Trainer Name: ");
  __isoc99_scanf(&DAT_0010220b,local_70);
  __printf_chk(2,"Enter your Pokemon Master License: ");
  __isoc99_scanf(&DAT_00102210,local_58);
  puts("\nValidating license...");
  iVar1 = FUN_001014f0(local_58,auStack_78);
  if (iVar1 == 0) {
    puts("Invalid license! You\'re not a true Pokemon Master yet.");
  }
  else {
    puts("License validated successfully!");
    FUN_00101610();
  }
  return 0;
}
```


Here we can see that some input is read from the user using scanf, and then a function is called on the input.
Opening the function that calls our input leads to this:

```c
undefined8 FUN_001014f0(undefined8 param_1,uint *param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  size_t sVar6;
  uint *trainer_name_ptr;
  uint uVar7;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined2 local_3a;
  
  iVar4 = FUN_00101450(param_1,&local_40);
  if (iVar4 == 0) {
    puts("Invalid license key format! Must be XXXX-YYYY-ZZZZ-WWWW (hex)");
  }
  else {
    trainer_name_ptr = param_2 + 2;
    uVar2 = *param_2;
    uVar3 = param_2[1];
    uVar7 = ((uVar2 ^ 0x251) << 0x10 | uVar2 >> 0x10) + uVar3 * 4;
    sVar6 = strlen((char *)trainer_name_ptr);
    if (0 < (int)sVar6) {
      uVar5 = 0;
      do {
        bVar1 = *(byte *)trainer_name_ptr;
        trainer_name_ptr = (uint *)((long)__s + 1);
        uVar5 = uVar5 + bVar1;
      } while ((uint *)((long)param_2 + (ulong)((int)sVar6 - 1) + 9) != trainer_name_ptr);
      uVar7 = uVar7 ^ uVar5 * 0x10000 + (uVar5 & 0xffff);
    }
    if (CONCAT22(local_40,local_3e) == (uVar7 ^ 0x474f4c44)) {
      if (CONCAT22(local_3c,local_3a) == (uVar2 ^ uVar3 ^ CONCAT22(local_40,local_3e))) {
        return 1;
      }
      puts("License checksum failed!");
    }
    else {
      puts("License validation failed!");
    }
  }
  return 0;
}
```

Here, we can see that quite a few operations are conducted on our input, then, two values are compared. 
If the two values are equal, the program will return 1, or true, and then we will have passed the license validator.

So, how do we get the program to return 1?

If we look at the beginning of the program, iVar4 determines if the program exits early due to a incorrect format. We can assume the function that assigns this value, FUN_00101450, is some function that process the format of param 1.

So now we have this:
```c
  is_format_valid = FUN_00101450(param_1,&local_40);
  if (is_format_valid == 0) {
    puts("Invalid license key format! Must be XXXX-YYYY-ZZZZ-WWWW (hex)");
  }
```

Taking a look at this function:
```c
undefined8 FUN_00101450(char *param_1,undefined2 *param_2)

{
  char *pcVar1;
  size_t sVar2;
  long lVar3;
  undefined8 uVar4;
  char local_35 [4];
  undefined local_31;
  char *local_30;
  
  sVar2 = strlen(param_1);
  if ((((sVar2 == 0x13) && (param_1[4] == '-')) && (param_1[9] == '-')) && (param_1[0xe] == '-')) {
    pcVar1 = param_1 + 0x14;
    do {
      strncpy(local_35,param_1,4);
      local_31 = 0;
      lVar3 = strtol(local_35,&local_30,0x10);
      *param_2 = (short)lVar3;
      if (*local_30 != '\0') goto LAB_00101471;
      param_1 = param_1 + 5;
      param_2 = param_2 + 1;
    } while (param_1 != pcVar1);
    uVar4 = 1;
  }
  else {
LAB_00101471:
    uVar4 = 0;
  }
  return uVar4;
}
```

We can see that the length of the input is taken. After that, the input is compared to the desired format (XXXX-YYYY-ZZZZ-WWWW (hex)):

```c
if ((((len == 0x13) && (param_1[4] == '-')) && (param_1[9] == '-')) && (param_1[0xe] == '-')) {
```

If the format matches up, the do {} segment executes. 

We can see that the first 4 characters from the input are copied into a local buffer:

```c
strncpy(local_35,param_1,4);
```

After that, the copied characters are processed by strtol, which returns the decimal value of the hex string.
```c
lVar3 = strtol(local_35,&local_30,0x10);
```

Finally, the value of the processed number is stored in the buffer provided by the second parameter.
```c
*param_2 = (short)lVar3;
```

Then, the loop cleans up by "removing" the processed values:
```c
param_1 = param_1 + 5;
param_2 = param_2 + 1;
```
So that the next time the loop runs, it'll process the next section of the Master License, or the next section after the -.\
This loop will run four times, each processing and storing the next part of the Master License.

An interesting note, it may seem that the program overflows the buffer it is writing into, but it is not. If we take a look at what is after param 2 on the stack:
```c
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined2 local_3a;
```
There will be more space for values. So this function writes each part of the license into a separate variable, storing it for future use when it is needed.
We can now rewrite the stack vars:
```c
  undefined2 parsed_license_part1;
  undefined2 parsed_license_part2;
  undefined2 parsed_license_part3;
  undefined2 parsed_license_part4;
```


So, to put it together, this is our reversed line in the license checker:
```c
is_format_valid = FUN_00101450(param_1,&parsed_license_part1);
```

Now that we are back in the license checker, a few values are processed into variables.
```c
trainer_name_ptr = param_2 + 2;
tid = *param_2;
uid = param_2[1];
```

Then, these values are used to generate a new value:
```c
NEW_VALUE = ((tid ^ 0x251) << 0x10 | tid >> 0x10) + uid * 4;
```
Looking at this output, we can name the value NEW_VALUE for now until we get more of an idea of how and where it is used.
However, we can note that this is one of the values that are compared at the end of the function.

```c
if (CONCAT22(parsed_license_part1,parsed_license_part2) == (NEW_VALUE ^ 0x474f4c44)) {
```

Now comes the interesting part:
```c
    sVar6 = strlen((char *)trainer_name_ptr);
    if (0 < (int)sVar6) {
      uVar5 = 0;
      do {
        bVar1 = *(byte *)trainer_name_ptr;
        trainer_name_ptr = (uint *)((long)trainer_name_ptr + 1);
        uVar5 = uVar5 + bVar1;
      } while ((uint *)((long)param_2 + (ulong)((int)sVar6 - 1) + 9) != trainer_name_ptr);
      NEW_VALUE = NEW_VALUE ^ uVar5 * 0x10000 + (uVar5 & 0xffff);
```

The first part of this function takes the length of the trainer name and stores it in a variable. The loop will then run once for each character in the string, summing up each hexadecimal ASCII code. Our NEW_VALUE variable is then updated with a few manipulations depending on the summation of the hexadecimal ASCII codes.

For example, if the string is "AB":

 'A' = 0x41 = decimal 65 
 
 'B' = 0x42 = decimal 66
 
 Sum = 65 + 66 = 131 
 


Here is a cleaned up version of the previous code:

```c
    trainer_name_len = strlen((char *)trainer_name_ptr);
    if (0 < (int)trainer_name_len) {
      trainer_name_sum = 0;
      do {
        current_char = *(byte *)trainer_name_ptr;
        trainer_name_ptr = (uint *)((long)trainer_name_ptr + 1);
        trainer_name_sum = trainer_name_sum + current_char;
      } while ((uint *)((long)param_2 + (ulong)((int)trainer_name_len - 1) + 9) != trainer_name_ptr);
      expected_license_part_1 = expected_license_part_1 ^ trainer_name_sum * 0x10000 + (trainer_name_sum & 0xffff);
```

Finally, after all of this, the values are checked and the license is either valid or invalid.

```c
if (CONCAT22(parsed_license_part1,parsed_license_part2) == (expected_license_part_1 ^ 0x474f4c44)) {
  if (CONCAT22(parsed_license_part3,parsed_license_part4) == (tid ^ uid ^ CONCAT22(parsed_license_part1,parsed_license_part2))) {
    return 1;
```

So the main premise of this challenge is to find a valid Master License code that corresponds with your Name, UID, and TID. A python script can be used to complete the math of finding this Master License value.


## The Solve

To start, we can pick some basic string, uid, and tid.
```py
name = "zilmoe"
tid = 12345
sid = 54321
```

Next, we can replicate some of the expected values from the program by performing the same operations:

```c
expected_license_part_1 = ((tid ^ 0x251) << 0x10 | tid >> 0x10) + uid * 4;
```

can be replicated with:

```py
expected_license_p1 = ((tid ^ 0x251) << 16) | (tid >> 16) + uid * 4
```

which, in hindsight, looks the exact same in python and in C.
Then, we can add up all the hexadecimal ASCII codes:

```py
trainer_name_sum = sum(ord(char) for char in trainer_name)
```

Then, we can replicate this line:
```c
expected_license_part_1 = expected_license_part_1 ^ trainer_name_sum * 0x10000 + (trainer_name_sum & 0xffff);
```

By doing the same in our solve script in python:

```py
expected_license_p1 = expected_license_p1 ^ trainer_name_sum * 0x10000 + (trainer_name_sum & 0xffff)
```

Finally, to pass the first check:

```c
if (CONCAT22(parsed_license_part1,parsed_license_part2) == (expected_license_part_1 ^ 0x474f4c44))
```

we need to XOR by the same value and then implement the CONCAT22.

```c
license_part_1 = expected_license_p1 ^ 0x474f4c44

p1 = (license_part_1 >> 16) & 0xFFFF
p2 = license_part_1 & 0xFFFF
```

CONCAT22 may show up different in other decompilers, but it is Ghidra's shorthand for:
```
CONCAT22(high16, low16)

(high16 << 16) | (low16 & 0xFFFF)
```
So these two are identical in output.

From here, we can do the same for the second license part:

```py
license_part_2 = tid ^ sid ^ license_part_1

p3 = (license_part_2 >> 16) & 0xFFFF
p4 = license_part_2 & 0xFFFF
```

And then we can get some nicely formatted output like so:

```py
print(f"{p1:04X}-{p2:04X}-{p3:04X}-{p4:04X}")
```


## Solutions

This is the final reversed decompilation:
```c
undefined8 FUN_001014f0(undefined8 param_1,uint *param_2)

{
  int is_format_valid;
  uint trainer_name_sum;
  size_t trainer_name_len;
  uint *trainer_name_ptr;
  uint expected_license_part_1;
  undefined2 parsed_license_part1;
  undefined2 parsed_license_part2;
  undefined2 parsed_license_part3;
  undefined2 parsed_license_part4;
  byte current_char;
  uint tid;
  uint uid;
  
  is_format_valid = FUN_00101450(param_1,&parsed_license_part1);
  if (is_format_valid == 0) {
    puts("Invalid license key format! Must be XXXX-YYYY-ZZZZ-WWWW (hex)");
  }
  else {
    trainer_name_ptr = param_2 + 2;
    tid = *param_2;
    uid = param_2[1];
    expected_license_part_1 = ((tid ^ 0x251) << 0x10 | tid >> 0x10) + uid * 4;
    trainer_name_len = strlen((char *)trainer_name_ptr);
    if (0 < (int)trainer_name_len) {
      trainer_name_sum = 0;
      do {
        current_char = *(byte *)trainer_name_ptr;
        trainer_name_ptr = (uint *)((long)trainer_name_ptr + 1);
        trainer_name_sum = trainer_name_sum + current_char;
      } while ((uint *)((long)param_2 + (ulong)((int)trainer_name_len - 1) + 9) != trainer_name_ptr);
      expected_license_part_1 = expected_license_part_1 ^ trainer_name_sum * 0x10000 + (trainer_name_sum & 0xffff);
    }
    if (CONCAT22(parsed_license_part1,parsed_license_part2) == (expected_license_part_1 ^ 0x474f4c44)) {
      if (CONCAT22(parsed_license_part3,parsed_license_part4) == (tid ^ uid ^ CONCAT22(parsed_license_part1,parsed_license_part2))) {
        return 1;
      }
      puts("License checksum failed!");
    }
    else {
      puts("License validation failed!");
    }
  }
  return 0;
```

And this is the solve script:

```py
trainer_name = "zilmoe"
tid = 12345
sid = 54321

expected_license_p1 = ((tid ^ 0x251) << 16) | (tid >> 16) + sid * 4
trainer_name_sum = sum(ord(char) for char in trainer_name)
expected_license_p1 = expected_license_p1 ^ trainer_name_sum * 0x10000 + (trainer_name_sum & 0xffff)
license_part_1 = expected_license_p1 ^ 0x474f4c44
license_part_2 = tid ^ sid ^ license_part_1

p1 = (license_part_1 >> 16) & 0xFFFF
p2 = license_part_1 & 0xFFFF
p3 = (license_part_2 >> 16) & 0xFFFF
p4 = license_part_2 & 0xFFFF
print(f"{p1:04X}-{p2:04X}-{p3:04X}-{p4:04X}")
```



