# babyaeg @ qwbctf2019

## DISCLAIMER

I am not the author of challenge. I am the second solver in the competition. All rights are reserved by the actual author.

This writeup is mostly for the purpose of benchmarking a level of general programming ability. It is the best available external challenge I can solve that shows the importance of high-level programming. (In contrast, I believe the best one that I wrote is [subl](https://github.com/ThinerDAS/subl))

## Service Execution

```
cd env
python ./babyaeg.py
```

## Directory structure

[env] is the collected remote source code for generating binaries. The content of the directory is not available in competition until the challenge is solved.

[example] is the collected elfs generated from remote.

[exp.py] is the client script.

[script.py] is the solver & exploit generator.

## Introduction

This CTF challenge is a great PPC/OOP training challenge. On each connection the server will generate a stripped binary, send it to the client, and wait for a string as `argv[1]` of the binary. The client only has 5 seconds to generate the input. The goal is to get command execution and capture the flag on the server.

All files are for reference and training purposes.

## Solution sketch

First grab one binary and analyze it manually. It is a crackme before a rop primitive, and the pattern is mostly fixed.

I do not expect `angr` to finish the challenge. There are a few reasons:

1. 5 second is still a short time.
2. initial xor loop contains too many fork primitives and I do not believe that angr can handle unnecessary forkings correctly.
3. the first 16 functions are plain char verifier, but the later functions are lookup tables, and angr is not very famous for this level of complex cases.

So based on the observations I skip attempt of angr and parse the elf by myself.

`elftools` and `capstone` are my good friends. I parse the program header for the memory map (and ELF header for entry point), write a simple pattern matcher and bruteforcer for targetting and solving the initial crackme, resolve the position of mprotect and finish the later exploit.

`pypy` is also great, since my exploit involves dumb bruteforcing, and `pypy` accelerates the process.

The exploit is dumb and minimal for successful exploit, and it sometimes fails (though it is likely to succeed). Nonetheless it shows how programming experience is inspected directly in CTF. Great skill of designing and programming is still important.

## babyaeg environment dump

Below is the deploy environment, for reference purposes.

### === ls -al ===
```
total 52
drwxr-x---  9 0 1000 4096 May 23 17:30 .
drwxr-x---  9 0 1000 4096 May 23 17:30 ..
-rwxr-x---  1 0 1000  220 Apr  4  2018 .bash_logout
-rwxr-x---  1 0 1000 3771 Apr  4  2018 .bashrc
-rwxr-x---  1 0 1000  807 Apr  4  2018 .profile
-rwxr-x---  1 0 1000 2379 May 23 17:27 babyaeg.py
drwxr-x---  2 0 1000  111 May 23 17:29 bin
drwxr-x---  2 0 1000   55 May 23 17:29 dev
-rwxr-----  1 0 1000   39 May 25 04:31 flag
-rwxr-x---  1 0 1000 2391 May 23 17:27 generate.py
drwxr-x--- 28 0 1000 4096 May 23 17:29 lib
drwxr-x---  3 0 1000 4096 May 23 17:29 lib32
drwxr-x---  2 0 1000   33 May 23 17:29 lib64
-rwxr-x---  1 0 1000 6292 May 23 17:27 source
drwxrwxrwx  2 0    0 4096 May 26 13:32 tmp
drwxr-x---  5 0 1000   40 May 23 17:29 usr
```
### === ls -al /bin ===
```
total 7828
drwxr-x--- 2 0 1000     111 May 23 17:29 .
drwxr-x--- 9 0 1000    4096 May 23 17:30 ..
-rwxr-x--- 1 0 1000  917488 May 23 17:29 as
-rwxr-x--- 1 0 1000   35064 May 23 17:29 cat
-rwxr-x--- 1 0 1000   22536 May 23 17:29 compress
-rwxr-x--- 1 0 1000 1010624 May 23 17:29 gcc
-rwxr-x--- 1 0 1000 1783496 May 23 17:29 ld
-rwxr-x--- 1 0 1000  133792 May 23 17:29 ls
-rwxr-x--- 1 0 1000 3670448 May 23 17:29 python
-rwxr-x--- 1 0 1000   63704 May 23 17:29 rm
-rwxr-x--- 1 0 1000  121432 May 23 17:29 sh
-rwxr-x--- 1 0 1000  235728 May 23 17:29 strip
```
### === version of gcc / as / ld ===
```
gcc (Ubuntu 7.4.0-1ubuntu1~18.04) 7.4.0
Copyright (C) 2017 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

GNU assembler (GNU Binutils for Ubuntu) 2.30
Copyright (C) 2018 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or later.
This program has absolutely no warranty.
This assembler was configured for a target of `x86_64-linux-gnu'.
GNU ld (GNU Binutils for Ubuntu) 2.30
Copyright (C) 2018 Free Software Foundation, Inc.
This program is free software; you may redistribute it under the terms of
the GNU General Public License version 3 or (at your option) a later version.
This program has absolutely no warranty.
```